"""Image scanning functionality."""

import json
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import urllib.request

from .utils import read_image_list, ensure_tag, print_info, print_error


class ScanResult:
    """Represents the results of an image scan."""

    def __init__(self):
        self.images: List[str] = []
        self.sizes: Dict[str, float] = {}
        self.vulnerabilities: Dict[str, Dict] = {}
        self.kev_matches: List[Tuple[str, str]] = []  # (cve, image)
        self.epss_matches: List[Tuple[float, str, str, str]] = []  # (score, cve, image, package)
        self.json_data: Dict = {"items": []}
        self.cg_security_advisories: List[Dict] = []  # Chainguard security advisories
        self.cg_detailed_vulns: Dict[str, List[Dict]] = {}  # Detailed vulnerability info for Chainguard images


class ImageScanner:
    """Handles Docker image scanning with Grype."""

    def __init__(self, threads: int = 4):
        self.threads = threads
        self.kev_data: Optional[Dict] = None
        self.cg_security_feed: Optional[Dict] = None

    def check_pullable(self, image_list_path: Path) -> bool:
        """
        Check if all images in the list are pullable.

        Args:
            image_list_path: Path to image list file

        Returns:
            True if all images are pullable, False otherwise
        """
        result = subprocess.run(
            [
                "python3",
                "check-pullable-dryrun/check-pullable.py",
                str(image_list_path),
                "--threads",
                "4"
            ],
            capture_output=True
        )
        return result.returncode == 0

    def _download_kev_data(self) -> Dict:
        """Download KEV (Known Exploited Vulnerabilities) data from CISA."""
        if self.kev_data is None:
            url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            with urllib.request.urlopen(url) as response:
                self.kev_data = json.loads(response.read().decode())
        return self.kev_data

    def _download_cg_security_feed(self) -> Dict:
        """Download Chainguard security feed."""
        if self.cg_security_feed is None:
            url = "https://packages.cgr.dev/chainguard/security.json"
            try:
                with urllib.request.urlopen(url) as response:
                    self.cg_security_feed = json.loads(response.read().decode())
            except Exception as e:
                print_error(f"Failed to fetch Chainguard security feed: {str(e)}")
                self.cg_security_feed = {}
        return self.cg_security_feed

    def _find_cve_status_in_feed(self, vuln_id: str, package_name: str, package_version: str) -> Dict:
        """
        Find vulnerability status in Chainguard security feed.

        Args:
            vuln_id: Vulnerability ID (e.g., CVE-2024-1234 or GHSA-xxxx-xxxx-xxxx)
            package_name: Package name
            package_version: Installed package version

        Returns:
            Dictionary with status, fixed_version, and other info
        """
        feed = self._download_cg_security_feed()

        if not feed or 'packages' not in feed:
            return {'status': 'Unknown', 'fixed_version': None}

        # Look for the package in the feed
        for pkg_entry in feed['packages']:
            pkg = pkg_entry.get('pkg', {})
            if pkg.get('name') != package_name:
                continue

            # Check secfixes to find which version fixed the vulnerability
            secfixes = pkg.get('secfixes', {})
            for version, vulns in secfixes.items():
                if vuln_id in vulns:
                    return {
                        'status': 'Fixed',
                        'fixed_version': version,
                        'package': package_name
                    }

        # Vulnerability not found in security fixes for this package
        return {'status': 'Not Found', 'fixed_version': None}

    def _match_cg_advisories(self, cve_list: List[str], image: str) -> List[Dict]:
        """
        Match CVEs against Chainguard security feed with package info.

        Args:
            cve_list: List of CVE IDs found in image
            image: Image name

        Returns:
            List of advisory dictionaries with status information
        """
        # This will be populated with CVE -> package mapping from detailed scan data
        # For now, return empty as we'll handle this in the report generator
        return []

    def _pull_image(self, image: str) -> Tuple[str, Optional[str], Optional[float]]:
        """
        Pull a Docker image and get its digest and size.

        Args:
            image: Image name

        Returns:
            Tuple of (digest, error_message, size_in_mb)
        """
        # Pull the image
        result = subprocess.run(
            ["docker", "pull", image],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            return None, f"Failed to pull {image}", None

        # Get the digest
        inspect_result = subprocess.run(
            ["docker", "inspect", image],
            capture_output=True,
            text=True
        )

        if inspect_result.returncode != 0:
            return None, f"Failed to inspect {image}", None

        inspect_data = json.loads(inspect_result.stdout)
        digest = inspect_data[0].get("RepoDigests", [None])[0]
        size_bytes = inspect_data[0].get("Size", 0)
        size_mb = size_bytes / 1024 / 1024

        return digest, None, size_mb

    def _scan_single_image(
        self,
        image: str,
        temp_dir: Path,
        kev_cves: set
    ) -> Optional[Dict]:
        """
        Scan a single image with Grype.

        Args:
            image: Image name
            temp_dir: Temporary directory for results
            kev_cves: Set of KEV CVE IDs

        Returns:
            Scan results dictionary or None on error
        """
        print_info(f"Scanning image: {image}")

        # Run grype scan
        result = subprocess.run(
            ["grype", image, "-o", "json"],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print_error(f"Error scanning {image}")
            return None

        raw_json = json.loads(result.stdout)

        # Calculate vulnerability counts
        matches = raw_json.get("matches", [])
        scan_data = {
            "Total": len(matches),
            "Critical": sum(1 for m in matches if m.get("vulnerability", {}).get("severity") == "Critical"),
            "High": sum(1 for m in matches if m.get("vulnerability", {}).get("severity") == "High"),
            "Medium": sum(1 for m in matches if m.get("vulnerability", {}).get("severity") == "Medium"),
            "Low": sum(1 for m in matches if m.get("vulnerability", {}).get("severity") == "Low"),
            "Unknown": sum(1 for m in matches if m.get("vulnerability", {}).get("severity") in [None, "Unknown"]),
            "WontFix": sum(1 for m in matches if m.get("vulnerability", {}).get("fix", {}).get("state") == "wont-fix"),
            "FixedTotal": sum(1 for m in matches if m.get("vulnerability", {}).get("fix", {}).get("state", "").lower() == "fixed")
        }

        # Extract CVEs for KEV matching
        scan_cves = {m["vulnerability"]["id"] for m in matches}
        kev_matches = scan_cves & kev_cves

        # Save KEV matches
        if kev_matches:
            kev_file = temp_dir / "kev.txt"
            with open(kev_file, "a") as f:
                for cve in kev_matches:
                    f.write(f"{cve} from {image}\n")

        # Extract EPSS data (score >= 0.75)
        image_no_tag = image.split('@')[0].split(':')[0]
        epss_file = temp_dir / "epss.txt"
        with open(epss_file, "a") as f:
            for match in matches:
                vuln = match.get("vulnerability", {})
                epss_data = vuln.get("epss", [{}])[0] if vuln.get("epss") else {}
                epss_score = epss_data.get("epss")

                if epss_score is not None and epss_score >= 0.75:
                    cve_id = vuln.get("id", "")
                    package = match.get("matchDetails", [{}])[0].get("searchedBy", {}).get("package", {}).get("name", "")
                    f.write(f"{epss_score} {cve_id} {image_no_tag} {package}\n")

        # Save scan result
        result_file = temp_dir / f"{image.replace('/', '_').replace(':', '_').replace('.', '_')}.json"
        with open(result_file, "w") as f:
            json.dump(scan_data, f)

        # Save CVE list for Chainguard matching
        cve_file = temp_dir / f"{image.replace('/', '_').replace(':', '_').replace('.', '_')}_cves.txt"
        with open(cve_file, "w") as f:
            for cve in scan_cves:
                f.write(f"{cve}\n")

        # Save full grype JSON for detailed vulnerability information
        full_json_file = temp_dir / f"{image.replace('/', '_').replace(':', '_').replace('.', '_')}_full.json"
        with open(full_json_file, "w") as f:
            json.dump(raw_json, f)

        return scan_data

    def scan_images(self, image_list_path: Path, output_prefix: str) -> Optional[ScanResult]:
        """
        Scan all images in the list.

        Args:
            image_list_path: Path to image list file
            output_prefix: Prefix for output files (e.g., 'out' or 'cgout')

        Returns:
            ScanResult object or None on error
        """
        images = read_image_list(str(image_list_path))
        result = ScanResult()

        # Download KEV data
        kev_data = self._download_kev_data()
        kev_cves = {v["cveID"] for v in kev_data.get("vulnerabilities", [])}

        # Ensure all images have tags and pull them
        print("\nImage Size On Disk:")
        digests = []
        for image in images:
            image = ensure_tag(image)
            digest, error, size_mb = self._pull_image(image)

            if error:
                print_error(error)
                return None

            result.sizes[image] = size_mb
            digests.append(digest or image)
            print(f"{image}: {size_mb:.2f} MB")

        result.images = digests
        print()

        # Create temporary directory for parallel results
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Initialize temp files
            (temp_path / "kev.txt").touch()
            (temp_path / "epss.txt").touch()

            # Scan images in parallel
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(self._scan_single_image, image, temp_path, kev_cves): image
                    for image in digests
                }

                for future in as_completed(futures):
                    image = futures[future]
                    try:
                        scan_data = future.result()
                        if scan_data is None:
                            return None
                        result.vulnerabilities[image] = scan_data
                    except Exception as e:
                        print_error(f"Error scanning {image}: {str(e)}")
                        return None

            # Read KEV matches
            kev_file = temp_path / "kev.txt"
            if kev_file.stat().st_size > 0:
                with open(kev_file, "r") as f:
                    for line in f:
                        parts = line.strip().split(" from ")
                        if len(parts) == 2:
                            result.kev_matches.append((parts[0], parts[1]))

            # Read EPSS matches
            epss_file = temp_path / "epss.txt"
            if epss_file.stat().st_size > 0:
                with open(epss_file, "r") as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            result.epss_matches.append((
                                float(parts[0]),
                                parts[1],
                                parts[2],
                                parts[3]
                            ))

            # Save CVE lists and full JSON to persistent directory for future use
            cve_dir = Path(f"{output_prefix}-cves")
            cve_dir.mkdir(exist_ok=True)

            for image in digests:
                image_filename = f"{image.replace('/', '_').replace(':', '_').replace('.', '_')}_cves.txt"
                temp_cve_file = temp_path / image_filename
                persistent_cve_file = cve_dir / image_filename

                if temp_cve_file.exists():
                    # Copy CVE list to persistent directory
                    with open(temp_cve_file, "r") as src:
                        with open(persistent_cve_file, "w") as dst:
                            dst.write(src.read())

                # Copy full JSON for detailed vulnerability info
                full_json_filename = f"{image.replace('/', '_').replace(':', '_').replace('.', '_')}_full.json"
                temp_full_file = temp_path / full_json_filename
                persistent_full_file = cve_dir / full_json_filename

                if temp_full_file.exists():
                    with open(temp_full_file, "r") as src:
                        with open(persistent_full_file, "w") as dst:
                            dst.write(src.read())

        # Check Chainguard advisories for Chainguard images
        is_chainguard = output_prefix == "cgout" or any("cgr.dev/chainguard" in img for img in images)
        if is_chainguard:
            print_info("Fetching Chainguard advisories for each CVE...")
            # Match CVEs against Chainguard security feed
            for image in digests:
                image_filename = f"{image.replace('/', '_').replace(':', '_').replace('.', '_')}_cves.txt"
                cve_file = cve_dir / image_filename

                if cve_file.exists():
                    with open(cve_file, "r") as f:
                        cves = [line.strip() for line in f if line.strip()]

                    if cves:  # Only check if there are vulnerabilities
                        advisories = self._match_cg_advisories(cves, image)
                        result.cg_security_advisories.extend(advisories)

                # Load detailed vulnerability information
                full_json_filename = f"{image.replace('/', '_').replace(':', '_').replace('.', '_')}_full.json"
                full_json_file = cve_dir / full_json_filename
                if full_json_file.exists():
                    with open(full_json_file, "r") as f:
                        full_data = json.load(f)
                        result.cg_detailed_vulns[image] = full_data.get("matches", [])

        # Build summary statistics
        total_critical = sum(v["Critical"] for v in result.vulnerabilities.values())
        total_high = sum(v["High"] for v in result.vulnerabilities.values())
        total_medium = sum(v["Medium"] for v in result.vulnerabilities.values())
        total_low = sum(v["Low"] for v in result.vulnerabilities.values())
        total_unknown = sum(v["Unknown"] for v in result.vulnerabilities.values())
        total_wontfix = sum(v["WontFix"] for v in result.vulnerabilities.values())
        total_count = sum(v["Total"] for v in result.vulnerabilities.values())
        total_fixed = sum(v["FixedTotal"] for v in result.vulnerabilities.values())

        num_images = len(digests)

        # Build JSON output
        for image in digests:
            scan_data = result.vulnerabilities[image]
            result.json_data["items"].append({
                "image": image,
                "scan": {
                    "type": "grype",
                    "critical": scan_data["Critical"],
                    "high": scan_data["High"],
                    "medium": scan_data["Medium"],
                    "low": scan_data["Low"],
                    "unknown": scan_data["Unknown"],
                    "wontfix": scan_data["WontFix"],
                    "total": scan_data["Total"],
                    "fixed_total": scan_data["FixedTotal"]
                }
            })

        # Save outputs
        json_file = Path(f"{output_prefix}.json")
        with open(json_file, "w") as f:
            json.dump(result.json_data, f, indent=2)

        # Save KEV matches
        kev_output = Path(f"{output_prefix}-kev.txt")
        with open(kev_output, "w") as f:
            for cve, image in result.kev_matches:
                f.write(f"{cve} from {image}\n")

        # Save EPSS matches
        epss_output = Path(f"{output_prefix}-epss.txt")
        with open(epss_output, "w") as f:
            for score, cve, image, package in result.epss_matches:
                f.write(f"{score} {cve} {image} {package}\n")

        # Generate text output
        txt_file = Path(f"{output_prefix}.txt")
        with open(txt_file, "w") as f:
            f.write("\nImage Size On Disk:\n")
            for image, size in result.sizes.items():
                f.write(f"{image}: {size:.2f} MB\n")

            f.write(f"\nTotal Vulnerabilities: {total_count}\n")
            f.write(f"Total Critical CVEs: {total_critical}\n")
            f.write(f"Total High CVEs: {total_high}\n")
            f.write(f"Total Medium CVEs: {total_medium}\n")
            f.write(f"Total Low CVEs: {total_low}\n")
            f.write(f"Total Unknown CVEs: {total_unknown}\n")
            f.write(f"Average Vulnerabilities: {total_count / num_images:.2f}\n")
            f.write(f"Average Critical CVEs: {total_critical / num_images:.2f}\n")
            f.write(f"Average High CVEs: {total_high / num_images:.2f}\n")
            f.write(f"Average Medium CVEs: {total_medium / num_images:.2f}\n")
            f.write(f"Average Low CVEs: {total_low / num_images:.2f}\n")
            f.write(f"Average Unknown CVEs: {total_unknown / num_images:.2f}\n")
            f.write(f"\nTotal Fixes Available: {total_fixed}\n")

        # Print summary
        print("Image Size On Disk:")
        print(f"Total Vulnerabilities: {total_count}")
        print(f"Total Critical CVEs: {total_critical}")
        print(f"Total High CVEs: {total_high}")
        print(f"Total Medium CVEs: {total_medium}")
        print(f"Total Low CVEs: {total_low}")
        print(f"Total Unknown CVEs: {total_unknown}")
        print(f"Average Vulnerabilities: {total_count / num_images:.2f}")
        print(f"Average Critical CVEs: {total_critical / num_images:.2f}")
        print(f"Average High CVEs: {total_high / num_images:.2f}")
        print(f"Average Medium CVEs: {total_medium / num_images:.2f}")
        print(f"Average Low CVEs: {total_low / num_images:.2f}")
        print(f"Average Unknown CVEs: {total_unknown / num_images:.2f}")
        print(f"\nTotal Fixes Available: {total_fixed}\n")

        return result

    def load_existing_results(self, output_prefix: str) -> Optional[ScanResult]:
        """
        Load existing scan results from files.

        Args:
            output_prefix: Prefix of the output files

        Returns:
            ScanResult object or None on error
        """
        result = ScanResult()

        json_file = Path(f"{output_prefix}.json")
        if not json_file.exists():
            return None

        with open(json_file, "r") as f:
            result.json_data = json.load(f)

        # Load KEV matches
        kev_file = Path(f"{output_prefix}-kev.txt")
        if kev_file.exists():
            with open(kev_file, "r") as f:
                for line in f:
                    parts = line.strip().split(" from ")
                    if len(parts) == 2:
                        result.kev_matches.append((parts[0], parts[1]))

        # Load EPSS matches
        epss_file = Path(f"{output_prefix}-epss.txt")
        if epss_file.exists():
            with open(epss_file, "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        result.epss_matches.append((
                            float(parts[0]),
                            parts[1],
                            parts[2],
                            parts[3]
                        ))

        # Check Chainguard advisories for Chainguard images
        images = [item["image"] for item in result.json_data.get("items", [])]
        is_chainguard = output_prefix == "cgout" or any("cgr.dev/chainguard" in img for img in images)

        if is_chainguard:
            print_info("Fetching Chainguard advisories for each CVE...")
            cve_dir = Path(f"{output_prefix}-cves")

            if cve_dir.exists():
                for image in images:
                    image_filename = f"{image.replace('/', '_').replace(':', '_').replace('.', '_')}_cves.txt"
                    cve_file = cve_dir / image_filename

                    if cve_file.exists():
                        with open(cve_file, "r") as f:
                            cves = [line.strip() for line in f if line.strip()]

                        if cves:  # Only check if there are vulnerabilities
                            advisories = self._match_cg_advisories(cves, image)
                            result.cg_security_advisories.extend(advisories)

                    # Load detailed vulnerability information
                    full_json_filename = f"{image.replace('/', '_').replace(':', '_').replace('.', '_')}_full.json"
                    full_json_file = cve_dir / full_json_filename
                    if full_json_file.exists():
                        with open(full_json_file, "r") as f:
                            full_data = json.load(f)
                            result.cg_detailed_vulns[image] = full_data.get("matches", [])

        return result
