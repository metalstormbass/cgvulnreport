"""Utility functions for the vulnerability comparison tool."""

import sys
from typing import List, Optional


class Colors:
    """ANSI color codes for terminal output."""
    CYAN = '\033[1;36m'
    YELLOW = '\033[1;33m'
    RED = '\033[1;31m'
    GREEN = '\033[1;32m'
    PURPLE = '\033[1;35m'
    WHITE = '\033[1;37m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def print_header():
    """Print the application header."""
    print(f"\n{Colors.CYAN}{'═'*52}{Colors.RESET}")
    print(f"{Colors.CYAN}   Chainguard Vulnerability Comparison Report{Colors.RESET}")
    print(f"{Colors.CYAN}{'═'*52}{Colors.RESET}\n")


def print_section(message: str):
    """Print a section header."""
    print(f"{Colors.CYAN}{'━'*52}{Colors.RESET}")
    print(f"{Colors.YELLOW}{message}{Colors.RESET}")
    print(f"{Colors.CYAN}{'━'*52}{Colors.RESET}\n")


def print_error(message: str):
    """Print an error message."""
    print(f"{Colors.RED}❌ {message}{Colors.RESET}", file=sys.stderr)


def print_success(message: str):
    """Print a success message."""
    print(f"{Colors.GREEN}✅ {message}{Colors.RESET}\n")


def print_info(message: str):
    """Print an info message."""
    print(f"{Colors.WHITE}{message}{Colors.RESET}")


def read_image_list(file_path: str) -> List[str]:
    """
    Read and parse an image list file.

    Args:
        file_path: Path to the image list file

    Returns:
        List of image names (non-empty, trimmed lines)
    """
    images = []
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                images.append(line)
    return images


def ensure_tag(image: str) -> str:
    """
    Ensure an image has a tag. If not, append ':latest'.

    Args:
        image: Image name

    Returns:
        Image name with tag
    """
    if ':' not in image or image.endswith('/'):
        return f"{image}:latest"
    return image
