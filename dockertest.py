import docker

def list_images():
    """
    List container images and their sizes using Docker or Podman.
    This function uses the docker-py library for compatibility.
    """
    try:
        # Initialize the Docker client
        client = docker.from_env()

        # List all images
        images = client.images.list()

        for image in images:
            print(f"Image ID: {image.id}")
            print(f"Tags: {image.tags}")
            print(f"Size: {image.attrs['Size'] / (1024 * 1024):.2f} MB")
            print("-" * 40)

    except docker.errors.DockerException as e:
        print(f"Error interacting with container engine: {str(e)}")

# Run the function
if __name__ == "__main__":
    list_images()
