# How to Use the Docker Image

## Obtain the Docker Image

### Option 1: Use the Published Image

Pull the latest image from GHCR:

```bash
docker pull ghcr.io/nttcom/pola:latest
```

### Option 2: Build the Docker Image Locally

To build the Docker image locally, run the following command from the repository root (`pola/`, which contains `build/`):

```bash
docker buildx build \
    -t <image-name> \
    -f build/package/Dockerfile \
    --load \
    .
```

Note: To build the development image, use `Dockerfile.dev` instead:

```bash
docker buildx build \
    -t <image-name> \
    -f build/package/Dockerfile.dev \
    --load \
    .
```

### Option 3: Build with Make Targets

From the repository root, you can build images using Makefile targets:

```bash
# Build production image as pola:latest
make image

# Build development image as pola:latest-dev
make image-dev
```

You can override image name and tag:

```bash
make image IMAGE=<image-name> TAG=<tag>
make image-dev IMAGE=<image-name> TAG=<tag>
```

## Run with Host Network Mode

`polad` reads `polad.yaml` from its working directory, which is `/pola` inside the container. Mount your config directory there as shown below.

```bash
# Prepare polad config directory for volume mount
mkdir -p pola-config

# Prepare polad log directory for volume mount
LOGDIR="$(pwd)/logs"
mkdir -p "$LOGDIR"

# Create a polad configuration file
# Reference:
# https://github.com/nttcom/pola/blob/main/docs/sources/getting-started.md#configuration
vi "pola-config/polad.yaml"

# Start the container
docker run -d --network host \
    -v "$(pwd)/pola-config:/pola" \
    -v "$LOGDIR:/var/log/pola" \
    ghcr.io/nttcom/pola:latest
```

## Run with Bridge Network Mode

`polad` reads `polad.yaml` from its working directory, which is `/pola` inside the container. Mount your config directory there as shown below.

```bash
# Create a dedicated network for PCEP communication
docker network create --subnet <PCEP network subnet> pcep_net

# Prepare polad config directory for volume mount
mkdir -p pola-config

# Prepare polad log directory for volume mount
LOGDIR="$(pwd)/logs"
mkdir -p "$LOGDIR"

# Create a polad configuration file
# Reference:
# https://github.com/nttcom/pola/blob/main/docs/sources/getting-started.md#configuration
vi "pola-config/polad.yaml"

# Start the container
docker run -d --network pcep_net --ip <PCE Address> \
    -v "$(pwd)/pola-config:/pola" \
    -v "$LOGDIR:/var/log/pola" \
    ghcr.io/nttcom/pola:latest

# Connect the PCC container to the network
docker network connect pcep_net <PCC container name>
```
