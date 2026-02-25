# How to Use the Docker Image

## Obtain the Docker Image

### Option 1: Use the Published Image

Pull the latest image from GHCR:

```bash
docker pull ghcr.io/nttcom/pola:latest
```

### Option 2: Build the Docker Image Locally

To build the Docker image locally, run the following command from the repository root (not from `build/package`):

```bash
docker build -t <image-name> -f build/package/Dockerfile .
```

Note: To build the development image, use `Dockerfile.dev` instead:

```bash
docker build -t <image-name> -f build/package/Dockerfile.dev .
```

## Run with Host Network Mode

```bash
# Prepare polad config directory for volume mount
MOUNTDIR=cfg
mkdir -p "$MOUNTDIR"

# Prepare polad log directory for volume mount
LOGDIR="$(pwd)/logs"
mkdir -p "$LOGDIR"

# Create a polad configuration file
# Reference:
# https://github.com/nttcom/pola/blob/main/docs/sources/getting-started.md#configuration
vi "$MOUNTDIR/polad.yaml"

# Start the container
docker run -d --network host \
    -v "$(pwd)/$MOUNTDIR:/$MOUNTDIR" \
    -v "$LOGDIR:$LOGDIR" \
    -w "/$MOUNTDIR" \
    ghcr.io/nttcom/pola:latest \
    polad -f polad.yaml
```

## Run with Bridge Network Mode

```bash
# Create a dedicated network for PCEP communication
docker network create --subnet <PCEP network subnet> pcep_net

# Prepare polad config directory for volume mount
MOUNTDIR=cfg
mkdir -p "$MOUNTDIR"

# Prepare polad log directory for volume mount
LOGDIR="$(pwd)/logs"
mkdir -p "$LOGDIR"

# Create a polad configuration file
# Reference:
# https://github.com/nttcom/pola/blob/main/docs/sources/getting-started.md#configuration
vi "$MOUNTDIR/polad.yaml"

# Start the container
docker run -d --network pcep_net --ip <PCE Address> \
    -v "$(pwd)/$MOUNTDIR:/$MOUNTDIR" \
    -v "$LOGDIR:$LOGDIR" \
    -w "/$MOUNTDIR" \
    ghcr.io/nttcom/pola:latest \
    polad -f polad.yaml

# Connect the PCC container to the network
docker network connect pcep_net <PCC container name>
```
