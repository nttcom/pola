# How to use Docker Image

## Use host network mode

```bash
# Prepare polad config and directory for volume mount
MOUNTDIR=cfg
mkdir $MOUNTDIR

# prepare polad log  directory for volume mount
LOGDIR=/var/log/pola
mkdir $LOGDIR

# Create a daemon config with this reference => https://github.com/nttcom/pola/blob/main/docs/sources/getting-started.md#configuration
vi $MOUNTDIR/polad.yaml

# Get pola container image
docker pull ghcr.io/nttcom/pola:latest

# Container up and detach
CURRENTDIR=`pwd`
docker run -itd --network host \
    -v $CURRENTDIR/$MOUNTDIR:/$MOUNTDIR -v $LOGDIR:$LOGDIR \
    -w /$MOUNTDIR ghcr.io/nttcom/pola:latest \
    /bin/bash -c "source ~/.bashrc;polad"
```


## Use bridge network mode

```bash
# Prepare network for PCEP
docker network create --subnet <PCEP network subnet> pcep_net

# Prepare polad config and directory for volume mount
MOUNTDIR=cfg
mkdir $MOUNTDIR

# prepare polad log  directory for volume mount
LOGDIR=/var/log/pola
mkdir $LOGDIR

# Create a daemon config with this reference => https://github.com/nttcom/pola/blob/main/docs/sources/getting-started.md#configuration
vi $MOUNTDIR/polad.yaml

# Get pola container image
docker pull ghcr.io/nttcom/pola:latest

# Container up and detach
CURRENTDIR=`pwd`
docker run -itd --network pcep_net --ip <PCE Address> \
    -v $CURRENTDIR/$MOUNTDIR:/$MOUNTDIR -v $LOGDIR:$LOGDIR -w /$MOUNTDIR ghcr.io/nttcom/pola:latest \
    /bin/bash -c "source ~/.bashrc;polad"

# Connect the container's PCC to the network
docker network connect pcep_net <PCC container name> 
```