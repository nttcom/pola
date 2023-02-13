FROM ubuntu:23.04
LABEL maintainer "Motoki TAKENAKA <m.takenaka@ntt.com>"

SHELL ["/bin/bash", "-c"]

# Install packages
RUN apt update \
 && apt install -y iproute2  iperf iputils-ping tcpdump tmux traceroute vim
