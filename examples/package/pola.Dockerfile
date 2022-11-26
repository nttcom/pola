FROM ghcr.io/nttcom/pola:latest
LABEL maintainer "Motoki TAKENAKA <m.takenaka@ntt.com>"

SHELL ["/bin/bash", "-c"]

RUN apt update \
 && apt install -y iputils-ping tcpdump tmux vim
