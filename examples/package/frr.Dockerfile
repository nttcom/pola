FROM frrouting/frr:latest
LABEL maintainer "Motoki TAKENAKA <m.takenaka@ntt.com>"

SHELL ["/bin/bash", "-l", "-c"]

# Install packages
RUN apk update \
 && apk add tcpdump

# Setup FRRouting
RUN sed -i -e 's/=no/=yes/g' /etc/frr/daemons \
 && sed -i -e 's/pathd_options="  -A 127.0.0.1"/pathd_options="  -A 127.0.0.1 -M pathd_pcep"/g' /etc/frr/daemons \
 && touch /etc/frr/vtysh.conf \
 && echo "service integrated-vtysh-config" >> /etc/frr/vtysh.conf \
 && mkdir /var/log/frr \
 && touch /var/log/frr/frr.log \
 && chmod 766 /var/log/frr/frr.log
