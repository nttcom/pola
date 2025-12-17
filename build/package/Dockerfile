FROM golang:1.25.5
LABEL maintainer "Motoki TAKENAKA <m.takenaka@ntt.com>"

WORKDIR /pola

COPY . .

# Install packages
RUN apt-get update \
 && apt-get install -y bash-completion curl iproute2 wget vim iputils-ping net-tools

# Enable Completion 
RUN echo "" >> ~/.bashrc \
 && echo "if [ -f /etc/bash_completion ] && ! shopt -oq posix; then" >> ~/.bashrc \
 && echo "  . /etc/bash_completion" >> ~/.bashrc \
 && echo "fi" >> ~/.bashrc

# Install Pola

SHELL ["/bin/bash", "-c"]
RUN go install ./cmd/...

# remove build directory
RUN rm -rf  ./*

# Add completion
RUN pola completion bash | tee -a /usr/share/bash-completion/completions/pola >/dev/null \
 && source /usr/share/bash-completion/completions/pola
