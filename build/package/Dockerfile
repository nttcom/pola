FROM ubuntu:24.04
LABEL maintainer "Motoki TAKENAKA <m.takenaka@ntt.com>"

# Install packages
RUN apt-get update \
 && apt-get install -y bash-completion curl iproute2

# Setup Go 1.22.2
RUN curl -o ~/go1.22.2.linux-amd64.tar.gz -LO https://go.dev/dl/go1.22.2.linux-amd64.tar.gz \
    && rm -rf /usr/local/go \
    && tar -C /usr/local -xzf ~/go1.22.2.linux-amd64.tar.gz \
    && echo "export PATH=$PATH:/usr/local/go/bin" > ~/.bashrc

# Enable Completion 
RUN echo "" >> ~/.bashrc \
 && echo "if [ -f /etc/bash_completion ] && ! shopt -oq posix; then" >> ~/.bashrc \
 && echo "  . /etc/bash_completion" >> ~/.bashrc \
 && echo "fi" >> ~/.bashrc

# Install Pola
SHELL ["/bin/bash", "-l", "-c"]

ENV GOBIN /usr/local/go/bin
RUN go install github.com/nttcom/pola/cmd/...@latest

# Add completion
RUN pola completion bash | tee -a /usr/share/bash-completion/completions/pola >/dev/null \
 && source /usr/share/bash-completion/completions/pola
