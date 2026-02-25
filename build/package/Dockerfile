# ---- builder stage ----
FROM golang:1.26.5 AS builder

WORKDIR /pola

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go install ./cmd/...

# ---- runtime stage ----
FROM debian:bookworm-slim

LABEL org.opencontainers.image.authors="Motoki TAKENAKA <m.takenaka@ntt.com>, Wataru MISHIMA <w.mishima@ntt.com>"

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /go/bin/pola /usr/local/bin/
COPY --from=builder /go/bin/polad /usr/local/bin/

ENTRYPOINT ["polad"]
CMD ["-f", "polad.yaml"]
