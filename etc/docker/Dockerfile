ARG OS
ARG ARCH

# Build stage
FROM --platform=${OS}/${ARCH} golang:1.26 AS builder
ARG OS
ARG ARCH
RUN apt-get update -y && apt-get install -y nodejs npm && rm -rf /var/lib/apt/lists/*
WORKDIR /usr/src/app
COPY . .
RUN OS=${OS} ARCH=${ARCH} make

# Runtime stage
FROM --platform=${OS}/${ARCH} debian:trixie-slim
ARG SOURCE
RUN apt-get update -y && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/app/build/authmanager /usr/local/bin/authmanager

# Labels
LABEL org.opencontainers.image.source=https://${SOURCE}

# Entrypoint
EXPOSE 80 443
ENV ADDR=0.0.0.0:80
ENTRYPOINT ["/usr/local/bin/authmanager"]
CMD ["run"]
