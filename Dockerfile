FROM rust:latest AS build

ENV BASE /usr/local
ADD . /opt/plasma
WORKDIR /opt/plasma
RUN cargo build --release --workspace --target-dir /opt/plasma/bin

# cleanup everything except binaries
RUN mkdir -p /opt/plasma/exec && \
cp bin/release/server exec && \
cp bin/release/leader exec

# Thin container with binaries base image is taken from
# https://hub.docker.com/_/debian/
FROM debian:stable-slim AS plasma
COPY --from=build /opt/plasma/exec /opt/plasma/bin
COPY --from=build /opt/plasma/src/bin/config_8.json /opt/plasma/bin/
WORKDIR /opt/plasma
