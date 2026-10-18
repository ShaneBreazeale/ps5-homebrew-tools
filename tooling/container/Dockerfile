# SPDX-License-Identifier: GPL-3.0-or-later
# Reference toolchain for byte-reproducible payload builds.
#
# Ubuntu 24.04's clang-18 (18.1.3) is the compiler that built the SDK's own
# crt1.o and libc.a, so payloads link against matching code. The SDK release
# archive is pinned by SHA-256. Build from the repository root with
# `make container-build`.
FROM ubuntu:24.04

ARG LLVM_RELEASE=18.1.3
ARG SDK_VERSION=v0.44
ARG SDK_SHA256=4d06eab777bb135705b5a6816688c9132efb246093fe606ac488ab6cf65ca5b0

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      bash ca-certificates clang-18 curl lld-18 llvm-18 make python3 unzip \
 && rm -rf /var/lib/apt/lists/*

RUN curl -fsSLo /tmp/sdk.zip \
      "https://github.com/ps5-payload-dev/sdk/releases/download/${SDK_VERSION}/ps5-payload-sdk.zip" \
 && echo "${SDK_SHA256}  /tmp/sdk.zip" | sha256sum -c - \
 && unzip -q /tmp/sdk.zip -d /opt \
 && rm /tmp/sdk.zip

ENV PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk \
    LLVM_CONFIG=/usr/bin/llvm-config-18 \
    PS5_LLVM_VERSION=${LLVM_RELEASE} \
    PS5_SDK_VERSION=${SDK_VERSION}

WORKDIR /src
