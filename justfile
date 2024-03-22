BASE_NAME := "ghcr.io/dimonoff/openvpn-client"
QEMU_BUILDER := "qemu-builder"

default:
  just -l

# Create a builder for multi-arch docker images
setup-builder:
  docker buildx create --name {{QEMU_BUILDER}}

# Build docker images for all artchitectures
build-all:
  #!/usr/bin/env bash
  VERSION=$(grep -oP 'FROM alpine:\K[0-9.]+' ./Dockerfile)
  docker buildx build \
    --builder={{QEMU_BUILDER}} \
    --platform linux/arm64/v8,linux/amd64 \
    --tag "{{BASE_NAME}}:${VERSION}" .

# Publish a new version 
publish:
  #!/usr/bin/env bash
  VERSION=$(grep -oP 'FROM alpine:\K[0-9.]+' ./Dockerfile)
  # Check if the tag already exists
  if git rev-parse "v${VERSION}" >/dev/null 2>&1; then
    echo "Tag v${VERSION} already exists"
    exit 1
  fi
  git tag -a "v${VERSION}" -m "Release ${VERSION}"
  git push --tags
