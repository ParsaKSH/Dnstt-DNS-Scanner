#!/bin/bash

APP_CLIENT="dns-scanner-client"
APP_SERVER="dns-scanner-server"
VERSION="2.0.0"
OUTPUT_DIR="build"

mkdir -p "$OUTPUT_DIR"

echo "Building Dnstt DNS Scanner v$VERSION ..."
echo ""

PLATFORMS=(
    "linux amd64 "
    "linux arm64 "
    "windows amd64 .exe"
    "windows arm64 .exe"
    "darwin amd64 "
    "darwin arm64 "
    "android arm64 "
)

for platform in "${PLATFORMS[@]}"; do
    read -r OS ARCH EXT <<< "$platform"
    echo "  → ${OS}/${ARCH}"

    # Build client
    CGO_ENABLED=0 GOOS=$OS GOARCH=$ARCH go build -ldflags="-s -w" \
        -o "$OUTPUT_DIR/${APP_CLIENT}-${OS}-${ARCH}${EXT}" \
        ./cmd/client/

    # Build server
    CGO_ENABLED=0 GOOS=$OS GOARCH=$ARCH go build -ldflags="-s -w" \
        -o "$OUTPUT_DIR/${APP_SERVER}-${OS}-${ARCH}${EXT}" \
        ./cmd/server/
done

echo ""
echo "Build complete! Files in ./$OUTPUT_DIR/"
ls -lh "$OUTPUT_DIR/"
