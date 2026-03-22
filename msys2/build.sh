#!/bin/bash
# Build sillybear MSYS2 package using Docker.
#
# Produces an MSYS2 .pkg.tar.zst package that can be installed with:
#   pacman -U sillybear-*.pkg.tar.zst
#
# Requirements: Docker
#
# Usage:
#   ./msys2/build.sh [output_dir]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_DIR="${1:-${SCRIPT_DIR}/output}"
IMAGE_NAME="sillybear-msys2-builder"

cd "${PROJECT_DIR}"

echo "=== Building Docker image (first run may take a while) ==="
docker build -t "${IMAGE_NAME}" -f msys2/Dockerfile .

echo ""
echo "=== Building MSYS2 package ==="
mkdir -p "${OUTPUT_DIR}"
docker run --rm -v "${OUTPUT_DIR}:/output" "${IMAGE_NAME}"

echo ""
echo "=== Done ==="
ls -la "${OUTPUT_DIR}"/*.pkg.tar.* 2>/dev/null || {
    echo "ERROR: No package files found in ${OUTPUT_DIR}"
    exit 1
}
