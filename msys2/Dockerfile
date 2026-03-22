# Build sillybear MSYS2 package on Linux using Wine + MSYS2.
#
# Based on https://github.com/msys2/msys2-docker which provides
# a patched Wine with MSYS2/Cygwin compatibility.
#
# Usage:
#   docker build -t sillybear-msys2-builder -f msys2/Dockerfile .
#   docker run --rm -v $(pwd)/msys2/output:/output sillybear-msys2-builder
#
# The resulting .pkg.tar.zst can be installed in MSYS2 with:
#   pacman -U sillybear-*.pkg.tar.zst

FROM ghcr.io/msys2/msys2-docker-experimental

# Use the MSYS subsystem (Cygwin-compatible POSIX layer),
# required for pty, syslog, and other POSIX APIs that sillybear needs.
ENV MSYSTEM=MSYS

# Install build dependencies
RUN msys2 -c "pacman -Syu --noconfirm"
RUN msys2 -c "pacman -S --noconfirm --needed \
    gcc \
    make \
    autoconf \
    zlib-devel \
    libcrypt-devel"

# Copy project source into MSYS2 home directory
COPY . /root/.wine/drive_c/msys64/home/root/sillybear

# Install and configure the build entry point
COPY msys2/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
