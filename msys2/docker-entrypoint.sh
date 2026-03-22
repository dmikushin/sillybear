#!/bin/bash
# Build sillybear MSYS2 package from local source tree.
# Runs inside the Docker container.
set -e

MSYS2_ROOT=/root/.wine/drive_c/msys64
SRC_DIR=${MSYS2_ROOT}/home/root/sillybear
BUILD_DIR=${MSYS2_ROOT}/home/root/build

echo "=== Building sillybear MSYS2 package ==="

# Extract version from source
PKGVER=$(grep -oP '#define SILLYBEAR_VERSION "\K[^"]+' "${SRC_DIR}/src/sysoptions.h")
echo "Version: ${PKGVER}"

# Create build directory
mkdir -p "${BUILD_DIR}"

# Create source tarball from the local tree
tar czf "${BUILD_DIR}/sillybear-${PKGVER}.tar.gz" \
    -C "${SRC_DIR}/.." \
    --transform="s,^sillybear,sillybear-${PKGVER}," \
    --exclude='sillybear/.git' \
    --exclude='sillybear/msys2/output' \
    sillybear

# Generate PKGBUILD that uses the local tarball
cat > "${BUILD_DIR}/PKGBUILD" << PKGBUILD_EOF
# Auto-generated for Docker build
pkgname=sillybear
pkgver=${PKGVER}
pkgrel=1
pkgdesc="Lightweight SSH2 server and client"
arch=('x86_64' 'i686')
url="https://github.com/dmikushin/sillybear"
license=('MIT')
depends=('zlib' 'libxcrypt')
makedepends=('gcc' 'make' 'autoconf' 'zlib-devel' 'libcrypt-devel')
source=("sillybear-\${pkgver}.tar.gz")
sha256sums=('SKIP')

prepare() {
    cd "\${srcdir}/sillybear-\${pkgver}"
    autoconf
    autoheader
}

build() {
    cd "\${srcdir}/sillybear-\${pkgver}"
    ./configure \\
        --prefix=/usr \\
        --sysconfdir=/etc/sillybear \\
        --enable-bundled-libtom \\
        --disable-pam \\
        --disable-lastlog
    make PROGRAMS="sillybear dbclient sillybearkey sillybearconvert scp"
}

package() {
    cd "\${srcdir}/sillybear-\${pkgver}"
    make DESTDIR="\${pkgdir}" \\
        PROGRAMS="sillybear dbclient sillybearkey sillybearconvert scp" \\
        install
    install -Dm644 LICENSE "\${pkgdir}/usr/share/licenses/\${pkgname}/LICENSE"
    install -dm755 "\${pkgdir}/etc/sillybear"
}
PKGBUILD_EOF

# Build the package via MSYS2
msys2 -c "cd ~/build && makepkg -sf --noconfirm"

# Copy results to mounted /output volume
if [ -d /output ]; then
    cp "${BUILD_DIR}"/*.pkg.tar.* /output/
    echo "=== Package(s) copied to /output/ ==="
    ls -la /output/*.pkg.tar.*
else
    echo "=== Package(s) built ==="
    ls -la "${BUILD_DIR}"/*.pkg.tar.*
    echo "Hint: mount /output to extract packages:"
    echo "  docker run --rm -v \$(pwd)/output:/output <image>"
fi
