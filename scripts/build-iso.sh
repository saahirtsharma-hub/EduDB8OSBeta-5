#!/bin/bash
# Run as root on a Debian/Ubuntu host with internet access:  sudo ./build-iso.sh
set -e
apt-get install -y live-build
cd "$(dirname "$0")/../live-build"
# Use the custom kernel packages if they have been built (see build-kernel.sh)
if ls ../kernel/*.deb >/dev/null 2>&1; then
  mkdir -p config/packages.chroot
  cp ../kernel/linux-image-*xfceproxy*.deb config/packages.chroot/
  EXTRA="--linux-packages none --linux-flavours none"
fi
lb clean --purge || true
lb config $EXTRA
lb build 2>&1 | tee build.log
ls -lh ./*.iso
