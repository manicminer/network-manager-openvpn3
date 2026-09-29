#!/bin/bash
# Builds the .deb packages for one distribution inside a container.
# Usage: scripts/build-deb.sh <image> <codename> [outdir]
#   e.g. scripts/build-deb.sh ubuntu:26.04 resolute dist/
set -euo pipefail
image=$1 codename=$2 out=${3:-dist}
src=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$out"
out=$(cd "$out" && pwd)
docker run --rm -v "$src":/src:ro -v "$out":/out -e CODENAME="$codename" \
  -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" "$image" bash -euo pipefail -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends devscripts equivs lintian git ca-certificates >/dev/null
    mkdir -p /build && cp -r /src /build/pkg && cd /build/pkg
    rm -rf build obj-* debian/.debhelper
    mk-build-deps -i -r -t "apt-get -y -qq --no-install-recommends" debian/control >/dev/null
    # Per-distribution version: rewrite the top changelog entry in the copy.
    base=$(dpkg-parsechangelog -S Version)
    sed -i "1s/(${base}) [a-z-]*;/(${base}+${CODENAME}1) ${CODENAME};/" debian/changelog
    dpkg-buildpackage -us -uc -b
    lintian --fail-on error --suppress-tags initial-upload-closes-no-bugs ../*.changes
    find .. -maxdepth 1 -name "*.deb" ! -name "*-dbgsym_*" -exec cp {} /out/ \;
    chown "$HOST_UID:$HOST_GID" /out/*.deb
  '
