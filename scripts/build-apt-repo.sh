#!/bin/bash
# Builds a signed APT repository for GitHub Pages from release .deb files.
# Usage: scripts/build-apt-repo.sh <deb dir> <output dir> <signing key fingerprint>
# The passphrase of the key is read from $GPG_PASSPHRASE.
set -euo pipefail
debs=$1 site=$2 key=$3
name=network-manager-openvpn3
codenames=(resolute noble trixie)

sign() { gpg --batch --yes --pinentry-mode loopback --passphrase-fd 3 --local-user "$key" "$@" 3<<<"$GPG_PASSPHRASE"; }

rm -rf "$site"
mkdir -p "$site"
for c in "${codenames[@]}"; do
  pool=pool/main/$c
  mkdir -p "$site/$pool" "$site/dists/$c/main/binary-amd64"
  found=0
  for deb in "$debs"/*+"$c"[0-9]*_amd64.deb; do
    [ -e "$deb" ] || continue
    cp "$deb" "$site/$pool/"
    found=1
  done
  [ "$found" = 1 ] || { echo "no packages for $c" >&2; exit 1; }
  (cd "$site" && apt-ftparchive packages "$pool" > "dists/$c/main/binary-amd64/Packages")
  gzip -9nk "$site/dists/$c/main/binary-amd64/Packages"
  apt-ftparchive \
    -o APT::FTPArchive::Release::Origin="$name" \
    -o APT::FTPArchive::Release::Label="$name" \
    -o APT::FTPArchive::Release::Suite="$c" \
    -o APT::FTPArchive::Release::Codename="$c" \
    -o APT::FTPArchive::Release::Architectures=amd64 \
    -o APT::FTPArchive::Release::Components=main \
    release "$site/dists/$c" > "$site/dists/$c/Release"
  sign --clearsign -o "$site/dists/$c/InRelease" "$site/dists/$c/Release"
  sign --armor --detach-sign -o "$site/dists/$c/Release.gpg" "$site/dists/$c/Release"
done

gpg --armor --export "$key" > "$site/$name.asc"
gpg --export "$key" > "$site/$name.gpg"
cat > "$site/index.html" <<HTML
<!doctype html>
<meta charset="utf-8">
<title>$name APT repository</title>
<h1>$name APT repository</h1>
<p>Packages for Ubuntu 26.04 (resolute), Ubuntu 24.04 (noble) and Debian 13 (trixie).</p>
<p>See <a href="https://github.com/AlexeySetevoi/$name#installation">the README</a> for installation.</p>
HTML
touch "$site/.nojekyll"
