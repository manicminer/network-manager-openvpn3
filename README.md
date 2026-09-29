# network-manager-openvpn3

NetworkManager VPN plugin for [OpenVPN 3 Linux](https://github.com/OpenVPN/openvpn3-linux).

OpenVPN 3 Linux ships its own command line client and D-Bus services, but no
NetworkManager integration. This plugin lets NetworkManager start and stop
openvpn3 sessions, so OpenVPN 3 connections show up where every other VPN
does: the VPN toggle in GNOME Quick Settings, **Settings → Network**, and
`nmcli`.

Supported releases: Ubuntu 26.04, Ubuntu 24.04, Debian 13 (amd64).

## Installation

### From the APT repository

```sh
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://alexeysetevoi.github.io/network-manager-openvpn3/network-manager-openvpn3.gpg \
  | sudo tee /etc/apt/keyrings/network-manager-openvpn3.gpg >/dev/null
echo "deb [signed-by=/etc/apt/keyrings/network-manager-openvpn3.gpg] https://alexeysetevoi.github.io/network-manager-openvpn3 $(. /etc/os-release && echo "$VERSION_CODENAME") main" \
  | sudo tee /etc/apt/sources.list.d/network-manager-openvpn3.list
sudo apt update
sudo apt install network-manager-openvpn3-gnome
```

Check that the key you downloaded is the project key:

```sh
gpg --show-keys /etc/apt/keyrings/network-manager-openvpn3.gpg
```

The fingerprint must be `58DA FDC4 A0AE 538F 7D72  5E61 78EB B361 EFD7 F500`.

`network-manager-openvpn3-gnome` adds the editor for GNOME Settings; on a
system without GNOME install `network-manager-openvpn3` alone.

The packages depend on the OpenVPN 3 client (`openvpn3-client`). Ubuntu
26.04 and Debian 13 have it in their archives. On Ubuntu 24.04 add the
[OpenVPN 3 repository](https://community.openvpn.net/openvpn/wiki/OpenVPN3Linux)
first. Tested with openvpn3 v24 (Debian 13) and v27.

### From a release

Each [release](https://github.com/AlexeySetevoi/network-manager-openvpn3/releases)
has the `.deb` files for every supported distribution, the source tarball, a
`SHA256SUMS` file and its signature.

```sh
gpg --import network-manager-openvpn3.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
sudo apt install ./network-manager-openvpn3_*+noble1_amd64.deb ./network-manager-openvpn3-gnome_*+noble1_amd64.deb
```

The files also carry [build provenance attestations](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations):

```sh
gh attestation verify network-manager-openvpn3_*.deb -R AlexeySetevoi/network-manager-openvpn3
```

(`gh attestation` needs GitHub CLI 2.49 or newer.)

## Usage

Import an OpenVPN profile:

```sh
nmcli connection import type openvpn3 file office.ovpn
nmcli connection up office
```

In GNOME: **Settings → Network → VPN → +**, choose **OpenVPN 3**, then
**Load from file…**. If the classic OpenVPN plugin is installed as well,
**Import from file…** may pick that one; choosing **OpenVPN 3** explicitly
avoids it.

After that the connection is in the VPN menu of Quick Settings.

### Profiles and credentials

- Files referenced by the profile (`ca`, `cert`, `key`, `tls-auth`,
  `tls-crypt`, `auth-user-pass` …) are read once at import and stored inside
  the connection, the original files are no longer needed.
- Credentials in the profile (an inline `<auth-user-pass>` block or the file
  it points to) move into the connection: the username as data, the password
  as a NetworkManager secret. Without them the password is agent-owned: GNOME
  asks for it and can keep it in the keyring.
- One-time codes (`static-challenge`, and dynamic challenges sent by the
  server) are asked for on every connect and never stored.
- Exported profiles contain no credentials.

### Not supported

- Web based authentication (SAML / "open this URL" flows).
- PKCS#11 tokens and PKCS#12 files; convert PKCS#12 to PEM (`ca`, `cert`, `key`).
- GTK 3 connection editors such as `nm-connection-editor` (use GNOME
  Settings or `nmcli`).

## How it works

- `nm-openvpn3-service` is started by NetworkManager. It imports the profile
  into openvpn3 as a single-use configuration, creates a session and drives
  it over openvpn3's D-Bus API, answering credential requests from the
  connection's secrets.
- openvpn3 configures the tunnel itself (`openvpn3-service-netcfg`: device,
  addresses, routes, DNS). Once connected the plugin reports the same
  addresses, routes and DNS settings to NetworkManager, so NetworkManager
  shows the connection as active with correct details and keeps its own DNS
  configuration consistent.
- openvpn3 only applies DNS when its netcfg service is told which resolver to
  use. On a fresh install with systemd-resolved running, the package enables
  it (`/var/lib/openvpn3/netcfg.json`); an existing configuration is left
  alone. To enable it by hand:
  `sudo openvpn3-admin netcfg-service --config-set systemd-resolved 1`.
- Sessions belong to root; `sudo openvpn3 sessions-list` shows them.
- The profile is stored base64-encoded in the connection (`vpn.data`
  key `profile`): some NetworkManager settings backends (netplan on Ubuntu)
  do not keep multi-line values intact.

Logs: `journalctl -u NetworkManager | grep nm-openvpn3`.

## Building

```sh
meson setup build
ninja -C build
meson test -C build
```

Build dependencies (Debian/Ubuntu): `meson pkgconf libnm-dev
libnma-gtk4-dev libgtk-4-dev libglib2.0-dev python3-gi python3-pytest
gir1.2-nm-1.0`. `-Dgnome=false` skips the GTK 4 editor.

Packages for one distribution, built in a container:

```sh
scripts/build-deb.sh ubuntu:26.04 resolute dist/
```

### Tests

- `tests/unit`: profile import (through the built libnm plugin), the VPN
  plugin D-Bus contract, the session state machine against a fake openvpn3,
  the auth dialog and, with a display, the GTK editor
  (`GDK_BACKEND=broadway` works headless).
- `tests/integration/run.sh`: end to end on a disposable machine — a local
  OpenVPN server, openvpn3 as the client, NetworkManager with this plugin:
  connect, routes and DNS, reconnect, disconnect, wrong password, password
  from a secret agent, one-time code. `tests/integration/Vagrantfile` runs it
  in libvirt VMs:

  ```sh
  cd tests/integration
  BOX=cloud-image/ubuntu-26.04 DEBS=$PWD/../../dist vagrant up
  vagrant ssh -c 'sudo /repo/tests/integration/run.sh /debs'
  ```

CI builds and tests every distribution and runs the integration test on
Ubuntu 24.04. Tags `v*` publish a release and the APT repository.

## License

GPL-2.0-or-later, see [LICENSE](LICENSE).

This project is developed with [Claude Code](https://claude.com/claude-code).
