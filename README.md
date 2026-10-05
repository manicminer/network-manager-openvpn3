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
  the connection, the original files are no longer needed. This includes file
  references inside `<connection>` blocks, which are a scope of options and
  not an opaque payload: a profile whose only `remote` lives in one imports
  normally. Directive order, repeated directives, repeated `<connection>`
  blocks, quoting and directives this plugin has never heard of are all
  preserved — there is no list of allowed directives.
- Formatting — comments and blank lines — is dropped at import. openvpn3 reads
  nothing from it, and the profile in a connection is no longer a file anybody
  opens in an editor, so a client that shows it as a table of entries would
  only get rows nothing can act on. A `#` or `;` counts as a comment when it is
  unquoted, unescaped and starts a word — what OpenVPN 2's `parse_line()` and
  openvpn3's `LexComment` agree on. A quoted, escaped or word-internal one is a
  value and stays. A line counts as blank when `g_ascii_isspace()` — what this
  code strips every line with — is all it holds, so a line of `U+00A0` is a
  value and stays, and so is one of `\v`, which GLib does not count as
  whitespace even though C's `isspace()` does. The lines of an inline payload
  (`<ca>`, `<key>`, `<auth-user-pass>`, an unknown `<tag>`) are content rather
  than directives and are never touched: a blank line inside a certificate, or
  an empty password, is kept.
- Credentials in the profile (an inline `<auth-user-pass>` block or the file
  it points to) move into the connection: the username as data, the password
  as a NetworkManager secret. Without them the password is agent-owned: GNOME
  asks for it and can keep it in the keyring.
- One-time codes (`static-challenge`, and dynamic challenges sent by the
  server) are asked for on every connect and never stored.
- Web based login (the server sends a URL, e.g. SSO/OAuth after the
  password): the login page opens in the browser of the user at the desktop
  (the active graphical session), and the connection completes once the
  login is done there. NetworkManager gives a VPN 60 seconds to come up by
  default; for slow logins raise it, e.g.
  `nmcli connection modify office vpn.timeout 180`.
- Client certificates: PEM `cert`/`key`, encrypted private keys and PKCS#12
  bundles (`pkcs12`). openvpn3 itself cannot read PKCS#12, so the bundle is
  kept in the connection and converted to PEM in memory when connecting. The
  passphrase of an encrypted key or bundle is a NetworkManager secret
  ("Private key passphrase"), asked for by GNOME and optionally kept in the
  keyring.
- Export (`nmcli connection export`, and the editors) writes the profile back
  out as it is stored: passwords and passphrases are **not** in it — they
  stayed in NetworkManager and the exported profile asks for them again — but
  the certificates, private keys and shared TLS keys that were inlined at
  import **are**, because they are part of the profile. The file is therefore
  created `0600`, and an existing file at that path is replaced along with its
  permissions. A connection that keeps its profile with its secrets refuses to
  export at all (see below).

### Where the profile is stored

A profile is self-contained: certificates, private keys and shared TLS keys
are inlined into it at import. By default it is kept in `vpn.data`. The
keyfile of a system connection is root-owned and `0600` — the concern is not
the file but that `vpn.data` is ordinary connection data, which NetworkManager
hands to every client allowed to read the connection's settings, and which
lives in whatever settings backend the distribution uses. Secrets are gated
instead: they go to the owning agent, or to a caller that asks for secrets
specifically. So a front-end may give NetworkManager the **whole profile as a
secret**, so that the secret agent (KWallet, the GNOME keyring) keeps it, or
NetworkManager itself owns it for unattended activation.

The two layouts are mutually exclusive:

| | `vpn.data` | `vpn.secrets` |
| --- | --- | --- |
| legacy | `profile` = base64 profile | — |
| secret | `profile-storage` = `secret`, `profile-flags` = `1` (agent-owned) or `0` (system-owned) | `profile` = base64 profile |

`profile-flags` is nothing special: NetworkManager keeps the flags of a VPN
secret `x` in `vpn.data["x-flags"]`, so it is simply the flags key of the
`profile` secret. It follows that **absent `profile-flags` mean `0`** — what
absent flags mean to NetworkManager, i.e. system-owned. A reader must not
read them as agent-owned: that would move the profile of an unattended
connection into a user's wallet the first time anything saved it. A writer
that wants the wallet writes `1` explicitly, which is what new profiles get.

Why the whole profile rather than a list of sensitive directives: there is no
whitelist to get wrong, unknown sensitive directives are covered too, and
nothing has to be taken apart and put back together.

Rules a client must follow:

- In secret mode `vpn.data["profile"]` is **removed**. Never leave a public
  copy behind and never read one in secret mode: it is stale by definition.
  A client that predates this layout therefore finds no profile and fails
  closed instead of connecting with an outdated one.
- A `profile-storage` value other than `secret` (and other than absent or
  empty, which mean the legacy layout) is a layout the reader does not know.
  **Fail closed**: the `profile` data item belongs to whatever layout the
  connection used before, so it must not be read, written back, exported, or
  reclassified as legacy on edit. The service refuses such a connection, the
  importer's reader returns no profile, the editors refuse to save it and say
  why, and export refuses.
- `profile-flags` may only be `0` or `1`. `NotSaved` / `NotRequired` would
  describe a profile nobody could ever reconstruct and are rejected — as is
  anything that is not one of those two numbers. Rejecting means reporting an
  error, never saving the connection with the profile dropped.
- Never fall back to writing the profile into `vpn.data` because the wallet
  was unavailable. Report the failure instead.
- `NeedSecrets` asks for the profile first when it is not available: which
  credentials a connection needs is a property of the profile. For the same
  reason the auth dialog does not offer a password prompt for a connection
  whose profile it could not read; it explains that the profile is unavailable.
- `profile-storage` tells "the profile is locked or the agent is gone" apart
  from "this connection has no profile".

Implementations: `src/nm_openvpn3/profile_storage.py` — `stored_profile()` is
the one place that decides which layout a connection uses, shared by the
service and the auth dialog — and `openvpn3_setting_get_profile()` /
`openvpn3_setting_profile_flags()` / `openvpn3_setting_set_profile_secret()`
in `properties/ovpn-import.c` (libnm plugin, GTK editors).

Import always produces the legacy layout, so existing clients keep working; a
front-end that offers the choice migrates the connection before saving it.

### Editors

- **GNOME Settings** uses the GTK 4 editor, **nm-connection-editor** the
  GTK 3 one; both come with `network-manager-openvpn3-gnome`. They load a
  profile from a file and edit the username and the stored secrets.
- Those two editors do not offer a choice of profile storage; they keep
  whatever layout the connection already uses. If the profile is a secret and
  was not handed to the editor, it refuses to save rather than overwrite it,
  and exporting such a connection is refused rather than writing private key
  material to a plain file. They refuse the same way, with the reason on the
  page, for a connection whose `profile-flags` would never store the profile,
  and for a `profile-storage` layout they do not know — in the first case
  loading a profile from a file repairs the connection (and stores it
  agent-owned, like any new profile), in the second nothing does, because
  saving would have to reclassify a layout they cannot read.
- **Plasma** has a native editor in plasma-nm which does offer the choice
  (wallet or system storage) and edits the profile itself.

### Limitation: PKCS#11

Hardware tokens and smart cards (`pkcs11-providers`, `pkcs11-id`) do not work
because openvpn3 has no PKCS#11 / external key support: in openvpn3-linux
(checked v24 to v27) the external PKI callbacks are unimplemented
([`core-client.hpp`](https://github.com/OpenVPN/openvpn3-linux/blob/master/src/client/core-client.hpp),
`external_pki_cert_request` / `external_pki_sign_request`), and a profile
without a PEM key is rejected with *"Configuration requires external PKI
which is not implemented yet"*. Nothing a front-end can do works around it;
use the classic OpenVPN 2 NetworkManager plugin for such profiles until
openvpn3 implements it.

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
  key `profile`, or the `profile` secret — see *Where the profile is
  stored*): some NetworkManager settings backends (netplan on Ubuntu) do not
  keep multi-line values intact.

Logs: `journalctl -u NetworkManager | grep nm-openvpn3`.

## Reporting problems

Open an [issue](https://github.com/AlexeySetevoi/network-manager-openvpn3/issues/new/choose).
The bug report form asks for the distribution, package versions, desktop and
the NetworkManager journal, and has a command that collects all of it.
Remove server names, addresses, usernames and login URLs before posting, and
never attach a profile as is.

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
  PKCS#12 conversion, the auth dialog and, with a display, the editors
  (`GDK_BACKEND=broadway` works headless; `OPENVPN3_EDITOR_GTK=3` tests the
  GTK 3 one).
- `tests/integration/run.sh`: end to end on a disposable machine — a local
  OpenVPN server, openvpn3 as the client, NetworkManager with this plugin:
  connect, routes and DNS, reconnect, disconnect, wrong password, password
  from a secret agent, one-time code, PKCS#12 bundle and encrypted key
  against a certificate-only server. `tests/integration/Vagrantfile` runs it
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
