#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# End-to-end test: a local OpenVPN 2 server, openvpn3 as the client, driven
# through NetworkManager with this plugin. Runs as root on a disposable
# machine (VM or CI runner) with systemd. All data is synthetic.
#
# Usage: run.sh <dir with .deb files>
set -euo pipefail

DEBS=${1:?usage: run.sh <deb dir>}
WORK=$(mktemp -d /tmp/nmovpn3-it.XXXXXX)
# The server unit runs with a private /tmp, keep its files under /etc.
SRV=/etc/openvpn/server/it
SERVER_NET=198.51.100.0
SERVER_IP=198.51.100.1
PUSHED_ROUTE=203.0.113.0/24
PUSHED_DNS=192.0.2.53
PUSHED_DOMAIN=corp.example.com
CON=it-test

log() { printf '\n=== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; dump; exit 1; }
dump() {
  journalctl -b --no-pager -u NetworkManager -n 80 2>/dev/null | grep -iE 'openvpn3|vpn' | tail -40 || :
  openvpn3 sessions-list 2>/dev/null || :
}

wait_for() { # wait_for <seconds> <description> <command...>
  local t=$1 what=$2; shift 2
  for _ in $(seq "$t"); do "$@" && return 0; sleep 1; done
  fail "timed out waiting for: $what"
}

con_state() { nmcli -g GENERAL.STATE connection show "$1" 2>/dev/null || :; }
is_activated() { [ "$(con_state "$1")" = activated ]; }
is_inactive() { [ -z "$(con_state "$1")" ]; }
tun_dev() { openvpn3 sessions-list 2>/dev/null | awk '/Device:/{print $NF; exit}'; }

install_packages() {
  log "Installing packages"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  if [ -z "$(apt-cache policy openvpn3-client | awk '/Candidate:/{print $2}' | grep -v none)" ]; then
    # Older releases: openvpn3 comes from the OpenVPN repository.
    . /etc/os-release
    apt-get install -y -qq curl gpg >/dev/null
    curl -fsSL https://packages.openvpn.net/packages-repo.gpg -o /etc/apt/keyrings/openvpn.asc
    echo "deb [signed-by=/etc/apt/keyrings/openvpn.asc] https://packages.openvpn.net/openvpn3/debian $VERSION_CODENAME main" \
      > /etc/apt/sources.list.d/openvpn3.list
    apt-get update -qq
  fi
  apt-get install -y -qq --no-install-recommends network-manager openvpn openssl iputils-ping systemd-resolved >/dev/null
  systemctl enable --now systemd-resolved NetworkManager
  apt-get install -y -qq --reinstall --no-install-recommends "$DEBS"/network-manager-openvpn3_*.deb \
    > "$WORK/apt.log" 2>&1 || { cat "$WORK/apt.log"; fail "package installation failed"; }
  # The package turns on openvpn3's DNS handling on first install.
  grep -q '"systemd_resolved" *: *true' /var/lib/openvpn3/netcfg.json \
    || fail "openvpn3 DNS integration not enabled by the package"
}

make_pki() {
  log "Generating a throwaway PKI"
  install -d -m 700 "$SRV"
  cd "$SRV"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
    -subj "/CN=Test CA" -keyout ca.key -out ca.crt 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -subj "/CN=vpn.example.net" -keyout server.key -out server.csr 2>/dev/null
  printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n' > ext.cnf
  openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 \
    -extfile ext.cnf -out server.crt 2>/dev/null
  cp ca.crt "$WORK/"
}

start_server() {
  log "Starting OpenVPN server"
  install -d -m 755 /etc/openvpn/server
  cat > /etc/openvpn/server/check-user.sh <<'EOF'
#!/bin/sh
{ read -r user; read -r pass; } < "$1"
[ "$user" = testuser ] || exit 1
[ "$pass" = testpass ] && exit 0
# static-challenge clients send SCRV1:base64(password):base64(response)
case "$pass" in
  SCRV1:*) p=$(echo "$pass" | cut -d: -f2 | base64 -d); r=$(echo "$pass" | cut -d: -f3 | base64 -d)
           [ "$p" = testpass ] && [ "$r" = 424242 ] ;;
  *) exit 1 ;;
esac
EOF
  chmod 755 /etc/openvpn/server/check-user.sh
  cat > /etc/openvpn/server/it.conf <<EOF
port 1194
proto udp
dev tun-it-srv
dev-type tun
topology subnet
server $SERVER_NET 255.255.255.0
ca $SRV/ca.crt
cert $SRV/server.crt
key $SRV/server.key
dh none
verify-client-cert none
username-as-common-name
script-security 2
auth-user-pass-verify /etc/openvpn/server/check-user.sh via-file
push "route ${PUSHED_ROUTE%/*} 255.255.255.0"
push "dhcp-option DNS $PUSHED_DNS"
push "dhcp-option DOMAIN $PUSHED_DOMAIN"
keepalive 2 10
verb 3
EOF
  systemctl restart openvpn-server@it
  wait_for 20 "server tun device" ip link show tun-it-srv
}

write_profile() { # write_profile <path> [password] [extra directive]; no password: prompt
  local creds="<auth-user-pass>
testuser
${2:-}
</auth-user-pass>"
  [ -n "${2:-}" ] || creds="auth-user-pass"
  cat > "$1" <<EOF
client
dev tun
proto udp
remote 127.0.0.1 1194
nobind
remote-cert-tls server
${3:-}
<ca>
$(cat "$WORK/ca.crt")
</ca>
$creds
EOF
}

# NetworkManager needs an active connection to hang the VPN on. A dummy
# device with a high-metric default route does not disturb the VM's own
# networking.
base_connection() {
  log "Creating base connection"
  # Server images leave devices unmanaged; desktops manage them. Match the
  # desktop for the devices this test uses.
  printf '[keyfile]\nunmanaged-devices=*,except:interface-name:it-dummy0,except:interface-name:tun*\n' \
    > /etc/NetworkManager/conf.d/10-globally-managed-devices.conf
  systemctl restart NetworkManager
  nm-online -s -q -t 30
  nmcli connection delete it-base >/dev/null 2>&1 || :
  nmcli connection add type dummy ifname it-dummy0 con-name it-base \
    ipv4.method manual ipv4.addresses 192.0.2.10/24 ipv4.gateway 192.0.2.254 \
    ipv4.route-metric 20000 ipv6.method disabled >/dev/null
  nmcli connection up it-base >/dev/null
}

test_connect() {
  log "Import and connect"
  write_profile "$WORK/$CON.ovpn" testpass
  nmcli connection import type openvpn3 file "$WORK/$CON.ovpn"
  nmcli connection up "$CON" || fail "nmcli connection up failed"
  wait_for 30 "activated" is_activated "$CON"
  local dev; dev=$(tun_dev)
  [ -n "$dev" ] || fail "no tunnel interface reported"
  echo "tunnel device: $dev"

  ip -4 addr show dev "$dev" | grep -q "inet ${SERVER_IP%.*}\." || fail "no tunnel address on $dev"
  [ "$(ip -4 route show "$PUSHED_ROUTE" dev "$dev" | wc -l)" -ge 1 ] || fail "pushed route missing"
  ip -4 route show "$PUSHED_ROUTE"
  resolvectl dns "$dev" | grep -q "$PUSHED_DNS" || fail "DNS server missing on $dev"
  resolvectl domain "$dev" | grep -q "$PUSHED_DOMAIN" || fail "search domain missing on $dev"
  ping -c 2 -W 2 "$SERVER_IP" >/dev/null || fail "no traffic through the tunnel"
  openvpn3 sessions-list | grep -q "Client connected" || fail "openvpn3 session not connected"
  nmcli -g IP4.DNS connection show "$CON" | grep -q "$PUSHED_DNS" || fail "NetworkManager does not know the DNS server"
  nmcli -g IP4.DOMAIN connection show "$CON" | grep -q "$PUSHED_DOMAIN" || fail "NetworkManager does not know the search domain"
  nmcli -f GENERAL.STATE,IP4.ADDRESS,IP4.ROUTE,IP4.DNS,IP4.DOMAIN connection show "$CON"
}

test_reconnect() {
  log "Server restart: openvpn3 reconnects, NetworkManager stays activated"
  systemctl restart openvpn-server@it
  sleep 15
  is_activated "$CON" || fail "connection dropped after server restart"
  local dev; dev=$(tun_dev)
  wait_for 30 "traffic after reconnect" ping -c 1 -W 2 "$SERVER_IP"
  resolvectl dns "$dev" | grep -q "$PUSHED_DNS" || fail "DNS lost after reconnect"
}

test_disconnect() {
  log "Disconnect"
  local dev; dev=$(tun_dev)
  nmcli connection down "$CON"
  wait_for 20 "inactive" is_inactive "$CON"
  sleep 2
  ! ip link show "$dev" >/dev/null 2>&1 || fail "$dev still exists"
  ! openvpn3 sessions-list | grep -q "Client connected" || fail "openvpn3 session left behind"
  ip -4 route show "$PUSHED_ROUTE" | grep -q . && fail "pushed route left behind"
  return 0
}

test_bad_password() {
  log "Wrong password is reported as a login failure"
  write_profile "$WORK/it-bad.ovpn" wrongpass
  nmcli connection import type openvpn3 file "$WORK/it-bad.ovpn"
  local out
  if out=$(nmcli --wait 40 connection up it-bad 2>&1); then
    fail "connection with a wrong password came up"
  fi
  echo "$out"
  # NetworkManager words the LOGIN_FAILED reason as "Invalid secrets".
  grep -qiE 'invalid secrets|login' <<<"$out" || fail "failure not reported as a login failure"
  nmcli connection delete it-bad >/dev/null
}

test_agent_password() {
  log "Password from a secret agent (not stored in the connection)"
  write_profile "$WORK/it-agent.ovpn"
  nmcli connection import type openvpn3 file "$WORK/it-agent.ovpn"
  [ "$(nmcli -g vpn.data connection show it-agent | grep -o 'password-flags = [0-9]')" = "password-flags = 1" ] \
    || fail "imported password is not agent-owned"
  nmcli connection modify it-agent +vpn.data username=testuser
  printf 'vpn.secrets.password:testpass\n' > "$WORK/secrets"
  nmcli --wait 40 connection up it-agent passwd-file "$WORK/secrets" || fail "agent password flow failed"
  wait_for 30 "activated" is_activated it-agent
  nmcli connection down it-agent
  nmcli connection delete it-agent >/dev/null
}

test_static_challenge() {
  log "One-time code (static challenge) asked through the secret agent"
  write_profile "$WORK/it-otp.ovpn" "" 'static-challenge "Enter OTP" 1'
  nmcli connection import type openvpn3 file "$WORK/it-otp.ovpn"
  nmcli connection modify it-otp +vpn.data username=testuser
  printf 'vpn.secrets.password:testpass\nvpn.secrets.challenge-response:424242\n' > "$WORK/secrets"
  nmcli --wait 40 connection up it-otp passwd-file "$WORK/secrets" || fail "static challenge flow failed"
  wait_for 30 "activated" is_activated it-otp
  nmcli connection down it-otp
  nmcli connection delete it-otp >/dev/null
}

cleanup() {
  nmcli connection delete "$CON" it-base >/dev/null 2>&1 || :
  systemctl stop openvpn-server@it 2>/dev/null || :
  rm -f /etc/NetworkManager/conf.d/10-globally-managed-devices.conf
  rm -rf "$WORK" "$SRV" /etc/openvpn/server/it.conf /etc/openvpn/server/check-user.sh
}

install_packages
make_pki
start_server
base_connection
test_connect
test_reconnect
test_disconnect
test_bad_password
test_agent_password
test_static_challenge
cleanup
log "ALL INTEGRATION TESTS PASSED"
