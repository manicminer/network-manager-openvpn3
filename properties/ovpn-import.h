/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef OVPN_IMPORT_H
#define OVPN_IMPORT_H

#include <NetworkManager.h>

#define OPENVPN3_SERVICE_TYPE "org.freedesktop.NetworkManager.openvpn3"
/* The profile is stored base64-encoded: multi-line values do not survive
 * every NetworkManager settings backend (netplan escapes newlines twice). */
#define OPENVPN3_KEY_PROFILE  "profile"
#define OPENVPN3_KEY_USERNAME "username"
#define OPENVPN3_KEY_PASSWORD "password"
#define OPENVPN3_KEY_CHALLENGE "challenge-response"
/* Passphrase of the private key: PKCS#12 bundle or encrypted PEM key. */
#define OPENVPN3_KEY_CERT_PASS "cert-pass"

typedef struct {
    char *config;   /* profile with every file inlined, no credentials */
    char *username; /* from inline <auth-user-pass> or its file, may be NULL */
    char *password; /* ditto */
    char *remote;   /* first remote host, may be NULL */
    gboolean needs_user_pass;
    gboolean needs_cert_pass; /* PKCS#12 or encrypted private key */
} Openvpn3Profile;

void openvpn3_profile_free(Openvpn3Profile *p);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(Openvpn3Profile, openvpn3_profile_free)

/* Normalizes profile text; file references are resolved against @base_dir. */
Openvpn3Profile *openvpn3_profile_parse(const char *text, const char *base_dir, GError **error);

Openvpn3Profile *openvpn3_profile_load(const char *path, GError **error);

/* Builds a new VPN connection named after the file. */
NMConnection *openvpn3_connection_from_profile(Openvpn3Profile *p, const char *id);

/* Profile text stored in / read from a VPN setting; NULL when absent or invalid. */
char *openvpn3_setting_get_profile(NMSettingVpn *s_vpn);
void  openvpn3_setting_set_profile(NMSettingVpn *s_vpn, const char *profile);

/* First remote host of a normalized profile, or NULL. */
char *openvpn3_profile_remote(const char *config);

#endif
