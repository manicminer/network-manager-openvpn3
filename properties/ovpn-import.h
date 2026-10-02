/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef OVPN_IMPORT_H
#define OVPN_IMPORT_H

#include <NetworkManager.h>

#define OPENVPN3_SERVICE_TYPE "org.freedesktop.NetworkManager.openvpn3"
/* The profile is stored base64-encoded: multi-line values do not survive
 * every NetworkManager settings backend (netplan escapes newlines twice).
 *
 * It lives in one of two places, never both (see README.md, "Where the
 * profile is stored"):
 *
 *   legacy  vpn.data["profile"]           = base64 profile
 *   secret  vpn.data["profile-storage"]   = "secret"
 *           vpn.data["profile-flags"]     = 1 (agent-owned) or 0 (system)
 *           vpn.secrets["profile"]        = base64 profile
 *
 * The second keeps inlined private keys out of ordinary connection data.  The
 * keyfile of a system connection is root-owned and 0600, but NetworkManager
 * hands connection data to every client allowed to read the connection's
 * settings, whereas secrets are only given to the owning agent or on an
 * explicit request.  A plugin that does not know about the second layout
 * finds no profile and fails closed rather than using a stale public copy.
 *
 * Absent profile-flags mean NM_SETTING_SECRET_FLAG_NONE, exactly what they
 * mean to NetworkManager -- system-owned.  A writer that wants the user's
 * wallet says agent-owned explicitly. */
#define OPENVPN3_KEY_PROFILE  "profile"
#define OPENVPN3_KEY_PROFILE_STORAGE "profile-storage"
#define OPENVPN3_KEY_PROFILE_FLAGS OPENVPN3_KEY_PROFILE "-flags"
#define OPENVPN3_PROFILE_STORAGE_SECRET "secret"
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

/* TRUE when the profile of @s_vpn is one of the connection's secrets. */
gboolean openvpn3_setting_profile_is_secret(NMSettingVpn *s_vpn);

/* The connection's profile-storage marker, or NULL when it has none. */
const char *openvpn3_setting_profile_storage(NMSettingVpn *s_vpn);

/* TRUE when @s_vpn declares a profile layout this build does not know, in
 * which case no profile can be read from it at all. */
gboolean openvpn3_setting_profile_storage_is_unsupported(NMSettingVpn *s_vpn);

/* Why such a connection cannot be read; free with g_free(). */
char *openvpn3_setting_unsupported_storage_message(NMSettingVpn *s_vpn);

/* Secret flags to store the profile of @s_vpn with; NM_SETTING_SECRET_FLAG_NONE
 * in legacy mode and for a secret profile without flags, as NetworkManager
 * reads absent flags.
 *
 * FALSE, leaving @out_flags alone, when the stored value is not one a profile
 * can be stored with: NotSaved/NotRequired describe a profile nobody could
 * ever reconstruct, and a value that is no number at all is no better.  Such
 * a connection has to be reported, not written back with its profile quietly
 * dropped. */
gboolean openvpn3_setting_profile_flags(NMSettingVpn *s_vpn, NMSettingSecretFlags *out_flags);

/* Profile text stored in / read from a VPN setting; NULL when absent or
 * invalid.  Reads whichever layout the setting uses; in secret mode a
 * leftover public copy is ignored, it is stale by definition. */
char *openvpn3_setting_get_profile(NMSettingVpn *s_vpn);

/* Stores @profile as a public data item (legacy layout). */
void  openvpn3_setting_set_profile(NMSettingVpn *s_vpn, const char *profile);

/* Stores @profile as the connection's "profile" secret with @flags, and
 * removes the public copy.  @flags must store the secret: agent-owned for a
 * wallet, none for a NetworkManager-owned (unattended) connection.
 *
 * FALSE for any other @flags, with @s_vpn left exactly as it was: the caller
 * is about to save a connection whose profile could never be read back, and
 * has to say so rather than save it without one. */
gboolean openvpn3_setting_set_profile_secret(NMSettingVpn        *s_vpn,
                                             const char          *profile,
                                             NMSettingSecretFlags flags,
                                             GError             **error);

/* First remote host of a normalized profile, or NULL. */
char *openvpn3_profile_remote(const char *config);

#endif
