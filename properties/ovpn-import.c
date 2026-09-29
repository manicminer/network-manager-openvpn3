/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Import of OpenVPN profiles.
 *
 * openvpn3 needs a self-contained profile, so every file referenced by the
 * profile is inlined.  Credentials are taken out of the profile and stored
 * in the connection instead: the username as data, the password as secret.
 */

#include "ovpn-import.h"

#include <string.h>

static const char *const file_directives[] = {
    "ca", "cert", "key", "extra-certs", "tls-auth", "tls-crypt", "tls-crypt-v2", "crl-verify", NULL,
};

void
openvpn3_profile_free(Openvpn3Profile *p)
{
    if (!p)
        return;
    g_free(p->config);
    g_free(p->username);
    if (p->password) {
        memset(p->password, 0, strlen(p->password));
        g_free(p->password);
    }
    g_free(p->remote);
    g_free(p);
}

/* Splits a directive line into words, honouring double and single quotes. */
static char **
split_words(const char *line)
{
    GPtrArray *words = g_ptr_array_new();
    const char *s   = line;

    while (*s) {
        GString *w;

        while (g_ascii_isspace(*s))
            s++;
        if (!*s || *s == '#' || *s == ';')
            break;
        w = g_string_new(NULL);
        while (*s && !g_ascii_isspace(*s)) {
            if (*s == '"' || *s == '\'') {
                char q = *s++;
                while (*s && *s != q) {
                    if (q == '"' && *s == '\\' && s[1])
                        s++;
                    g_string_append_c(w, *s++);
                }
                if (*s)
                    s++;
            } else {
                g_string_append_c(w, *s++);
            }
        }
        g_ptr_array_add(words, g_string_free(w, FALSE));
    }
    g_ptr_array_add(words, NULL);
    return (char **) g_ptr_array_free(words, FALSE);
}

static gboolean
is_file_directive(const char *name)
{
    return g_strv_contains(file_directives, name);
}

static char *
read_referenced(const char *base_dir, const char *ref, GError **error)
{
    g_autofree char *path = g_path_is_absolute(ref) ? g_strdup(ref) : g_build_filename(base_dir, ref, NULL);
    char            *contents = NULL;

    if (!g_file_get_contents(path, &contents, NULL, error)) {
        g_prefix_error(error, "Cannot read file referenced by the profile: ");
        return NULL;
    }
    return contents;
}

static void
append_inline(GString *out, const char *tag, const char *contents)
{
    g_string_append_printf(out, "<%s>\n%s", tag, contents);
    if (!g_str_has_suffix(contents, "\n"))
        g_string_append_c(out, '\n');
    g_string_append_printf(out, "</%s>\n", tag);
}

static void
take_credentials(Openvpn3Profile *p, const char *text)
{
    g_auto(GStrv) lines = g_strsplit(text, "\n", 3);

    if (lines[0] && *g_strstrip(lines[0]))
        p->username = g_strdup(lines[0]);
    if (lines[0] && lines[1]) {
        char *pw = g_strdup(lines[1]);
        g_strchomp(pw);
        if (*pw)
            p->password = pw;
        else
            g_free(pw);
    }
}

Openvpn3Profile *
openvpn3_profile_parse(const char *text, const char *base_dir, GError **error)
{
    g_autoptr(Openvpn3Profile) p = g_new0(Openvpn3Profile, 1);
    g_autoptr(GString) out       = g_string_new(NULL);
    g_autoptr(GString) creds     = NULL;
    g_auto(GStrv) lines          = g_strsplit(text, "\n", -1);
    g_autofree char *inline_tag  = NULL;
    gboolean has_auth_user_pass  = FALSE;
    gboolean wrote_auth_user_pass = FALSE;
    gboolean has_client          = FALSE;
    gboolean has_remote          = FALSE;

    for (char **l = lines; *l; l++) {
        g_autofree char *line = g_strstrip(g_strdup(*l));
        g_auto(GStrv) words   = NULL;
        const char *name;

        /* The empty piece after the final newline is not a line. */
        if (!l[1] && !**l)
            break;
        /* Tolerate CRLF files: g_strstrip removed the \r above. */
        if (inline_tag) {
            g_autofree char *end = g_strdup_printf("</%s>", inline_tag);
            if (g_str_equal(line, end)) {
                if (creds) {
                    take_credentials(p, creds->str);
                    g_string_free(g_steal_pointer(&creds), TRUE);
                } else {
                    g_string_append_printf(out, "%s\n", line);
                }
                g_clear_pointer(&inline_tag, g_free);
            } else if (creds) {
                g_string_append_printf(creds, "%s\n", line);
            } else {
                if (g_str_equal(inline_tag, "key")
                    && (strstr(line, "ENCRYPTED PRIVATE KEY") || strstr(line, "Proc-Type: 4,ENCRYPTED")))
                    p->needs_cert_pass = TRUE;
                g_string_append_printf(out, "%s\n", g_strchomp(*l));
            }
            continue;
        }
        if (line[0] == '<' && g_str_has_suffix(line, ">") && line[1] != '/') {
            inline_tag = g_strndup(line + 1, strlen(line) - 2);
            if (g_str_equal(inline_tag, "auth-user-pass")) {
                creds              = g_string_new(NULL);
                has_auth_user_pass = TRUE;
            } else {
                if (g_str_equal(inline_tag, "pkcs12"))
                    p->needs_cert_pass = TRUE;
                g_string_append_printf(out, "%s\n", line);
            }
            continue;
        }

        words = split_words(line);
        if (!words[0]) {
            g_string_append_printf(out, "%s\n", line);
            continue;
        }
        name = words[0];

        if (g_str_equal(name, "client"))
            has_client = TRUE;
        if (g_str_equal(name, "remote") && words[1]) {
            has_remote = TRUE;
            if (!p->remote)
                p->remote = g_strdup(words[1]);
        }

        if (g_str_equal(name, "auth-user-pass")) {
            has_auth_user_pass = TRUE;
            if (words[1]) {
                g_autofree char *contents = read_referenced(base_dir, words[1], error);
                if (!contents)
                    return NULL;
                take_credentials(p, contents);
            }
            if (!wrote_auth_user_pass)
                g_string_append(out, "auth-user-pass\n");
            wrote_auth_user_pass = TRUE;
            continue;
        }
        if (g_str_equal(name, "pkcs12") && words[1] && !g_str_equal(words[1], "[inline]")) {
            /* openvpn3 cannot read PKCS#12; the service converts the bundle
             * when connecting, so keep it inline as base64. */
            g_autofree char *path = g_path_is_absolute(words[1]) ? g_strdup(words[1])
                                                                 : g_build_filename(base_dir, words[1], NULL);
            g_autofree char *raw  = NULL;
            g_autofree char *b64  = NULL;
            gsize len;

            if (!g_file_get_contents(path, &raw, &len, error)) {
                g_prefix_error(error, "Cannot read file referenced by the profile: ");
                return NULL;
            }
            b64 = g_base64_encode((const guchar *) raw, len);
            g_string_append(out, "<pkcs12>\n");
            for (gsize i = 0, n = strlen(b64); i < n; i += 64)
                g_string_append_printf(out, "%.64s\n", b64 + i);
            g_string_append(out, "</pkcs12>\n");
            p->needs_cert_pass = TRUE;
            continue;
        }
        if (is_file_directive(name) && words[1] && !g_str_equal(words[1], "[inline]")
            && !(g_str_equal(name, "crl-verify") && words[2] && g_str_equal(words[2], "dir"))) {
            g_autofree char *contents = read_referenced(base_dir, words[1], error);
            if (!contents)
                return NULL;
            if (g_str_equal(name, "key")
                && (strstr(contents, "ENCRYPTED PRIVATE KEY") || strstr(contents, "Proc-Type: 4,ENCRYPTED")))
                p->needs_cert_pass = TRUE;
            append_inline(out, name, contents);
            if (g_str_equal(name, "tls-auth") && words[2])
                g_string_append_printf(out, "key-direction %s\n", words[2]);
            continue;
        }
        g_string_append_printf(out, "%s\n", line);
    }

    if (inline_tag) {
        g_set_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    "Unterminated <%s> block in the profile", inline_tag);
        return NULL;
    }
    if (!has_client || !has_remote) {
        g_set_error_literal(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            "Not an OpenVPN client profile (no 'client' or 'remote' directive)");
        return NULL;
    }
    /* The inline credentials block was dropped, keep openvpn3 asking for them. */
    if (has_auth_user_pass && !wrote_auth_user_pass)
        g_string_append(out, "auth-user-pass\n");
    p->needs_user_pass = has_auth_user_pass;

    p->config = g_string_free(g_steal_pointer(&out), FALSE);
    return g_steal_pointer(&p);
}

Openvpn3Profile *
openvpn3_profile_load(const char *path, GError **error)
{
    g_autofree char *text = NULL;
    g_autofree char *dir  = g_path_get_dirname(path);

    if (!g_file_get_contents(path, &text, NULL, error))
        return NULL;
    if (!g_utf8_validate(text, -1, NULL)) {
        g_set_error_literal(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            "The profile is not valid UTF-8 text");
        return NULL;
    }
    return openvpn3_profile_parse(text, dir, error);
}

NMConnection *
openvpn3_connection_from_profile(Openvpn3Profile *p, const char *id)
{
    NMConnection *con     = nm_simple_connection_new();
    NMSetting    *s_con   = nm_setting_connection_new();
    NMSetting    *s_vpn   = nm_setting_vpn_new();
    g_autofree char *uuid = nm_utils_uuid_generate();

    g_object_set(s_con,
                 NM_SETTING_CONNECTION_ID, id,
                 NM_SETTING_CONNECTION_UUID, uuid,
                 NM_SETTING_CONNECTION_TYPE, NM_SETTING_VPN_SETTING_NAME,
                 NULL);
    nm_connection_add_setting(con, s_con);

    g_object_set(s_vpn, NM_SETTING_VPN_SERVICE_TYPE, OPENVPN3_SERVICE_TYPE, NULL);
    openvpn3_setting_set_profile(NM_SETTING_VPN(s_vpn), p->config);
    if (p->username)
        nm_setting_vpn_add_data_item(NM_SETTING_VPN(s_vpn), OPENVPN3_KEY_USERNAME, p->username);
    if (p->needs_user_pass) {
        if (p->password) {
            /* The profile carried the password: keep it with the connection. */
            nm_setting_vpn_add_secret(NM_SETTING_VPN(s_vpn), OPENVPN3_KEY_PASSWORD, p->password);
            nm_setting_set_secret_flags(s_vpn, OPENVPN3_KEY_PASSWORD, NM_SETTING_SECRET_FLAG_NONE, NULL);
        } else {
            nm_setting_set_secret_flags(s_vpn, OPENVPN3_KEY_PASSWORD, NM_SETTING_SECRET_FLAG_AGENT_OWNED, NULL);
        }
        /* One-time codes are asked for on every connect and never stored;
         * secret agents only ask for secrets flagged this way. */
        nm_setting_set_secret_flags(s_vpn, OPENVPN3_KEY_CHALLENGE, NM_SETTING_SECRET_FLAG_NOT_SAVED, NULL);
    }
    if (p->needs_cert_pass)
        nm_setting_set_secret_flags(s_vpn, OPENVPN3_KEY_CERT_PASS, NM_SETTING_SECRET_FLAG_AGENT_OWNED, NULL);
    nm_connection_add_setting(con, s_vpn);

    nm_connection_add_setting(con, nm_setting_ip4_config_new());
    g_object_set(nm_connection_get_setting_ip4_config(con),
                 NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);
    nm_connection_add_setting(con, nm_setting_ip6_config_new());
    g_object_set(nm_connection_get_setting_ip6_config(con),
                 NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO, NULL);
    return con;
}

char *
openvpn3_profile_remote(const char *config)
{
    g_autoptr(GError) error   = NULL;
    g_autoptr(Openvpn3Profile) p = openvpn3_profile_parse(config, "/nonexistent", &error);

    return p ? g_strdup(p->remote) : NULL;
}

char *
openvpn3_setting_get_profile(NMSettingVpn *s_vpn)
{
    const char *b64 = s_vpn ? nm_setting_vpn_get_data_item(s_vpn, OPENVPN3_KEY_PROFILE) : NULL;
    g_autofree guchar *raw = NULL;
    gsize len;

    if (!b64)
        return NULL;
    raw = g_base64_decode(b64, &len);
    if (!raw || !g_utf8_validate((const char *) raw, len, NULL))
        return NULL;
    return g_strndup((const char *) raw, len);
}

void
openvpn3_setting_set_profile(NMSettingVpn *s_vpn, const char *profile)
{
    g_autofree char *b64 = g_base64_encode((const guchar *) profile, strlen(profile));

    nm_setting_vpn_add_data_item(s_vpn, OPENVPN3_KEY_PROFILE, b64);
}
