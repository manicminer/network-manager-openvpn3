/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Import of OpenVPN profiles.
 *
 * openvpn3 needs a self-contained profile, so every file referenced by the
 * profile is inlined.  Credentials are taken out of the profile and stored
 * in the connection instead: the username as data, the password as secret.
 *
 * Normalizing means inlining files, moving credentials out and dropping
 * comments, nothing else: directive order, repeated directives, blank lines,
 * quoting and directives this code has never heard of all come out the way
 * they went in.  There is no list of allowed directives anywhere.
 *
 * Comments go because openvpn3 ignores them and the profile inside a
 * connection is not a file anybody opens in an editor any more: a client that
 * shows it as a table of entries would only have rows nothing can act on.
 * See comment_start() for which '#' and ';' count as one.
 */

#include "ovpn-import.h"

#include <string.h>

static const char *const file_directives[] = {
    "ca", "cert", "key", "extra-certs", "tls-auth", "tls-crypt", "tls-crypt-v2", "crl-verify", NULL,
};

/* <connection> holds options, not a payload: a client config may well keep
 * its only remote -- and the files that remote needs -- inside one or more of
 * these.  Its lines are therefore directives, and the ones naming a file are
 * inlined where they stand, so the profile stays self-contained.
 *
 * Everything else in angle brackets (<ca>, <key>, <pkcs12>, <tls-auth> ...)
 * is opaque content whose lines are copied out verbatim, nested in a
 * <connection> or not.  Keep this in step with OPTION_SCOPES in
 * src/nm_openvpn3/ovpn.py. */
static const char *const option_scopes[] = {"connection", NULL};

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

/* Where the comment on a directive line starts, or -1 if it has none.
 *
 * The two OpenVPN lexers do not agree on this, so what is removed is what
 * both of them read as a comment:
 *
 *  - OpenVPN 2 (parse_line(), src/openvpn/options_parse.c) only looks for a
 *    '#' or ';' in STATE_INITIAL, that is at the start of a parameter, and
 *    not inside quotes.  "a#b" is the literal value a#b.
 *  - openvpn3 (OptionList::LexComment, openvpn/common/options.hpp) looks
 *    anywhere outside quotes, but lets a backslash escape the character:
 *    "a#b" is the value "a", and "\#" is a literal '#'.
 *
 * So a '#' or ';' is a comment here only when it is unquoted, unescaped and
 * starts a word.  Where the two disagree -- a character glued to the middle
 * of a word, an escaped one -- the line is left alone: openvpn3 is the one
 * that reads the stored profile, and it already ignores whatever it considers
 * a comment, so keeping those characters cannot change what the option means
 * while truncating them could.
 *
 * "Unquoted" has to satisfy both of them as well, and the two do not even
 * agree on where a quote ends: a backslash inside single quotes is a literal
 * character for OpenVPN 2 (parse_line() skips its escape handling in
 * STATE_READING_SQUOTED_PARM), so the apostrophe after it closes the quote,
 * while openvpn3 lets it escape that apostrophe and stays inside.  Both quote
 * states are therefore tracked, and a character counts as unquoted only when
 * neither lexer has it in a quote.  That keeps "setenv a 'x\' # literal'"
 * whole, which is the value openvpn3 reads.
 */
static gssize
comment_start(const char *line)
{
    gboolean ov2_squote = FALSE, ov2_dquote = FALSE, ov2_escaped = FALSE;
    gboolean ov3_squote = FALSE, ov3_dquote = FALSE, ov3_escaped = FALSE;
    gboolean word_start = TRUE;
    const char *s;

    for (s = line; *s; s++) {
        const gboolean quoted  = ov2_squote || ov2_dquote || ov3_squote || ov3_dquote;
        const gboolean escaped = ov2_escaped || ov3_escaped;

        if (word_start && !quoted && !escaped && (*s == '#' || *s == ';'))
            return s - line;

        /* OpenVPN 2: a backslash is not an escape inside single quotes. */
        if (ov2_escaped)
            ov2_escaped = FALSE;
        else if (*s == '\\' && !ov2_squote)
            ov2_escaped = TRUE;
        else if (*s == '"' && !ov2_squote)
            ov2_dquote = !ov2_dquote;
        else if (*s == '\'' && !ov2_dquote)
            ov2_squote = !ov2_squote;

        /* openvpn3: a backslash escapes everywhere, quotes included. */
        if (ov3_escaped)
            ov3_escaped = FALSE;
        else if (*s == '\\')
            ov3_escaped = TRUE;
        else if (*s == '"' && !ov3_squote)
            ov3_dquote = !ov3_dquote;
        else if (*s == '\'' && !ov3_dquote)
            ov3_squote = !ov3_squote;

        /* Only unquoted, unescaped whitespace starts the next word. */
        word_start = !quoted && !escaped && g_ascii_isspace(*s);
    }
    return -1;
}

/* Cuts the trailing whitespace a removed comment was separated by, and no
 * more: backslash-escaped whitespace is part of the value in front of it for
 * both lexers ("setenv a value\  # c" is the value "value "), so only the
 * unescaped run at the end goes.  An even number of backslashes before it are
 * escaped backslashes and leave the whitespace a separator again. */
static void
chomp_separators(char *line)
{
    gsize len = strlen(line);

    while (len > 0 && g_ascii_isspace(line[len - 1])) {
        gsize backslashes = 0;

        while (backslashes < len - 1 && line[len - 2 - backslashes] == '\\')
            backslashes++;
        if (backslashes % 2)
            break;
        len--;
    }
    line[len] = '\0';
}

/* A directive line as the lexers see it: the leading separators and the CRLF
 * terminator go, and so does the trailing separator run -- but not whitespace
 * a backslash escaped, which is part of the value in front of it.
 *
 * This is the trimming every line goes through before anything looks at it,
 * so it is also where an escaped trailing space written out by an earlier
 * normalization has to survive: the stored profile is parsed again on export,
 * on reimport and whenever the editor hands one back for inlining, and a
 * plain strip would turn "setenv a value\ " into a bare backslash before the
 * newline on the very next pass. */
static char *
strip_separators(char *line)
{
    gsize len;

    g_strchug(line);
    len = strlen(line);
    /* The line terminator is not part of the line, escaped or not. */
    if (len > 0 && line[len - 1] == '\r')
        line[--len] = '\0';
    chomp_separators(line);
    return line;
}

/* "</tag>" on a line of its own, the only thing openvpn3 closes a block
 * with. */
static gboolean
is_closing_tag(const char *line)
{
    return strlen(line) > 3 && line[0] == '<' && line[1] == '/' && g_str_has_suffix(line, ">");
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

static gboolean
is_option_scope(const char *tag)
{
    return g_strv_contains(option_scopes, tag);
}

/* "<tag>" -> tag, for an opening tag on a line of its own; else NULL. */
static char *
opening_tag(const char *line)
{
    if (line[0] != '<' || line[1] == '/' || !line[1] || !g_str_has_suffix(line, ">"))
        return NULL;
    return g_strndup(line + 1, strlen(line) - 2);
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
    g_autofree char *scope       = NULL;
    gboolean has_auth_user_pass  = FALSE;
    gboolean wrote_auth_user_pass = FALSE;
    gboolean has_client          = FALSE;
    gboolean has_remote          = FALSE;

    for (char **l = lines; *l; l++) {
        g_autofree char *line = strip_separators(g_strdup(*l));
        g_auto(GStrv) words   = NULL;
        const char *name;

        /* The empty piece after the final newline is not a line. */
        if (!l[1] && !**l)
            break;
        /* Tolerate CRLF files: strip_separators removed the \r above. */
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
        /* The option scope we are in ends here.  Matched before the comment
         * is taken off, because openvpn3 matches every closing tag against
         * the raw line: "</connection> # done" leaves the block open for it,
         * so it has to leave it open here too rather than let this import
         * store a profile openvpn3 will refuse.  The closing tag of an
         * opaque <tag> is matched the same way, in the block above. */
        if (scope) {
            g_autofree char *end = g_strdup_printf("</%s>", scope);

            if (g_str_equal(line, end)) {
                g_clear_pointer(&scope, g_free);
                g_string_append_printf(out, "%s\n", line);
                continue;
            }
        }
        /* Everything left is a directive, so a comment on it is a comment --
         * and a line that is nothing but one goes away entirely.  A blank
         * line is not a comment and stays.  The lines of an inline <tag> are
         * payload and were handled above without ever coming here. */
        {
            gssize cut = comment_start(line);

            if (cut >= 0) {
                char *kept = g_strndup(line, cut);

                chomp_separators(kept);
                /* Cutting a comment must not turn a line into a closing tag
                 * the raw line was not one: openvpn3 matches every closing
                 * tag against the raw line, so "</connection> # x" is no
                 * boundary for it even when a real closer follows below.
                 * Emitting the cut line would invent one there, push every
                 * directive up to the real closer out of the scope and leave
                 * the profile with a closing tag too many.  Such a line is
                 * passed through exactly as it came instead -- the comment
                 * stays, and openvpn3 ignores it where it stands. */
                if (is_closing_tag(kept)) {
                    g_free(kept);
                } else if (!*kept) {
                    g_free(kept);
                    continue;
                } else {
                    g_free(line);
                    line = kept;
                }
            }
        }
        {
            g_autofree char *tag = opening_tag(line);

            if (tag && is_option_scope(tag)) {
                g_free(scope);
                scope = g_steal_pointer(&tag);
                g_string_append_printf(out, "%s\n", line);
                continue;
            }
            if (tag) {
                inline_tag = g_steal_pointer(&tag);
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

    if (inline_tag || scope) {
        g_set_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    "Unterminated <%s> block in the profile", inline_tag ?: scope);
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

const char *
openvpn3_setting_profile_storage(NMSettingVpn *s_vpn)
{
    const char *mode = s_vpn ? nm_setting_vpn_get_data_item(s_vpn, OPENVPN3_KEY_PROFILE_STORAGE) : NULL;

    return (mode && *mode) ? mode : NULL;
}

gboolean
openvpn3_setting_profile_is_secret(NMSettingVpn *s_vpn)
{
    const char *mode = openvpn3_setting_profile_storage(s_vpn);

    return mode && g_str_equal(mode, OPENVPN3_PROFILE_STORAGE_SECRET);
}

gboolean
openvpn3_setting_profile_storage_is_unsupported(NMSettingVpn *s_vpn)
{
    const char *mode = openvpn3_setting_profile_storage(s_vpn);

    return mode && !g_str_equal(mode, OPENVPN3_PROFILE_STORAGE_SECRET);
}

char *
openvpn3_setting_unsupported_storage_message(NMSettingVpn *s_vpn)
{
    return g_strdup_printf("This connection stores its OpenVPN profile as \"%s\", a layout "
                           "this version does not know. Its %s data item belongs to the "
                           "layout the connection used before, so it is not read. Update "
                           "network-manager-openvpn3.",
                           openvpn3_setting_profile_storage(s_vpn), OPENVPN3_KEY_PROFILE);
}

gboolean
openvpn3_setting_profile_flags(NMSettingVpn *s_vpn, NMSettingSecretFlags *out_flags)
{
    const char *value;
    char       *end;
    gint64      number;

    if (!openvpn3_setting_profile_is_secret(s_vpn)) {
        *out_flags = NM_SETTING_SECRET_FLAG_NONE;
        return TRUE;
    }
    value = nm_setting_vpn_get_data_item(s_vpn, OPENVPN3_KEY_PROFILE_FLAGS);
    /* No flags means NM_SETTING_SECRET_FLAG_NONE to NetworkManager, i.e. a
     * system-owned secret.  Reading it as agent-owned would move the profile
     * of an unattended connection into a user's wallet behind their back. */
    if (!value) {
        *out_flags = NM_SETTING_SECRET_FLAG_NONE;
        return TRUE;
    }
    /* Parsed here rather than through nm_setting_get_secret_flags(): what a
     * value outside the enum turns into there is not something to rely on,
     * and every one of them has to be refused anyway. */
    number = g_ascii_strtoll(value, &end, 10);
    if (end == value || *end)
        return FALSE;
    if (number != NM_SETTING_SECRET_FLAG_NONE && number != NM_SETTING_SECRET_FLAG_AGENT_OWNED)
        return FALSE;
    *out_flags = (NMSettingSecretFlags) number;
    return TRUE;
}

char *
openvpn3_setting_get_profile(NMSettingVpn *s_vpn)
{
    const char *b64;
    g_autofree guchar *raw = NULL;
    gsize len;

    if (!s_vpn)
        return NULL;
    /* A layout this build does not know: the data item that goes with it is a
     * leftover of whatever the connection used before, so reading it would
     * hand out a stale profile.  Nothing is better than something wrong. */
    if (openvpn3_setting_profile_storage_is_unsupported(s_vpn))
        return NULL;
    b64 = openvpn3_setting_profile_is_secret(s_vpn)
              ? nm_setting_vpn_get_secret(s_vpn, OPENVPN3_KEY_PROFILE)
              : nm_setting_vpn_get_data_item(s_vpn, OPENVPN3_KEY_PROFILE);
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

    nm_setting_vpn_remove_secret(s_vpn, OPENVPN3_KEY_PROFILE);
    nm_setting_vpn_remove_data_item(s_vpn, OPENVPN3_KEY_PROFILE_STORAGE);
    nm_setting_vpn_remove_data_item(s_vpn, OPENVPN3_KEY_PROFILE_FLAGS);
    nm_setting_vpn_add_data_item(s_vpn, OPENVPN3_KEY_PROFILE, b64);
}

gboolean
openvpn3_setting_set_profile_secret(NMSettingVpn        *s_vpn,
                                    const char          *profile,
                                    NMSettingSecretFlags flags,
                                    GError             **error)
{
    g_autofree char *b64 = NULL;

    /* Checked before anything is written: a caller that gets this wrong must
     * end up with the connection it was given, not with one whose profile has
     * been dropped on the way. */
    if (flags != NM_SETTING_SECRET_FLAG_NONE && flags != NM_SETTING_SECRET_FLAG_AGENT_OWNED) {
        g_set_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    "An OpenVPN profile cannot be stored with %s=%d: nothing would ever "
                    "hand it back, so the connection could not be used.",
                    OPENVPN3_KEY_PROFILE_FLAGS, (int) flags);
        return FALSE;
    }
    b64 = g_base64_encode((const guchar *) profile, strlen(profile));

    /* No duplicate public copy: it would outlive the secret and be used stale. */
    nm_setting_vpn_remove_data_item(s_vpn, OPENVPN3_KEY_PROFILE);
    nm_setting_vpn_add_data_item(s_vpn, OPENVPN3_KEY_PROFILE_STORAGE, OPENVPN3_PROFILE_STORAGE_SECRET);
    nm_setting_set_secret_flags(NM_SETTING(s_vpn), OPENVPN3_KEY_PROFILE, flags, NULL);
    nm_setting_vpn_add_secret(s_vpn, OPENVPN3_KEY_PROFILE, b64);
    return TRUE;
}
