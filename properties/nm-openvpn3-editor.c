/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Editor page for openvpn3 connections. Built twice: against GTK 4 for
 * GNOME Settings and against GTK 3 for nm-connection-editor.
 */

#include <gtk/gtk.h>
#include <nma-ui-utils.h>
#include <string.h>

#include "ovpn-import.h"

#if GTK_CHECK_VERSION(4, 0, 0)
#define entry_get_text(w)      gtk_editable_get_text(GTK_EDITABLE(w))
#define entry_set_text(w, t)   gtk_editable_set_text(GTK_EDITABLE(w), (t))
#define box_append(b, w)       gtk_box_append(GTK_BOX(b), (w))
#define check_get_active(w)    gtk_check_button_get_active(GTK_CHECK_BUTTON(w))
#define label_set_wrap(l)      gtk_label_set_wrap(GTK_LABEL(l), TRUE)
#else
#define entry_get_text(w)      gtk_entry_get_text(GTK_ENTRY(w))
#define entry_set_text(w, t)   gtk_entry_set_text(GTK_ENTRY(w), (t))
#define box_append(b, w)       gtk_box_pack_start(GTK_BOX(b), (w), gtk_widget_get_hexpand(w), TRUE, 0)
#define check_get_active(w)    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w))
#define label_set_wrap(l)      gtk_label_set_line_wrap(GTK_LABEL(l), TRUE)
#endif

#define OPENVPN3_TYPE_EDITOR (openvpn3_editor_get_type())
G_DECLARE_FINAL_TYPE(Openvpn3Editor, openvpn3_editor, OPENVPN3, EDITOR, GObject)

typedef struct {
    GtkWidget *label;
    GtkWidget *entry;
} Row;

struct _Openvpn3Editor {
    GObject    parent;
    GtkWidget *root;
    GtkWidget *remote_label;
    GtkWidget *status_label;
    Row        username;
    Row        password;
    Row        cert_pass;
    GtkWidget *show_passwords;
    char      *config;
};

static void openvpn3_editor_interface_init(NMVpnEditorInterface *iface);

G_DEFINE_TYPE_WITH_CODE(Openvpn3Editor, openvpn3_editor, G_TYPE_OBJECT,
                        G_IMPLEMENT_INTERFACE(NM_TYPE_VPN_EDITOR, openvpn3_editor_interface_init))

static void
changed(Openvpn3Editor *self)
{
    g_signal_emit_by_name(self, "changed");
}

static void
row_set_visible(Row *row, gboolean visible)
{
    gtk_widget_set_visible(row->label, visible);
    gtk_widget_set_visible(row->entry, visible);
}

/* Shows the fields the loaded profile actually uses. */
static void
refresh_profile(Openvpn3Editor *self)
{
    g_autoptr(GError) error      = NULL;
    g_autoptr(Openvpn3Profile) p = self->config ? openvpn3_profile_parse(self->config, "/nonexistent", &error) : NULL;

    gtk_label_set_text(GTK_LABEL(self->remote_label), p && p->remote ? p->remote : "—");
    gtk_label_set_text(GTK_LABEL(self->status_label),
                       !self->config ? "No profile loaded yet" : p ? "Profile loaded" : error->message);
    row_set_visible(&self->username, !p || p->needs_user_pass);
    row_set_visible(&self->password, !p || p->needs_user_pass);
    row_set_visible(&self->cert_pass, p && p->needs_cert_pass);
}

static void
load_profile(Openvpn3Editor *self, const char *path)
{
    g_autoptr(GError) error      = NULL;
    g_autoptr(Openvpn3Profile) p = openvpn3_profile_load(path, &error);

    if (!p) {
        gtk_label_set_text(GTK_LABEL(self->status_label), error->message);
        return;
    }
    g_free(self->config);
    self->config = g_steal_pointer(&p->config);
    if (p->username)
        entry_set_text(self->username.entry, p->username);
    if (p->password)
        entry_set_text(self->password.entry, p->password);
    refresh_profile(self);
    changed(self);
}

#if GTK_CHECK_VERSION(4, 10, 0)
static void
profile_chosen(GObject *source, GAsyncResult *res, gpointer user_data)
{
    Openvpn3Editor *self    = user_data;
    g_autoptr(GFile) file   = gtk_file_dialog_open_finish(GTK_FILE_DIALOG(source), res, NULL);
    g_autofree char *path   = file ? g_file_get_path(file) : NULL;

    if (path)
        load_profile(self, path);
    g_object_unref(self);
}

static void
choose_profile(GtkButton *button, Openvpn3Editor *self)
{
    g_autoptr(GtkFileDialog) dialog = gtk_file_dialog_new();
    g_autoptr(GtkFileFilter) filter = gtk_file_filter_new();
    g_autoptr(GListStore) filters   = g_list_store_new(GTK_TYPE_FILE_FILTER);

    gtk_file_filter_set_name(filter, "OpenVPN profiles");
    gtk_file_filter_add_pattern(filter, "*.ovpn");
    gtk_file_filter_add_pattern(filter, "*.conf");
    g_list_store_append(filters, filter);
    gtk_file_dialog_set_filters(dialog, G_LIST_MODEL(filters));
    gtk_file_dialog_set_title(dialog, "Choose an OpenVPN profile");
    gtk_file_dialog_open(dialog, GTK_WINDOW(gtk_widget_get_root(GTK_WIDGET(button))), NULL,
                         profile_chosen, g_object_ref(self));
}
#else
static void
choose_profile(GtkButton *button, Openvpn3Editor *self)
{
    GtkWidget *toplevel             = gtk_widget_get_toplevel(GTK_WIDGET(button));
    GtkFileChooserNative *chooser   = gtk_file_chooser_native_new(
        "Choose an OpenVPN profile", GTK_IS_WINDOW(toplevel) ? GTK_WINDOW(toplevel) : NULL,
        GTK_FILE_CHOOSER_ACTION_OPEN, "_Open", "_Cancel");
    GtkFileFilter *filter           = gtk_file_filter_new();

    gtk_file_filter_set_name(filter, "OpenVPN profiles");
    gtk_file_filter_add_pattern(filter, "*.ovpn");
    gtk_file_filter_add_pattern(filter, "*.conf");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(chooser), filter);
    if (gtk_native_dialog_run(GTK_NATIVE_DIALOG(chooser)) == GTK_RESPONSE_ACCEPT) {
        g_autofree char *path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(chooser));
        if (path)
            load_profile(self, path);
    }
    g_object_unref(chooser);
}
#endif

static void
show_passwords_toggled(GtkWidget *check, Openvpn3Editor *self)
{
    gboolean visible = check_get_active(check);

    gtk_entry_set_visibility(GTK_ENTRY(self->password.entry), visible);
    gtk_entry_set_visibility(GTK_ENTRY(self->cert_pass.entry), visible);
}

static void
add_row(Openvpn3Editor *self, GtkGrid *grid, int row, const char *title, GtkWidget *widget, Row *out)
{
    GtkWidget *label = gtk_label_new_with_mnemonic(title);

    gtk_label_set_xalign(GTK_LABEL(label), 1.0);
    gtk_label_set_mnemonic_widget(GTK_LABEL(label), widget);
    gtk_widget_set_hexpand(widget, TRUE);
    gtk_grid_attach(grid, label, 0, row, 1, 1);
    gtk_grid_attach(grid, widget, 1, row, 1, 1);
    if (out) {
        out->label = label;
        out->entry = widget;
    }
}

static GtkWidget *
secret_entry(void)
{
    GtkWidget *entry = gtk_entry_new();

    gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
    gtk_entry_set_input_purpose(GTK_ENTRY(entry), GTK_INPUT_PURPOSE_PASSWORD);
    return entry;
}

static void
setup_secret(Row *row, NMSettingVpn *s_vpn, const char *key, NMSettingSecretFlags default_flags)
{
    g_autofree char *flags_key = g_strdup_printf("%s-flags", key);
    NMSettingSecretFlags flags = default_flags;
    gboolean has_flags         = s_vpn && nm_setting_vpn_get_data_item(s_vpn, flags_key);
    const char *value;

    if (s_vpn && (value = nm_setting_vpn_get_secret(s_vpn, key))) {
        entry_set_text(row->entry, value);
        flags = NM_SETTING_SECRET_FLAG_NONE; /* a stored secret without flags */
    }
    if (has_flags)
        nm_setting_get_secret_flags(NM_SETTING(s_vpn), key, &flags, NULL);
    /* libnma reads the flags from the setting when given one, which would
     * turn missing flags into NONE; then only the initial flags count. */
    nma_utils_setup_password_storage(row->entry, flags, has_flags ? NM_SETTING(s_vpn) : NULL, key, TRUE, FALSE);
}

static void
build_ui(Openvpn3Editor *self, NMConnection *connection)
{
    NMSettingVpn *s_vpn = nm_connection_get_setting_vpn(connection);
    GtkWidget *grid     = gtk_grid_new();
    GtkWidget *button   = gtk_button_new_with_mnemonic("_Load from file…");
    GtkWidget *profile  = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    const char *value;
    Row profile_row;

    gtk_grid_set_row_spacing(GTK_GRID(grid), 12);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 12);
    gtk_widget_set_margin_top(grid, 12);
    gtk_widget_set_margin_bottom(grid, 12);
    gtk_widget_set_margin_start(grid, 12);
    gtk_widget_set_margin_end(grid, 12);

    self->status_label = gtk_label_new(NULL);
    gtk_label_set_xalign(GTK_LABEL(self->status_label), 0.0);
    label_set_wrap(self->status_label);
    gtk_widget_set_hexpand(self->status_label, TRUE);
    box_append(profile, self->status_label);
    box_append(profile, button);
    g_signal_connect(button, "clicked", G_CALLBACK(choose_profile), self);
    add_row(self, GTK_GRID(grid), 0, "_Profile", profile, &profile_row);
    gtk_label_set_mnemonic_widget(GTK_LABEL(profile_row.label), button);

    self->remote_label = gtk_label_new(NULL);
    gtk_label_set_xalign(GTK_LABEL(self->remote_label), 0.0);
    gtk_label_set_selectable(GTK_LABEL(self->remote_label), TRUE);
    add_row(self, GTK_GRID(grid), 1, "Server", self->remote_label, NULL);

    add_row(self, GTK_GRID(grid), 2, "_Username", gtk_entry_new(), &self->username);
    add_row(self, GTK_GRID(grid), 3, "Pass_word", secret_entry(), &self->password);
    add_row(self, GTK_GRID(grid), 4, "Private _key passphrase", secret_entry(), &self->cert_pass);
    self->show_passwords = gtk_check_button_new_with_mnemonic("Sho_w passwords");
    gtk_grid_attach(GTK_GRID(grid), self->show_passwords, 1, 5, 1, 1);
    g_signal_connect(self->show_passwords, "toggled", G_CALLBACK(show_passwords_toggled), self);

    if (s_vpn) {
        self->config = openvpn3_setting_get_profile(s_vpn);
        if ((value = nm_setting_vpn_get_data_item(s_vpn, OPENVPN3_KEY_USERNAME)))
            entry_set_text(self->username.entry, value);
    }
    setup_secret(&self->password, s_vpn, OPENVPN3_KEY_PASSWORD, NM_SETTING_SECRET_FLAG_AGENT_OWNED);
    setup_secret(&self->cert_pass, s_vpn, OPENVPN3_KEY_CERT_PASS, NM_SETTING_SECRET_FLAG_AGENT_OWNED);

    g_signal_connect_swapped(self->username.entry, "changed", G_CALLBACK(changed), self);
    g_signal_connect_swapped(self->password.entry, "changed", G_CALLBACK(changed), self);
    g_signal_connect_swapped(self->cert_pass.entry, "changed", G_CALLBACK(changed), self);

#if !GTK_CHECK_VERSION(4, 0, 0)
    gtk_widget_show_all(grid);
#endif
    refresh_profile(self);
    self->root = g_object_ref_sink(grid);
}

static GObject *
get_widget(NMVpnEditor *editor)
{
    return G_OBJECT(OPENVPN3_EDITOR(editor)->root);
}

static void
save_secret(Row *row, NMSettingVpn *s_vpn, const char *key)
{
    NMSettingSecretFlags flags = nma_utils_menu_to_secret_flags(row->entry);
    const char *value          = entry_get_text(row->entry);

    nma_utils_update_password_storage(row->entry, flags, NM_SETTING(s_vpn), key);
    nm_setting_set_secret_flags(NM_SETTING(s_vpn), key, flags, NULL);
    if (value && *value && !(flags & NM_SETTING_SECRET_FLAG_NOT_SAVED))
        nm_setting_vpn_add_secret(s_vpn, key, value);
}

static gboolean
update_connection(NMVpnEditor *editor, NMConnection *connection, GError **error)
{
    Openvpn3Editor *self = OPENVPN3_EDITOR(editor);
    g_autoptr(Openvpn3Profile) p = NULL;
    NMSettingVpn *s_vpn;
    const char *username;

    if (!self->config) {
        g_set_error_literal(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY,
                            OPENVPN3_KEY_PROFILE);
        return FALSE;
    }
    p = openvpn3_profile_parse(self->config, "/nonexistent", error);
    if (!p)
        return FALSE;

    s_vpn = NM_SETTING_VPN(nm_setting_vpn_new());
    g_object_set(s_vpn, NM_SETTING_VPN_SERVICE_TYPE, OPENVPN3_SERVICE_TYPE, NULL);
    openvpn3_setting_set_profile(s_vpn, self->config);

    if (p->needs_user_pass) {
        username = entry_get_text(self->username.entry);
        if (username && *username)
            nm_setting_vpn_add_data_item(s_vpn, OPENVPN3_KEY_USERNAME, username);
        save_secret(&self->password, s_vpn, OPENVPN3_KEY_PASSWORD);
        nm_setting_set_secret_flags(NM_SETTING(s_vpn), OPENVPN3_KEY_CHALLENGE,
                                    NM_SETTING_SECRET_FLAG_NOT_SAVED, NULL);
    }
    if (p->needs_cert_pass)
        save_secret(&self->cert_pass, s_vpn, OPENVPN3_KEY_CERT_PASS);

    nm_connection_add_setting(connection, NM_SETTING(s_vpn));
    return TRUE;
}

static void
openvpn3_editor_init(Openvpn3Editor *self)
{
}

static void
dispose(GObject *object)
{
    Openvpn3Editor *self = OPENVPN3_EDITOR(object);

    g_clear_object(&self->root);
    g_clear_pointer(&self->config, g_free);
    G_OBJECT_CLASS(openvpn3_editor_parent_class)->dispose(object);
}

static void
openvpn3_editor_class_init(Openvpn3EditorClass *klass)
{
    G_OBJECT_CLASS(klass)->dispose = dispose;
}

static void
openvpn3_editor_interface_init(NMVpnEditorInterface *iface)
{
    iface->get_widget        = get_widget;
    iface->update_connection = update_connection;
}

G_MODULE_EXPORT NMVpnEditor *
nm_vpn_editor_factory_openvpn3(NMVpnEditorPlugin *plugin, NMConnection *connection, GError **error)
{
    Openvpn3Editor *self = g_object_new(OPENVPN3_TYPE_EDITOR, NULL);

    build_ui(self, connection);
    return NM_VPN_EDITOR(self);
}
