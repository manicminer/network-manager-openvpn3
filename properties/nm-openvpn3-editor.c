/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * GTK 4 editor page for openvpn3 connections, shown by GNOME Settings.
 */

#include <gtk/gtk.h>
#include <nma-ui-utils.h>
#include <string.h>

#include "ovpn-import.h"

#define OPENVPN3_TYPE_EDITOR (openvpn3_editor_get_type())
G_DECLARE_FINAL_TYPE(Openvpn3Editor, openvpn3_editor, OPENVPN3, EDITOR, GObject)

struct _Openvpn3Editor {
    GObject    parent;
    GtkWidget *root;
    GtkWidget *remote_label;
    GtkWidget *status_label;
    GtkWidget *username;
    GtkWidget *password;
    GtkWidget *show_password;
    char      *config;
    gboolean   new_connection;
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
refresh_profile_labels(Openvpn3Editor *self)
{
    g_autofree char *remote = self->config ? openvpn3_profile_remote(self->config) : NULL;

    gtk_label_set_text(GTK_LABEL(self->remote_label), remote ? remote : "—");
    gtk_label_set_text(GTK_LABEL(self->status_label),
                       self->config ? "Profile loaded" : "No profile loaded yet");
}

static void
profile_chosen(GObject *source, GAsyncResult *res, gpointer user_data)
{
    Openvpn3Editor *self         = user_data;
    g_autoptr(GError) error      = NULL;
    g_autoptr(GFile) file        = gtk_file_dialog_open_finish(GTK_FILE_DIALOG(source), res, &error);
    g_autoptr(Openvpn3Profile) p = NULL;
    g_autofree char *path        = NULL;

    if (!file) {
        g_object_unref(self);
        return; /* cancelled */
    }
    path = g_file_get_path(file);
    p    = path ? openvpn3_profile_load(path, &error) : NULL;
    if (!p) {
        gtk_label_set_text(GTK_LABEL(self->status_label), error ? error->message : "Cannot read the file");
        g_object_unref(self);
        return;
    }
    g_free(self->config);
    self->config = g_steal_pointer(&p->config);
    if (p->username)
        gtk_editable_set_text(GTK_EDITABLE(self->username), p->username);
    if (p->password)
        gtk_editable_set_text(GTK_EDITABLE(self->password), p->password);
    refresh_profile_labels(self);
    changed(self);
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

static void
show_password_toggled(GtkCheckButton *check, Openvpn3Editor *self)
{
    gtk_entry_set_visibility(GTK_ENTRY(self->password), gtk_check_button_get_active(check));
}

static GtkWidget *
add_row(GtkGrid *grid, int row, const char *title, GtkWidget *widget)
{
    GtkWidget *label = gtk_label_new_with_mnemonic(title);

    gtk_label_set_xalign(GTK_LABEL(label), 1.0);
    gtk_label_set_mnemonic_widget(GTK_LABEL(label), widget);
    gtk_widget_set_hexpand(widget, TRUE);
    gtk_grid_attach(grid, label, 0, row, 1, 1);
    gtk_grid_attach(grid, widget, 1, row, 1, 1);
    return widget;
}

static void
build_ui(Openvpn3Editor *self, NMConnection *connection)
{
    NMSettingVpn *s_vpn = nm_connection_get_setting_vpn(connection);
    NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_AGENT_OWNED;
    GtkWidget *grid     = gtk_grid_new();
    GtkWidget *button   = gtk_button_new_with_mnemonic("_Load from file…");
    GtkWidget *profile  = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    const char *value;

    gtk_grid_set_row_spacing(GTK_GRID(grid), 12);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 12);
    gtk_widget_set_margin_top(grid, 12);
    gtk_widget_set_margin_bottom(grid, 12);
    gtk_widget_set_margin_start(grid, 12);
    gtk_widget_set_margin_end(grid, 12);

    self->status_label = gtk_label_new(NULL);
    gtk_label_set_xalign(GTK_LABEL(self->status_label), 0.0);
    gtk_label_set_wrap(GTK_LABEL(self->status_label), TRUE);
    gtk_widget_set_hexpand(self->status_label, TRUE);
    gtk_box_append(GTK_BOX(profile), self->status_label);
    gtk_box_append(GTK_BOX(profile), button);
    g_signal_connect(button, "clicked", G_CALLBACK(choose_profile), self);
    add_row(GTK_GRID(grid), 0, "_Profile", profile);
    gtk_label_set_mnemonic_widget(GTK_LABEL(gtk_grid_get_child_at(GTK_GRID(grid), 0, 0)), button);

    self->remote_label = gtk_label_new(NULL);
    gtk_label_set_xalign(GTK_LABEL(self->remote_label), 0.0);
    gtk_label_set_selectable(GTK_LABEL(self->remote_label), TRUE);
    add_row(GTK_GRID(grid), 1, "Server", self->remote_label);

    self->username = add_row(GTK_GRID(grid), 2, "_Username", gtk_entry_new());
    self->password = add_row(GTK_GRID(grid), 3, "Pass_word", gtk_entry_new());
    gtk_entry_set_visibility(GTK_ENTRY(self->password), FALSE);
    gtk_entry_set_input_purpose(GTK_ENTRY(self->password), GTK_INPUT_PURPOSE_PASSWORD);
    self->show_password = gtk_check_button_new_with_mnemonic("Sho_w password");
    gtk_grid_attach(GTK_GRID(grid), self->show_password, 1, 4, 1, 1);
    g_signal_connect(self->show_password, "toggled", G_CALLBACK(show_password_toggled), self);

    if (s_vpn) {
        self->config = openvpn3_setting_get_profile(s_vpn);
        if ((value = nm_setting_vpn_get_data_item(s_vpn, OPENVPN3_KEY_USERNAME)))
            gtk_editable_set_text(GTK_EDITABLE(self->username), value);
        if ((value = nm_setting_vpn_get_secret(s_vpn, OPENVPN3_KEY_PASSWORD)))
            gtk_editable_set_text(GTK_EDITABLE(self->password), value);
        nm_setting_get_secret_flags(NM_SETTING(s_vpn), OPENVPN3_KEY_PASSWORD, &flags, NULL);
    }
    nma_utils_setup_password_storage(self->password, flags, s_vpn ? NM_SETTING(s_vpn) : NULL,
                                     OPENVPN3_KEY_PASSWORD, TRUE, FALSE);
    refresh_profile_labels(self);

    g_signal_connect_swapped(self->username, "changed", G_CALLBACK(changed), self);
    g_signal_connect_swapped(self->password, "changed", G_CALLBACK(changed), self);

    self->root = g_object_ref_sink(grid);
}

static GObject *
get_widget(NMVpnEditor *editor)
{
    return G_OBJECT(OPENVPN3_EDITOR(editor)->root);
}

static gboolean
update_connection(NMVpnEditor *editor, NMConnection *connection, GError **error)
{
    Openvpn3Editor *self = OPENVPN3_EDITOR(editor);
    NMSettingVpn *s_vpn;
    NMSettingSecretFlags flags;
    const char *username, *password;

    if (!self->config) {
        g_set_error_literal(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY,
                            OPENVPN3_KEY_PROFILE);
        return FALSE;
    }
    s_vpn = NM_SETTING_VPN(nm_setting_vpn_new());
    g_object_set(s_vpn, NM_SETTING_VPN_SERVICE_TYPE, OPENVPN3_SERVICE_TYPE, NULL);
    openvpn3_setting_set_profile(s_vpn, self->config);

    username = gtk_editable_get_text(GTK_EDITABLE(self->username));
    if (username && *username)
        nm_setting_vpn_add_data_item(s_vpn, OPENVPN3_KEY_USERNAME, username);

    flags    = nma_utils_menu_to_secret_flags(self->password);
    password = gtk_editable_get_text(GTK_EDITABLE(self->password));
    nma_utils_update_password_storage(self->password, flags, NM_SETTING(s_vpn), OPENVPN3_KEY_PASSWORD);
    nm_setting_set_secret_flags(NM_SETTING(s_vpn), OPENVPN3_KEY_PASSWORD, flags, NULL);
    if (password && *password && !(flags & NM_SETTING_SECRET_FLAG_NOT_SAVED))
        nm_setting_vpn_add_secret(s_vpn, OPENVPN3_KEY_PASSWORD, password);

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
