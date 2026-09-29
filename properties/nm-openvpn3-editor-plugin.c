/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * libnm VPN editor plugin for openvpn3: import/export of profiles, loads the
 * GTK 4 editor on demand so that the plugin itself does not link GTK.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <gio/gio.h>
#include <string.h>

#include "ovpn-import.h"

#define EDITOR_LIBRARY "libnm-gtk4-vpn-plugin-openvpn3-editor.so"
#define EDITOR_FACTORY "nm_vpn_editor_factory_openvpn3"

typedef NMVpnEditor *(*EditorFactory)(NMVpnEditorPlugin *plugin, NMConnection *connection, GError **error);

enum { PROP_0, PROP_NAME, PROP_DESC, PROP_SERVICE };

#define OPENVPN3_TYPE_EDITOR_PLUGIN (openvpn3_editor_plugin_get_type())
G_DECLARE_FINAL_TYPE(Openvpn3EditorPlugin, openvpn3_editor_plugin, OPENVPN3, EDITOR_PLUGIN, GObject)

struct _Openvpn3EditorPlugin {
    GObject parent;
};

static void openvpn3_editor_plugin_interface_init(NMVpnEditorPluginInterface *iface);

G_DEFINE_TYPE_WITH_CODE(Openvpn3EditorPlugin, openvpn3_editor_plugin, G_TYPE_OBJECT,
                        G_IMPLEMENT_INTERFACE(NM_TYPE_VPN_EDITOR_PLUGIN, openvpn3_editor_plugin_interface_init))

static NMConnection *
import_from_file(NMVpnEditorPlugin *plugin, const char *path, GError **error)
{
    g_autoptr(Openvpn3Profile) p = NULL;
    g_autofree char *base        = NULL;
    char *dot;

    if (!g_str_has_suffix(path, ".ovpn") && !g_str_has_suffix(path, ".conf")) {
        g_set_error_literal(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
                            "Not an OpenVPN profile (expected .ovpn or .conf)");
        return NULL;
    }
    p = openvpn3_profile_load(path, error);
    if (!p)
        return NULL;
    base = g_path_get_basename(path);
    dot  = strrchr(base, '.');
    if (dot)
        *dot = '\0';
    return openvpn3_connection_from_profile(p, base);
}

static gboolean
export_to_file(NMVpnEditorPlugin *plugin, const char *path, NMConnection *connection, GError **error)
{
    g_autofree char *config = openvpn3_setting_get_profile(nm_connection_get_setting_vpn(connection));

    if (!config) {
        g_set_error_literal(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY,
                            "The connection has no OpenVPN profile");
        return FALSE;
    }
    /* Credentials stay in NetworkManager, the exported profile asks for them. */
    return g_file_set_contents(path, config, -1, error);
}

static char *
get_suggested_filename(NMVpnEditorPlugin *plugin, NMConnection *connection)
{
    const char *id = nm_connection_get_id(connection);

    return g_strdup_printf("%s.ovpn", id ? id : "openvpn3");
}

static NMVpnEditorPluginCapability
get_capabilities(NMVpnEditorPlugin *plugin)
{
    return NM_VPN_EDITOR_PLUGIN_CAPABILITY_IMPORT | NM_VPN_EDITOR_PLUGIN_CAPABILITY_EXPORT
           | NM_VPN_EDITOR_PLUGIN_CAPABILITY_IPV6;
}

static char *
editor_path(void)
{
    Dl_info info;
    g_autofree char *dir = NULL;

    if (!dladdr((void *) get_capabilities, &info) || !info.dli_fname)
        return g_strdup(EDITOR_LIBRARY);
    dir = g_path_get_dirname(info.dli_fname);
    return g_build_filename(dir, EDITOR_LIBRARY, NULL);
}

static NMVpnEditor *
get_editor(NMVpnEditorPlugin *plugin, NMConnection *connection, GError **error)
{
    static EditorFactory factory;

    if (!factory) {
        g_autofree char *path = NULL;
        void *handle;

        /* Only GTK 4 hosts are supported; loading a GTK 4 library into a
         * GTK 3 process would abort it. */
        if (!dlsym(RTLD_DEFAULT, "gtk_widget_get_first_child")) {
            g_set_error_literal(error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_FAILED,
                                "The openvpn3 editor requires a GTK 4 application");
            return NULL;
        }
        path   = editor_path();
        handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
        if (!handle) {
            g_set_error(error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_FAILED,
                        "Cannot load the openvpn3 editor: %s", dlerror());
            return NULL;
        }
        factory = (EditorFactory) dlsym(handle, EDITOR_FACTORY);
        if (!factory) {
            g_set_error(error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_FAILED,
                        "Invalid openvpn3 editor library %s", path);
            dlclose(handle);
            return NULL;
        }
    }
    return factory(plugin, connection, error);
}

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    switch (prop_id) {
    case PROP_NAME:
        g_value_set_string(value, "OpenVPN 3");
        break;
    case PROP_DESC:
        g_value_set_string(value, "Compatible with OpenVPN servers, using the OpenVPN 3 Linux client.");
        break;
    case PROP_SERVICE:
        g_value_set_string(value, OPENVPN3_SERVICE_TYPE);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
    }
}

static void
openvpn3_editor_plugin_init(Openvpn3EditorPlugin *plugin)
{
}

static void
openvpn3_editor_plugin_class_init(Openvpn3EditorPluginClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);

    object_class->get_property = get_property;
    g_object_class_override_property(object_class, PROP_NAME, NM_VPN_EDITOR_PLUGIN_NAME);
    g_object_class_override_property(object_class, PROP_DESC, NM_VPN_EDITOR_PLUGIN_DESCRIPTION);
    g_object_class_override_property(object_class, PROP_SERVICE, NM_VPN_EDITOR_PLUGIN_SERVICE);
}

static void
openvpn3_editor_plugin_interface_init(NMVpnEditorPluginInterface *iface)
{
    iface->get_editor             = get_editor;
    iface->get_capabilities       = get_capabilities;
    iface->import_from_file       = import_from_file;
    iface->export_to_file         = export_to_file;
    iface->get_suggested_filename = get_suggested_filename;
}

G_MODULE_EXPORT NMVpnEditorPlugin *
nm_vpn_editor_plugin_factory(GError **error)
{
    g_return_val_if_fail(!error || !*error, NULL);
    return g_object_new(OPENVPN3_TYPE_EDITOR_PLUGIN, NULL);
}
