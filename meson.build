# SPDX-License-Identifier: GPL-2.0-or-later
project('network-manager-openvpn3', 'c',
  version: '0.1.0',
  license: 'GPL-2.0-or-later',
  meson_version: '>= 1.0',
  default_options: ['c_std=gnu11', 'warning_level=2'])

prefix = get_option('prefix')
libexecdir = prefix / get_option('libexecdir')
plugindir = prefix / get_option('libdir') / 'NetworkManager'
pkgdatadir = prefix / get_option('datadir') / meson.project_name()

add_project_arguments('-Wno-unused-parameter', '-Wno-missing-field-initializers', language: 'c')

libnm = dependency('libnm', version: '>= 1.42')
gmodule = dependency('gmodule-2.0')
dl = meson.get_compiler('c').find_library('dl', required: false)

conf = configuration_data()
conf.set('libexecdir', libexecdir)
conf.set('plugindir', plugindir)
conf.set('pkgdatadir', pkgdatadir)

configure_file(input: 'data/nm-openvpn3-service.name.in', output: 'nm-openvpn3-service.name',
  configuration: conf, install_dir: prefix / 'lib' / 'NetworkManager' / 'VPN')
install_data('data/nm-openvpn3-service.conf',
  install_dir: get_option('datadir') / 'dbus-1' / 'system.d')

# Service and auth dialog (Python)
configure_file(input: 'src/service/nm-openvpn3-service.in', output: 'nm-openvpn3-service',
  configuration: conf, install_dir: libexecdir, install_mode: 'rwxr-xr-x')
install_subdir('src/nm_openvpn3', install_dir: pkgdatadir,
  exclude_directories: ['__pycache__'])

# Secret agents (GNOME Shell, nmcli) run it to learn which secrets to ask for.
configure_file(input: 'auth-dialog/nm-openvpn3-auth-dialog.in', output: 'nm-openvpn3-auth-dialog',
  configuration: conf, install_dir: libexecdir, install_mode: 'rwxr-xr-x')

# libnm plugin (no GTK)
import_lib = static_library('ovpn-import', 'properties/ovpn-import.c',
  dependencies: libnm, pic: true)

shared_module('nm-vpn-plugin-openvpn3', 'properties/nm-openvpn3-editor-plugin.c',
  name_prefix: 'lib',
  link_with: import_lib,
  dependencies: [libnm, gmodule, dl],
  link_args: ['-Wl,--version-script=' + meson.current_source_dir() / 'properties/plugin.ver'],
  install: true, install_dir: plugindir)

# Editors: GTK 4 for GNOME Settings, GTK 3 for nm-connection-editor.
editors = [
  ['gnome', 'nm-gtk4-vpn-plugin-openvpn3-editor', ['gtk4', '>= 4.10'], 'libnma-gtk4'],
  ['gtk3', 'nm-vpn-plugin-openvpn3-editor', ['gtk+-3.0', '>= 3.22'], 'libnma'],
]
foreach e : editors
  if get_option(e[0])
    shared_module(e[1], 'properties/nm-openvpn3-editor.c',
      name_prefix: 'lib',
      link_with: import_lib,
      dependencies: [libnm, dependency(e[2][0], version: e[2][1]), dependency(e[3], version: '>= 1.10')],
      link_args: ['-Wl,--version-script=' + meson.current_source_dir() / 'properties/editor.ver'],
      install: true, install_dir: plugindir)
  endif
endforeach

pytest = find_program('pytest-3', 'pytest', required: false)
if pytest.found()
  test('unit', pytest, args: ['-q', '-p', 'no:cacheprovider', meson.current_source_dir() / 'tests' / 'unit'],
    env: ['OPENVPN3_PLUGIN_DIR=' + meson.current_build_dir()])
endif
