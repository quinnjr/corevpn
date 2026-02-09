/*
    SPDX-FileCopyrightText: 2026 Pegasus Heavy Industries LLC
    SPDX-License-Identifier: GPL-3.0-only

    CoreVPN UI plugin for KDE Plasma NetworkManager integration.
*/

#include "corevpn.h"
#include "corevpnauth.h"
#include "corevpnwidget.h"

#include <KPluginFactory>
#include <KLocalizedString>

#include <NetworkManagerQt/ConnectionSettings>
#include <NetworkManagerQt/VpnSetting>

#include <QFile>
#include <QFileInfo>

extern "C" {
#include <NetworkManager.h>
}

K_PLUGIN_CLASS_WITH_JSON(CoreVpnUiPlugin, "plasmanetworkmanagement_corevpnui.json")

CoreVpnUiPlugin::CoreVpnUiPlugin(QObject *parent, const QVariantList &)
    : VpnUiPlugin(parent)
{
}

CoreVpnUiPlugin::~CoreVpnUiPlugin() = default;

SettingWidget *CoreVpnUiPlugin::widget(const NetworkManager::VpnSetting::Ptr &setting, QWidget *parent)
{
    return new CoreVpnSettingWidget(setting, parent);
}

SettingWidget *CoreVpnUiPlugin::askUser(const NetworkManager::VpnSetting::Ptr &setting, const QStringList &hints, QWidget *parent)
{
    return new CoreVpnAuthWidget(setting, hints, parent);
}

QString CoreVpnUiPlugin::suggestedFileName(const NetworkManager::ConnectionSettings::Ptr &connection) const
{
    return connection->id() + QStringLiteral(".ovpn");
}

QStringList CoreVpnUiPlugin::supportedFileExtensions() const
{
    return {QStringLiteral("*.ovpn"), QStringLiteral("*.conf")};
}

VpnUiPlugin::ImportResult CoreVpnUiPlugin::importConnectionSettings(const QString &fileName)
{
    if (!QFile::exists(fileName)) {
        return ImportResult::fail(i18n("File not found: %1", fileName));
    }

    const QFileInfo fileInfo(fileName);
    const QString connectionName = fileInfo.completeBaseName();
    const QString absolutePath = fileInfo.absoluteFilePath();

    // Create an NMConnection using libnm C API
    NMConnection *connection = nm_simple_connection_new();

    // Set connection settings
    NMSettingConnection *sConn = NM_SETTING_CONNECTION(nm_setting_connection_new());
    nm_connection_add_setting(connection, NM_SETTING(sConn));

    g_object_set(sConn,
                 NM_SETTING_CONNECTION_ID, connectionName.toUtf8().constData(),
                 NM_SETTING_CONNECTION_TYPE, NM_SETTING_VPN_SETTING_NAME,
                 NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
                 nullptr);

    // Set VPN settings
    NMSettingVpn *sVpn = NM_SETTING_VPN(nm_setting_vpn_new());
    nm_connection_add_setting(connection, NM_SETTING(sVpn));

    g_object_set(sVpn,
                 NM_SETTING_VPN_SERVICE_TYPE, "org.freedesktop.NetworkManager.corevpn",
                 nullptr);
    nm_setting_vpn_add_data_item(sVpn, "config", absolutePath.toUtf8().constData());

    return ImportResult::pass(connection);
}

VpnUiPlugin::ExportResult CoreVpnUiPlugin::exportConnectionSettings(
    const NetworkManager::ConnectionSettings::Ptr &connection, const QString &fileName)
{
    auto vpnSetting = connection->setting(NetworkManager::Setting::Vpn).staticCast<NetworkManager::VpnSetting>();
    const NMStringMap data = vpnSetting->data();

    const QString configPath = data.value(QStringLiteral("config"));
    if (configPath.isEmpty()) {
        return ExportResult::fail(i18n("No configuration file path stored in this connection."));
    }

    if (!QFile::exists(configPath)) {
        return ExportResult::fail(i18n("Source configuration file not found: %1", configPath));
    }

    // Copy the original .ovpn file to the export location
    if (QFile::exists(fileName)) {
        QFile::remove(fileName);
    }
    if (!QFile::copy(configPath, fileName)) {
        return ExportResult::fail(i18n("Failed to copy configuration to: %1", fileName));
    }

    return ExportResult::pass();
}

#include "corevpn.moc"
