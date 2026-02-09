/*
    SPDX-FileCopyrightText: 2026 Pegasus Heavy Industries LLC
    SPDX-License-Identifier: GPL-3.0-only

    CoreVPN UI plugin for KDE Plasma NetworkManager integration.
*/

#ifndef PLASMANM_COREVPN_H
#define PLASMANM_COREVPN_H

#include "vpnuiplugin.h"

#include <QVariant>

class Q_DECL_EXPORT CoreVpnUiPlugin : public VpnUiPlugin
{
    Q_OBJECT
public:
    explicit CoreVpnUiPlugin(QObject *parent = nullptr, const QVariantList & = QVariantList());
    ~CoreVpnUiPlugin() override;

    SettingWidget *widget(const NetworkManager::VpnSetting::Ptr &setting, QWidget *parent) override;
    SettingWidget *askUser(const NetworkManager::VpnSetting::Ptr &setting, const QStringList &hints, QWidget *parent) override;

    QString suggestedFileName(const NetworkManager::ConnectionSettings::Ptr &connection) const override;
    QStringList supportedFileExtensions() const override;

    ImportResult importConnectionSettings(const QString &fileName) override;
    ExportResult exportConnectionSettings(const NetworkManager::ConnectionSettings::Ptr &connection, const QString &fileName) override;
};

#endif // PLASMANM_COREVPN_H
