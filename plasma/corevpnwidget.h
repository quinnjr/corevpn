/*
    SPDX-FileCopyrightText: 2026 Pegasus Heavy Industries LLC
    SPDX-License-Identifier: GPL-3.0-only

    CoreVPN settings widget for the plasma-nm VPN connection editor.
*/

#ifndef COREVPNWIDGET_H
#define COREVPNWIDGET_H

#include "settingwidget.h"

#include <NetworkManagerQt/VpnSetting>

namespace Ui {
class CoreVpnWidget;
}

class CoreVpnSettingWidget : public SettingWidget
{
    Q_OBJECT
public:
    explicit CoreVpnSettingWidget(const NetworkManager::VpnSetting::Ptr &setting, QWidget *parent = nullptr);
    ~CoreVpnSettingWidget() override;

    void loadConfig(const NetworkManager::Setting::Ptr &setting) override;
    QVariantMap setting() const override;
    bool isValid() const override;

private:
    Ui::CoreVpnWidget *m_ui;
    NetworkManager::VpnSetting::Ptr m_setting;
};

#endif // COREVPNWIDGET_H
