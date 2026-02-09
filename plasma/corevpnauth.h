/*
    SPDX-FileCopyrightText: 2026 Pegasus Heavy Industries LLC
    SPDX-License-Identifier: GPL-3.0-only

    CoreVPN authentication widget for plasma-nm.
    CoreVPN primarily uses certificate-based or OAuth authentication,
    so this widget is minimal.
*/

#ifndef COREVPNAUTH_H
#define COREVPNAUTH_H

#include "settingwidget.h"

#include <NetworkManagerQt/VpnSetting>

class QLabel;

class CoreVpnAuthWidget : public SettingWidget
{
    Q_OBJECT
public:
    explicit CoreVpnAuthWidget(const NetworkManager::VpnSetting::Ptr &setting,
                               const QStringList &hints,
                               QWidget *parent = nullptr);
    ~CoreVpnAuthWidget() override;

    QVariantMap setting() const override;

private:
    QLabel *m_label = nullptr;
};

#endif // COREVPNAUTH_H
