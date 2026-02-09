/*
    SPDX-FileCopyrightText: 2026 Pegasus Heavy Industries LLC
    SPDX-License-Identifier: GPL-3.0-only

    CoreVPN authentication widget for plasma-nm.
*/

#include "corevpnauth.h"

#include <QLabel>
#include <QVBoxLayout>
#include <KLocalizedString>

CoreVpnAuthWidget::CoreVpnAuthWidget(const NetworkManager::VpnSetting::Ptr &setting,
                                     const QStringList &hints,
                                     QWidget *parent)
    : SettingWidget(setting, hints, parent)
{
    auto *layout = new QVBoxLayout(this);

    m_label = new QLabel(this);
    m_label->setWordWrap(true);
    m_label->setText(i18n("CoreVPN authenticates using the credentials embedded in the .ovpn "
                          "configuration file. If your server requires OAuth authentication, "
                          "a browser window will open automatically during connection."));
    layout->addWidget(m_label);

    layout->addStretch();

    setLayout(layout);
}

CoreVpnAuthWidget::~CoreVpnAuthWidget() = default;

QVariantMap CoreVpnAuthWidget::setting() const
{
    // No additional secrets needed — authentication is handled by the
    // CoreVPN daemon using the .ovpn config (certificates / OAuth).
    return {};
}
