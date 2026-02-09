// SPDX-FileCopyrightText: 2008 Will Stephenson <wstephenson@kde.org>
// SPDX-FileCopyrightText: 2013 Lukáš Tinkl <ltinkl@redhat.com>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL
//
// Vendored from KDE plasma-nm for build compatibility.

#ifndef PLASMA_NM_VPN_UI_PLUGIN_H
#define PLASMA_NM_VPN_UI_PLUGIN_H

#ifndef PLASMANM_EDITOR_EXPORT
#define PLASMANM_EDITOR_EXPORT
#endif

#include <QMessageBox>
#include <QObject>
#include <QVariant>

#include <NetworkManagerQt/ConnectionSettings>
#include <NetworkManagerQt/GenericTypes>
#include <NetworkManagerQt/VpnSetting>

#include <KPluginFactory>

#include "settingwidget.h"

// NMConnection is typedef struct _NMConnection from libnm,
// already available via NetworkManagerQt headers

class PLASMANM_EDITOR_EXPORT VpnUiPlugin : public QObject
{
    Q_OBJECT
public:
    enum ErrorType {
        NoError,
        NotImplemented,
        Error
    };

    explicit VpnUiPlugin(QObject *parent = nullptr, const QVariantList & = QVariantList());
    ~VpnUiPlugin() override;

    virtual SettingWidget *widget(const NetworkManager::VpnSetting::Ptr &setting, QWidget *parent) = 0;
    virtual SettingWidget *askUser(const NetworkManager::VpnSetting::Ptr &setting, const QStringList &hints, QWidget *parent) = 0;

    virtual QString suggestedFileName(const NetworkManager::ConnectionSettings::Ptr &connection) const = 0;
    virtual QStringList supportedFileExtensions() const;

    struct ImportResult {
    private:
        NMConnection *m_connection;
        ErrorType m_error = NoError;
        QString m_errorMessage;

    public:
        operator bool() const;

        QString errorMessage() const;

        NMConnection *connection() const;

        static ImportResult fail(const QString &errorMessage);

        static ImportResult pass(NMConnection *connection);

        static ImportResult notImplemented();
    };

    virtual ImportResult importConnectionSettings(const QString &fileName);

    struct ExportResult {
    private:
        ErrorType m_error = NoError;
        QString m_errorMessage;

    public:
        operator bool() const;

        QString errorMessage() const;

        static ExportResult pass();

        static ExportResult fail(const QString &errorMessage);

        static ExportResult notImplemented();
    };

    virtual ExportResult exportConnectionSettings(const NetworkManager::ConnectionSettings::Ptr &connection, const QString &fileName);

    virtual QMessageBox::StandardButtons suggestedAuthDialogButtons() const;

    static KPluginFactory::Result<VpnUiPlugin> loadPluginForType(QObject *parent, const QString &serviceType);
};

#endif // PLASMA_NM_VPN_UI_PLUGIN_H
