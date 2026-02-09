cmake_minimum_required(VERSION 3.22...4.2)
project(plasmanetworkmanagement_corevpnui VERSION 0.1.0)

# Copyright (c) 2026 Pegasus Heavy Industries LLC
# Contact: pegasusheavyindustries@gmail.com

# Required for CMake 4.x + Qt6 compatibility
set(QT_DEFAULT_MAJOR_VERSION 6)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)

# ── Find dependencies ──────────────────────────────────────────────────────────

find_package(ECM REQUIRED NO_MODULE)
set(CMAKE_MODULE_PATH ${ECM_MODULE_PATH})

include(KDEInstallDirs)
include(KDECMakeSettings)

find_package(Qt6 REQUIRED COMPONENTS Core Widgets DBus)
find_package(KF6CoreAddons REQUIRED)
find_package(KF6I18n REQUIRED)
find_package(KF6KIO REQUIRED)
find_package(KF6NetworkManagerQt REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(NM REQUIRED IMPORTED_TARGET libnm>=1.4.0)

# ── Locate the plasmanm_editor library ─────────────────────────────────────────
# plasma-nm does not install CMake config or development headers, so we locate
# the shared library directly and vendor the minimal headers needed to compile
# out-of-tree VPN plugins (see include/).

find_library(PLASMANM_EDITOR_LIB NAMES plasmanm_editor REQUIRED)

# ── Plugin target ──────────────────────────────────────────────────────────────

add_library(plasmanetworkmanagement_corevpnui MODULE
    corevpn.cpp
    corevpn.h
    corevpnwidget.cpp
    corevpnwidget.h
    corevpnauth.cpp
    corevpnauth.h
)

# The .ui file will be processed by AUTOUIC automatically

target_include_directories(plasmanetworkmanagement_corevpnui PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Suppress warnings about missing export header (we define the macro ourselves)
target_compile_definitions(plasmanetworkmanagement_corevpnui PRIVATE
    PLASMANM_EDITOR_EXPORT=
)

target_link_libraries(plasmanetworkmanagement_corevpnui
    ${PLASMANM_EDITOR_LIB}
    Qt6::Core
    Qt6::Widgets
    Qt6::DBus
    KF6::CoreAddons
    KF6::I18n
    KF6::KIOWidgets
    KF6::NetworkManagerQt
    PkgConfig::NM
)

# ── Install ────────────────────────────────────────────────────────────────────

install(TARGETS plasmanetworkmanagement_corevpnui
    DESTINATION ${KDE_INSTALL_PLUGINDIR}/plasma/network/vpn
)
