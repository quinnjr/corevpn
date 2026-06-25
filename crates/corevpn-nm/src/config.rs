//! NetworkManager connection settings parser.
//!
//! Extracts the .ovpn config file path from the NM connection dictionary
//! that is passed to the VPN plugin via D-Bus.
//!
//! NM passes connection data as `a{sa{sv}}` — a dict of setting groups,
//! each containing a dict of key-value pairs. The VPN-specific data lives
//! under the `"vpn"` group with keys `"data"` (public settings) and
//! `"secrets"` (private settings like passwords).

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use zbus::zvariant::{OwnedValue, Value};

/// Parsed VPN connection settings from NetworkManager.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct NmVpnSettings {
    /// Path to the .ovpn configuration file.
    pub config_path: PathBuf,
    /// Optional username for authentication.
    pub username: Option<String>,
    /// Optional password (from secrets).
    pub password: Option<String>,
}

/// Parse VPN settings from the NM connection dictionary.
///
/// The dictionary has the structure:
/// ```text
/// {
///   "vpn": {
///     "data": Dict { "config": "/path/to/file.ovpn", ... },
///     "secrets": Dict { "password": "...", ... },
///     "service-type": "org.freedesktop.NetworkManager.corevpn",
///   },
///   "connection": { "id": "My VPN", "type": "vpn", ... },
///   ...
/// }
/// ```
pub fn parse_nm_settings(
    connection: &HashMap<String, HashMap<String, OwnedValue>>,
) -> Result<NmVpnSettings> {
    let vpn_group = connection
        .get("vpn")
        .context("Connection dict missing 'vpn' group")?;

    // Extract the vpn.data dictionary (a{ss} stored as a{sv})
    let vpn_data = extract_string_dict(vpn_group, "data").unwrap_or_default();

    // Extract the vpn.secrets dictionary
    let vpn_secrets = extract_string_dict(vpn_group, "secrets").unwrap_or_default();

    // The config path is required
    let config_path = vpn_data
        .get("config")
        .or_else(|| vpn_data.get("config-file"))
        .context("vpn.data missing 'config' key — set it to the .ovpn file path")?;

    if config_path.is_empty() {
        bail!("vpn.data 'config' value is empty");
    }

    let path = PathBuf::from(config_path);
    if !path.exists() {
        bail!("Config file does not exist: {}", path.display());
    }

    Ok(NmVpnSettings {
        config_path: path,
        username: vpn_data.get("username").cloned(),
        password: vpn_secrets.get("password").cloned(),
    })
}

/// Extract a `Dict<String, String>` that NM may store as `a{sv}` inside the group.
///
/// NM stores vpn.data as a variant that is itself a dict. We try both
/// direct string values and nested dict representations.
fn extract_string_dict(
    group: &HashMap<String, OwnedValue>,
    key: &str,
) -> Option<HashMap<String, String>> {
    let value = group.get(key)?;
    try_as_string_dict(value)
}

/// Attempt to convert an `OwnedValue` into a `HashMap<String, String>`.
///
/// Handles the various ways NM may encode the dict.
fn try_as_string_dict(value: &OwnedValue) -> Option<HashMap<String, String>> {
    // Try as a{sv} first (most common NM encoding)
    if let Ok(dict) = <HashMap<String, OwnedValue>>::try_from(value.clone()) {
        let mut result = HashMap::new();
        for (k, v) in dict {
            if let Some(s) = try_as_string(&v) {
                result.insert(k, s);
            }
        }
        return Some(result);
    }

    // Try as a{ss}
    if let Ok(dict) = <HashMap<String, String>>::try_from(value.clone()) {
        return Some(dict);
    }

    None
}

/// Try to extract a string from an OwnedValue.
fn try_as_string(value: &OwnedValue) -> Option<String> {
    // Direct string
    if let Value::Str(s) = Value::from(value.clone()) {
        return Some(s.to_string());
    }
    // Try converting
    if let Ok(s) = String::try_from(value.clone()) {
        return Some(s);
    }
    None
}
