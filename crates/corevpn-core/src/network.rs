//! Network types and IP address management

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{CoreError, Result};

/// VPN IP address assigned to a client
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VpnAddress {
    /// IPv4 address (if assigned)
    pub ipv4: Option<Ipv4Addr>,
    /// IPv6 address (if assigned)
    pub ipv6: Option<Ipv6Addr>,
}

impl VpnAddress {
    /// Create with only IPv4
    pub fn v4(addr: Ipv4Addr) -> Self {
        Self {
            ipv4: Some(addr),
            ipv6: None,
        }
    }

    /// Create with only IPv6
    pub fn v6(addr: Ipv6Addr) -> Self {
        Self {
            ipv4: None,
            ipv6: Some(addr),
        }
    }

    /// Create with both IPv4 and IPv6
    pub fn dual(ipv4: Ipv4Addr, ipv6: Ipv6Addr) -> Self {
        Self {
            ipv4: Some(ipv4),
            ipv6: Some(ipv6),
        }
    }

    /// Get primary address (prefers IPv4)
    pub fn primary(&self) -> Option<IpAddr> {
        self.ipv4
            .map(IpAddr::V4)
            .or_else(|| self.ipv6.map(IpAddr::V6))
    }
}

/// Route to be pushed to VPN clients
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    /// Network/prefix to route
    pub network: IpNet,
    /// Gateway (None = use VPN gateway)
    pub gateway: Option<IpAddr>,
    /// Metric/priority
    pub metric: u32,
}

impl Route {
    /// Create a new route
    pub fn new(network: IpNet) -> Result<Self> {
        // Validate network
        Self::validate_network(&network)?;
        
        Ok(Self {
            network,
            gateway: None,
            metric: 0,
        })
    }

    /// Validate network configuration
    fn validate_network(network: &IpNet) -> Result<()> {
        match network {
            IpNet::V4(v4_net) => {
                // Validate IPv4 network prefix length
                let prefix_len = v4_net.prefix_len();
                if prefix_len > 32 {
                    return Err(CoreError::ConfigError(
                        "Invalid IPv4 network prefix length".into(),
                    ));
                }
            }
            IpNet::V6(v6_net) => {
                // Validate IPv6 network prefix length
                let prefix_len = v6_net.prefix_len();
                if prefix_len > 128 {
                    return Err(CoreError::ConfigError(
                        "Invalid IPv6 network prefix length".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Create default route (0.0.0.0/0)
    pub fn default_v4() -> Self {
        Self {
            network: "0.0.0.0/0".parse().unwrap(),
            gateway: None,
            metric: 0,
        }
    }

    /// Create default IPv6 route (::/0)
    pub fn default_v6() -> Self {
        Self {
            network: "::/0".parse().unwrap(),
            gateway: None,
            metric: 0,
        }
    }

    /// Set gateway
    pub fn with_gateway(mut self, gateway: IpAddr) -> Self {
        self.gateway = Some(gateway);
        self
    }

    /// Set metric
    pub fn with_metric(mut self, metric: u32) -> Self {
        self.metric = metric;
        self
    }
}

/// IP address pool for assigning addresses to VPN clients
pub struct AddressPool {
    /// IPv4 network range
    ipv4_net: Option<Ipv4Net>,
    /// IPv6 network range
    ipv6_net: Option<Ipv6Net>,
    /// Allocated IPv4 addresses
    allocated_v4: parking_lot::RwLock<HashSet<Ipv4Addr>>,
    /// Allocated IPv6 addresses
    allocated_v6: parking_lot::RwLock<HashSet<Ipv6Addr>>,
    /// Reserved addresses (e.g., gateway, broadcast)
    reserved_v4: HashSet<Ipv4Addr>,
    /// Reserved IPv6 addresses
    reserved_v6: HashSet<Ipv6Addr>,
}

impl AddressPool {
    /// Create a new address pool
    ///
    /// # Arguments
    /// * `ipv4_net` - IPv4 network (e.g., "10.8.0.0/24")
    /// * `ipv6_net` - IPv6 network (e.g., "fd00::/64")
    ///
    /// # Errors
    /// Returns an error if the network configuration is invalid
    pub fn new(ipv4_net: Option<Ipv4Net>, ipv6_net: Option<Ipv6Net>) -> Result<Self> {
        // Validate IPv4 network if provided
        if let Some(ref net) = ipv4_net {
            Self::validate_ipv4_net(net)?;
        }

        // Validate IPv6 network if provided
        if let Some(ref net) = ipv6_net {
            Self::validate_ipv6_net(net)?;
        }

        // Ensure at least one network is provided
        if ipv4_net.is_none() && ipv6_net.is_none() {
            return Err(CoreError::ConfigError(
                "At least one network (IPv4 or IPv6) must be provided".into(),
            ));
        }

        Ok(Self::new_unchecked(ipv4_net, ipv6_net))
    }

    /// Create a new address pool without validation (internal use)
    fn new_unchecked(ipv4_net: Option<Ipv4Net>, ipv6_net: Option<Ipv6Net>) -> Self {
        let mut reserved_v4 = HashSet::new();
        let mut reserved_v6 = HashSet::new();

        // Reserve network and broadcast addresses for IPv4
        if let Some(net) = &ipv4_net {
            reserved_v4.insert(net.network());
            reserved_v4.insert(net.broadcast());
            // Reserve .1 for gateway
            let gateway = Ipv4Addr::from(u32::from(net.network()) + 1);
            reserved_v4.insert(gateway);
        }

        // Reserve first address for IPv6 gateway
        if let Some(net) = &ipv6_net {
            let gateway = Ipv6Addr::from(u128::from(net.network()) + 1);
            reserved_v6.insert(gateway);
        }

        Self {
            ipv4_net,
            ipv6_net,
            allocated_v4: parking_lot::RwLock::new(HashSet::new()),
            allocated_v6: parking_lot::RwLock::new(HashSet::new()),
            reserved_v4,
            reserved_v6,
        }
    }

    /// Validate IPv4 network configuration
    fn validate_ipv4_net(net: &Ipv4Net) -> Result<()> {
        // Check prefix length is reasonable (not too small, not too large)
        let prefix_len = net.prefix_len();
        if prefix_len < 8 {
            return Err(CoreError::ConfigError(format!(
                "IPv4 network prefix length {} is too small (minimum 8)",
                prefix_len
            )));
        }
        if prefix_len > 30 {
            return Err(CoreError::ConfigError(format!(
                "IPv4 network prefix length {} is too large (maximum 30)",
                prefix_len
            )));
        }

        // Ensure network is not a loopback or multicast address
        let network_addr = net.network();
        if network_addr.is_loopback() {
            return Err(CoreError::ConfigError(
                "IPv4 network cannot be a loopback address".into(),
            ));
        }
        if network_addr.is_multicast() {
            return Err(CoreError::ConfigError(
                "IPv4 network cannot be a multicast address".into(),
            ));
        }

        // Ensure network is not in the link-local range (169.254.0.0/16)
        if network_addr.octets()[0] == 169 && network_addr.octets()[1] == 254 {
            return Err(CoreError::ConfigError(
                "IPv4 network cannot be in the link-local range (169.254.0.0/16)".into(),
            ));
        }

        Ok(())
    }

    /// Validate IPv6 network configuration
    fn validate_ipv6_net(net: &Ipv6Net) -> Result<()> {
        // Check prefix length is reasonable
        let prefix_len = net.prefix_len();
        if prefix_len < 48 {
            return Err(CoreError::ConfigError(format!(
                "IPv6 network prefix length {} is too small (minimum 48)",
                prefix_len
            )));
        }
        if prefix_len > 120 {
            return Err(CoreError::ConfigError(format!(
                "IPv6 network prefix length {} is too large (maximum 120)",
                prefix_len
            )));
        }

        // Ensure network is not a loopback or multicast address
        let network_addr = net.network();
        if network_addr.is_loopback() {
            return Err(CoreError::ConfigError(
                "IPv6 network cannot be a loopback address".into(),
            ));
        }
        if network_addr.is_multicast() {
            return Err(CoreError::ConfigError(
                "IPv6 network cannot be a multicast address".into(),
            ));
        }

        // Ensure network is not in the link-local range (fe80::/10)
        let segments = network_addr.segments();
        if segments[0] & 0xffc0 == 0xfe80 {
            return Err(CoreError::ConfigError(
                "IPv6 network cannot be in the link-local range (fe80::/10)".into(),
            ));
        }

        Ok(())
    }

    /// Get the gateway IPv4 address
    pub fn gateway_v4(&self) -> Option<Ipv4Addr> {
        self.ipv4_net.map(|net| {
            Ipv4Addr::from(u32::from(net.network()) + 1)
        })
    }

    /// Get the gateway IPv6 address
    pub fn gateway_v6(&self) -> Option<Ipv6Addr> {
        self.ipv6_net.map(|net| {
            Ipv6Addr::from(u128::from(net.network()) + 1)
        })
    }

    /// Allocate an address from the pool
    pub fn allocate(&self) -> Result<VpnAddress> {
        let ipv4 = if let Some(net) = &self.ipv4_net {
            Some(self.allocate_v4(net)?)
        } else {
            None
        };

        let ipv6 = if let Some(net) = &self.ipv6_net {
            Some(self.allocate_v6(net)?)
        } else {
            None
        };

        if ipv4.is_none() && ipv6.is_none() {
            return Err(CoreError::ConfigError("No address pools configured".into()));
        }

        Ok(VpnAddress { ipv4, ipv6 })
    }

    fn allocate_v4(&self, net: &Ipv4Net) -> Result<Ipv4Addr> {
        let mut allocated = self.allocated_v4.write();

        // Start from .2 (after gateway)
        let start = u32::from(net.network()) + 2;
        let end = u32::from(net.broadcast());

        for addr_u32 in start..end {
            let addr = Ipv4Addr::from(addr_u32);
            if !self.reserved_v4.contains(&addr) && !allocated.contains(&addr) {
                allocated.insert(addr);
                return Ok(addr);
            }
        }

        Err(CoreError::AddressPoolExhausted)
    }

    fn allocate_v6(&self, net: &Ipv6Net) -> Result<Ipv6Addr> {
        let mut allocated = self.allocated_v6.write();

        // Start from ::2 (after gateway)
        let start = u128::from(net.network()) + 2;
        // Limit search to reasonable range
        let end = start + 65534;

        for addr_u128 in start..end {
            let addr = Ipv6Addr::from(addr_u128);
            if !self.reserved_v6.contains(&addr) && !allocated.contains(&addr) {
                allocated.insert(addr);
                return Ok(addr);
            }
        }

        Err(CoreError::AddressPoolExhausted)
    }

    /// Allocate a specific address (for static assignment)
    pub fn allocate_specific(&self, addr: VpnAddress) -> Result<VpnAddress> {
        if let Some(v4) = addr.ipv4 {
            let mut allocated = self.allocated_v4.write();
            if let Some(net) = &self.ipv4_net {
                if !net.contains(&v4) {
                    return Err(CoreError::InvalidAddress(format!(
                        "{} not in pool {}",
                        v4, net
                    )));
                }
            }
            if self.reserved_v4.contains(&v4) || allocated.contains(&v4) {
                return Err(CoreError::InvalidAddress(format!(
                    "{} is reserved or already allocated",
                    v4
                )));
            }
            allocated.insert(v4);
        }

        if let Some(v6) = addr.ipv6 {
            let mut allocated = self.allocated_v6.write();
            if let Some(net) = &self.ipv6_net {
                if !net.contains(&v6) {
                    return Err(CoreError::InvalidAddress(format!(
                        "{} not in pool {}",
                        v6, net
                    )));
                }
            }
            if self.reserved_v6.contains(&v6) || allocated.contains(&v6) {
                return Err(CoreError::InvalidAddress(format!(
                    "{} is reserved or already allocated",
                    v6
                )));
            }
            allocated.insert(v6);
        }

        Ok(addr)
    }

    /// Release an address back to the pool
    pub fn release(&self, addr: &VpnAddress) {
        if let Some(v4) = addr.ipv4 {
            self.allocated_v4.write().remove(&v4);
        }
        if let Some(v6) = addr.ipv6 {
            self.allocated_v6.write().remove(&v6);
        }
    }

    /// Get the number of available IPv4 addresses
    pub fn available_v4(&self) -> usize {
        if let Some(net) = &self.ipv4_net {
            let total = net.hosts().count();
            let reserved = self.reserved_v4.len();
            let allocated = self.allocated_v4.read().len();
            total.saturating_sub(reserved).saturating_sub(allocated)
        } else {
            0
        }
    }

    /// Get the number of available IPv6 addresses
    pub fn available_v6(&self) -> usize {
        if self.ipv6_net.is_some() {
            // IPv6 pools are effectively unlimited, return large number
            let allocated = self.allocated_v6.read().len();
            65534usize.saturating_sub(allocated)
        } else {
            0
        }
    }

    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            ipv4_total: self.ipv4_net.map(|n| n.hosts().count()).unwrap_or(0),
            ipv4_allocated: self.allocated_v4.read().len(),
            ipv4_available: self.available_v4(),
            ipv6_allocated: self.allocated_v6.read().len(),
            ipv6_available: self.available_v6(),
        }
    }
}

/// Address pool statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolStats {
    /// Total IPv4 addresses in pool
    pub ipv4_total: usize,
    /// Allocated IPv4 addresses
    pub ipv4_allocated: usize,
    /// Available IPv4 addresses
    pub ipv4_available: usize,
    /// Allocated IPv6 addresses
    pub ipv6_allocated: usize,
    /// Available IPv6 addresses
    pub ipv6_available: usize,
}

/// DNS configuration to push to clients
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// DNS servers
    pub servers: Vec<IpAddr>,
    /// Search domains
    pub search_domains: Vec<String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            servers: vec![
                "1.1.1.1".parse().unwrap(),  // Cloudflare
                "1.0.0.1".parse().unwrap(),
            ],
            search_domains: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_pool() {
        let pool = AddressPool::new(
            Some("10.8.0.0/24".parse().unwrap()),
            None,
        ).unwrap();

        // First allocation should be .2
        let addr1 = pool.allocate().unwrap();
        assert_eq!(addr1.ipv4, Some("10.8.0.2".parse().unwrap()));

        // Second should be .3
        let addr2 = pool.allocate().unwrap();
        assert_eq!(addr2.ipv4, Some("10.8.0.3".parse().unwrap()));

        // Release first
        pool.release(&addr1);

        // Next allocation should reuse .2
        let addr3 = pool.allocate().unwrap();
        assert_eq!(addr3.ipv4, Some("10.8.0.2".parse().unwrap()));
    }

    #[test]
    fn test_gateway_address() {
        let pool = AddressPool::new(
            Some("10.8.0.0/24".parse().unwrap()),
            Some("fd00::/64".parse().unwrap()),
        ).unwrap();

        assert_eq!(pool.gateway_v4(), Some("10.8.0.1".parse().unwrap()));
        assert_eq!(pool.gateway_v6(), Some("fd00::1".parse().unwrap()));
    }

    #[test]
    fn test_route() {
        let route = Route::new("192.168.1.0/24".parse().unwrap()).unwrap()
            .with_gateway("10.8.0.1".parse().unwrap())
            .with_metric(100);

        assert_eq!(route.metric, 100);
        assert_eq!(route.gateway, Some("10.8.0.1".parse().unwrap()));
    }

    #[test]
    fn test_address_pool_validation() {
        // Test invalid IPv4 prefix length
        assert!(AddressPool::new(Some("10.8.0.0/7".parse().unwrap()), None).is_err());
        assert!(AddressPool::new(Some("10.8.0.0/31".parse().unwrap()), None).is_err());
        
        // Test invalid IPv6 prefix length
        assert!(AddressPool::new(None, Some("fd00::/47".parse().unwrap())).is_err());
        assert!(AddressPool::new(None, Some("fd00::/121".parse().unwrap())).is_err());
        
        // Test loopback addresses
        assert!(AddressPool::new(Some("127.0.0.0/24".parse().unwrap()), None).is_err());
        assert!(AddressPool::new(None, Some("::1/64".parse().unwrap())).is_err());
        
        // Test valid addresses
        assert!(AddressPool::new(Some("10.8.0.0/24".parse().unwrap()), None).is_ok());
        assert!(AddressPool::new(None, Some("fd00::/64".parse().unwrap())).is_ok());
    }
}
