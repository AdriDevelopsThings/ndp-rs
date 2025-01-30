use std::net::Ipv6Addr;

use anyhow::{Context, Result};
use pnet::{
    datalink::{self, NetworkInterface},
    ipnetwork::IpNetwork,
};

pub struct InterfaceInformation {
    pub interface: NetworkInterface,
    pub link_local_addr: Ipv6Addr,
    pub ips: Vec<Ipv6Addr>,
}

pub fn get_interface(name: String) -> Result<InterfaceInformation> {
    let interface = datalink::interfaces()
        .into_iter()
        .find(|i| i.name == name)
        .with_context(|| format!("Interface '{}' does not exist", name))?;

    let link_local_addr = interface
        .ips
        .iter()
        .find_map(|ip| match ip {
            IpNetwork::V4(_) => None,
            IpNetwork::V6(ip) => {
                if ip.network() == Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0) {
                    Some(ip.ip())
                } else {
                    None
                }
            }
        })
        .context("Interface does not have a link local ipv6 address")?;
    let ips = interface
        .ips
        .iter()
        .filter_map(|ip| match ip {
            IpNetwork::V4(_) => None,
            IpNetwork::V6(ip) => Some(ip.ip()),
        })
        .collect::<Vec<_>>();

    Ok(InterfaceInformation {
        interface,
        link_local_addr,
        ips,
    })
}
