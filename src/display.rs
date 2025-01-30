use std::fmt::Display;

use crate::packet::{NdpPacket, NdpPacketContent, NdpRouterAdvertOption};

impl Display for NdpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Source Mac: {}", self.mac_src)?;
        writeln!(f, "Source IPv6: {}", self.ipv6_src)?;
        write!(f, "{}", self.content)?;
        Ok(())
    }
}

fn default_router_pref_parse(n: u8) -> &'static str {
    match n {
        0 => "Medium",
        1 => "High",
        3 => "Low",
        _ => "ERROR",
    }
}

impl Display for NdpPacketContent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NeighborAdvert { target, mac_src } => {
                writeln!(f, "NDP Type: Neighbor Advertisment")?;
                write!(f, "Target: {}", target)?;
                if let Some(mac) = mac_src {
                    write!(f, "\nSource link-layer address: {}", mac)?;
                }
            }
            Self::RouterAdvert {
                cur_hop_limit,
                managed_address_config,
                other_stateful_config,
                home_agent,
                default_router_preference,
                nd_proxy,
                router_lifetime,
                reachable_time,
                retrans_timer,
                options,
            } => {
                writeln!(f, "NDP Type: Router Advertisment")?;
                writeln!(f, "Cur Hop Limit: {}", cur_hop_limit)?;
                writeln!(
                    f,
                    "Managed address configuration: {}",
                    managed_address_config
                )?;
                writeln!(f, "Other stateful configuration: {}", other_stateful_config)?;
                writeln!(f, "Home agent: {}", home_agent)?;
                writeln!(
                    f,
                    "Default Router Preference: {} ({})",
                    default_router_pref_parse(*default_router_preference),
                    default_router_preference
                )?;
                writeln!(f, "ND Proxy: {}", nd_proxy)?;
                writeln!(f, "Router Lifetime: {}", router_lifetime)?;
                writeln!(f, "Reachable Time: {}", reachable_time)?;
                writeln!(f, "Retrans Timer: {}", retrans_timer)?;
                write!(f, "Options:")?;
                for option in options {
                    write!(f, "\n{option}")?;
                }
            }
        }
        Ok(())
    }
}

impl Display for NdpRouterAdvertOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SourceLinkLayerAddress { addr } => {
                writeln!(f, "Source link-layer address")?;
                write!(f, "Mac: {addr}")?;
            }
            Self::Mtu { mtu } => {
                writeln!(f, "MTU")?;
                write!(f, "MTU: {mtu}")?;
            }
            Self::PrefixInformation {
                prefix_length,
                on_link,
                autonomous_addr_config,
                valid_lifetime,
                preferred_lifetime,
                prefix,
            } => {
                writeln!(f, "Prefix Information")?;
                writeln!(f, "on-link: {}", on_link)?;
                writeln!(
                    f,
                    "autonomous address-configuration: {}",
                    autonomous_addr_config
                )?;
                writeln!(f, "Valid Lifetime: {}", valid_lifetime)?;
                writeln!(f, "Preferred Lifetime: {}", preferred_lifetime)?;
                write!(f, "Prefix: {}/{}", prefix, prefix_length)?;
            }
            Self::RouteInformation {
                prefix_length,
                route_preference,
                route_lifetime,
                prefix,
            } => {
                writeln!(f, "Route Information")?;
                writeln!(f, "Route Preference: {}", route_preference)?;
                writeln!(f, "Route Lifetime: {}", route_lifetime)?;
                write!(f, "Prefix: {}/{}", prefix, prefix_length)?;
            }
            Self::RecursiveDnsServer {
                lifetime,
                addresses,
            } => {
                writeln!(f, "Recursive DNS Server")?;
                write!(f, "Lifetime: {}", lifetime)?;
                for address in addresses {
                    write!(f, "\n- {address}")?;
                }
            }
        }
        Ok(())
    }
}
