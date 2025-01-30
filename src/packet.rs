use std::net::Ipv6Addr;

use anyhow::{Context, Result};
use pnet::{
    packet::{
        ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
        icmpv6::{
            self,
            ndp::{
                MutableNdpOptionPacket, MutableNeighborSolicitPacket, MutableRouterAdvertPacket,
                MutableRouterSolicitPacket, NdpOptionPacket, NdpOptionType, NdpOptionTypes,
                NeighborAdvertPacket, NeighborSolicitPacket, RouterAdvertPacket,
                RouterSolicitPacket,
            },
            Icmpv6Packet, Icmpv6Types, MutableIcmpv6Packet,
        },
        ip::IpNextHeaderProtocols,
        ipv6::{Ipv6Packet, MutableIpv6Packet},
        Packet,
    },
    util::MacAddr,
};

use crate::{args::Commands, ra_config::RouterAdvertismentConfig};

const PKT_ETH_SIZE: usize = EthernetPacket::minimum_packet_size();
const PKT_IPV6_SIZE: usize = Ipv6Packet::minimum_packet_size();
const PKT_NDP_N_SOL_SIZE: usize = NeighborSolicitPacket::minimum_packet_size();
const PKT_NDP_R_SOL_SIZE: usize = RouterSolicitPacket::minimum_packet_size();
const PKT_NDP_R_ADV_SIZE: usize = RouterAdvertPacket::minimum_packet_size();
const PKT_NDP_OPT_SIZE: usize = NdpOptionPacket::minimum_packet_size();
const PKT_MAC_SIZE: usize = 6;
const PKT_NDP_OPT_PREFIX_INFORMATION_SIZE: usize = 30;
const PKT_NDP_OPT_MTU_SIZE: usize = 6;
const PKT_NDP_OPT_ROUTE_INFORMATION_SIZE: usize = 6; // without prefix (variable length)
const PKT_NDP_OPT_RECURSIVE_DNS_SERVER_SIZE: usize = 6; // without addresses
const PKT_MIN_ICMPV6_SIZE: usize =
    PKT_ETH_SIZE + PKT_IPV6_SIZE + Icmpv6Packet::minimum_packet_size();

pub fn prepare_buffer(command: &Commands, ra: &Option<RouterAdvertismentConfig>) -> Vec<u8> {
    let len = PKT_ETH_SIZE
        + PKT_IPV6_SIZE
        + match command {
            Commands::NeighborSolicitation { .. } => {
                PKT_NDP_N_SOL_SIZE + PKT_NDP_OPT_SIZE + PKT_MAC_SIZE
            }
            Commands::RouterSolicitation => PKT_NDP_R_SOL_SIZE + PKT_NDP_OPT_SIZE + PKT_MAC_SIZE,
            Commands::RouterAdvertisment(_) => {
                let ra = ra.as_ref().unwrap();
                PKT_NDP_R_ADV_SIZE
                    + PKT_NDP_OPT_SIZE
                    + PKT_MAC_SIZE
                    + (ra.prefix.len() * (PKT_NDP_OPT_SIZE + PKT_NDP_OPT_PREFIX_INFORMATION_SIZE)
                        + (ra.mtu.len()) * (PKT_NDP_OPT_SIZE + PKT_NDP_OPT_MTU_SIZE))
                    + ra.route
                        .iter()
                        .map(|route| {
                            let prefix_len = route
                                .prefix
                                .split('/')
                                .last()
                                .expect("Invalid route ipv6 address")
                                .parse::<u8>()
                                .expect("Invalid route ipv6 address");
                            PKT_NDP_OPT_SIZE
                                + PKT_NDP_OPT_ROUTE_INFORMATION_SIZE
                                + match prefix_len {
                                    0 => 0,
                                    _ => ((prefix_len - 1) / 8) + 1,
                                } as usize
                        })
                        .sum::<usize>()
                    + ra.dns_server
                        .iter()
                        .map(|dns_server| {
                            PKT_NDP_OPT_SIZE
                                + PKT_NDP_OPT_RECURSIVE_DNS_SERVER_SIZE
                                + (dns_server.addresses.len() * 16)
                        })
                        .sum::<usize>()
            }
        };
    vec![0; len]
}

pub fn prepare_pkt_eth(buffer: &mut [u8], src: MacAddr, dst: MacAddr) {
    let mut pkt = MutableEthernetPacket::new(buffer).unwrap();
    pkt.set_ethertype(EtherTypes::Ipv6);
    pkt.set_source(src);
    pkt.set_destination(dst);
}

pub fn prepare_pkt_ipv6(buffer: &mut [u8], src: Ipv6Addr, dst: Ipv6Addr) {
    let buffer_len = buffer.len();
    let mut pkt = MutableIpv6Packet::new(&mut buffer[PKT_ETH_SIZE..]).unwrap();
    pkt.set_version(6);
    pkt.set_hop_limit(u8::MAX);
    pkt.set_next_header(IpNextHeaderProtocols::Icmpv6);
    pkt.set_source(src);
    pkt.set_destination(dst);
    pkt.set_payload_length((buffer_len - PKT_ETH_SIZE - PKT_IPV6_SIZE) as u16);
}

pub fn prepare_pkt_ndp_neighbor_solicitation(buffer: &mut [u8], src: MacAddr, dst: Ipv6Addr) {
    let mut pkt =
        MutableNeighborSolicitPacket::new(&mut buffer[PKT_ETH_SIZE + PKT_IPV6_SIZE..]).unwrap();
    pkt.set_icmpv6_type(Icmpv6Types::NeighborSolicit);
    pkt.set_target_addr(dst);

    let mut opt_pkt = MutableNdpOptionPacket::new(pkt.get_options_raw_mut()).unwrap();
    opt_pkt.set_option_type(NdpOptionTypes::SourceLLAddr);
    opt_pkt.set_length(1);
    opt_pkt.set_data(&src.octets());
}

pub fn prepare_pkt_ndp_router_solicitation(buffer: &mut [u8], src: MacAddr) {
    let mut pkt =
        MutableRouterSolicitPacket::new(&mut buffer[PKT_ETH_SIZE + PKT_IPV6_SIZE..]).unwrap();
    pkt.set_icmpv6_type(Icmpv6Types::RouterSolicit);

    let mut opt_pkt = MutableNdpOptionPacket::new(pkt.get_options_raw_mut()).unwrap();
    opt_pkt.set_option_type(NdpOptionTypes::SourceLLAddr);
    opt_pkt.set_length(1);
    opt_pkt.set_data(&src.octets());
}

pub fn prepare_pkt_ndp_router_advertisment(
    buffer: &mut [u8],
    args: &RouterAdvertismentConfig,
    src: MacAddr,
) -> Result<()> {
    let mut pkt =
        MutableRouterAdvertPacket::new(&mut buffer[PKT_ETH_SIZE + PKT_IPV6_SIZE..]).unwrap();

    let mut flags = 0u8;
    if args.managed_address_configuration {
        flags |= 0x80;
    }
    if args.other_stateful_configuration {
        flags |= 0x40;
    }

    pkt.set_icmpv6_type(Icmpv6Types::RouterAdvert);
    pkt.set_hop_limit(args.cur_hop_limit.to_be());
    pkt.set_flags(flags.to_be());
    pkt.set_lifetime(args.router_lifetime.to_be());
    pkt.set_reachable_time(args.reachable_time.to_be());
    pkt.set_retrans_time(args.retrans_timer.to_be());

    let mut i = PKT_ETH_SIZE + PKT_IPV6_SIZE + PKT_NDP_R_ADV_SIZE;

    {
        let length = PKT_NDP_OPT_SIZE + PKT_MAC_SIZE;
        let mut opt = MutableNdpOptionPacket::new(&mut buffer[i..i + length]).unwrap();
        opt.set_option_type(NdpOptionTypes::SourceLLAddr);
        opt.set_length(1);
        opt.set_data(&src.octets());
        i += length;
    }

    for option in &args.prefix {
        let length = PKT_NDP_OPT_SIZE + PKT_NDP_OPT_PREFIX_INFORMATION_SIZE;
        let length_s = option.prefix.split('/').collect::<Vec<_>>();
        let prefix: Ipv6Addr = length_s[0]
            .parse()
            .with_context(|| format!("Invalid ipv6 addr '{}'", length_s[0]))?;
        let prefix_len: u8 = length_s[1].parse().context("Invalid prefix length")?;

        let mut opt = MutableNdpOptionPacket::new(&mut buffer[i..i + length]).unwrap();
        opt.set_option_type(NdpOptionTypes::PrefixInformation);
        opt.set_length(4);

        let mut flags = 0u8;
        if option.on_link {
            flags |= 0x80;
        }
        if option.autonomous_address_configuration {
            flags |= 0x40;
        }

        let mut opt_buffer = [0; PKT_NDP_OPT_PREFIX_INFORMATION_SIZE];
        opt_buffer[0] = prefix_len.to_be();
        opt_buffer[1] = flags.to_be();
        opt_buffer[2..6].copy_from_slice(&option.valid_lifetime.to_be_bytes());
        opt_buffer[6..10].copy_from_slice(&option.preferred_lifetime.to_be_bytes());
        opt_buffer[14..30].copy_from_slice(&prefix.octets());

        opt.set_data(&opt_buffer);
        i += length;
    }

    for option in &args.mtu {
        let length = PKT_NDP_OPT_SIZE + PKT_NDP_OPT_MTU_SIZE;
        let mut opt = MutableNdpOptionPacket::new(&mut buffer[i..i + length]).unwrap();
        opt.set_option_type(NdpOptionTypes::MTU);
        opt.set_length(1);

        let mut opt_buffer = [0u8; PKT_NDP_OPT_MTU_SIZE];
        opt_buffer[2..6].copy_from_slice(&option.mtu.to_be_bytes());

        opt.set_data(&opt_buffer);
        i += length;
    }

    for option in &args.route {
        let splitted_prefix = option.prefix.split('/').collect::<Vec<_>>();
        let prefix: Ipv6Addr = splitted_prefix[0]
            .parse()
            .with_context(|| format!("Invalid ipv6 address {}", option.prefix))?;
        let prefix_len: u8 = splitted_prefix[1]
            .parse()
            .with_context(|| format!("Invalid ipv6 address {}", option.prefix))?;

        let prefix_len_octs = (((prefix_len - 1) / 64) + 1) as usize;
        let prefix_len_bytes = prefix_len_octs * 8;

        let length = PKT_NDP_OPT_SIZE + PKT_NDP_OPT_ROUTE_INFORMATION_SIZE + prefix_len_bytes;

        let mut opt = MutableNdpOptionPacket::new(&mut buffer[i..i + length]).unwrap();
        opt.set_option_type(NdpOptionType(24));
        opt.set_length(1 + prefix_len_octs as u8);

        let flags = (option.preference << 3) & 0x14;

        let mut opt_buffers = vec![0u8; PKT_NDP_OPT_ROUTE_INFORMATION_SIZE + prefix_len_bytes];
        opt_buffers[0] = prefix_len.to_be();
        opt_buffers[1] = flags.to_be();
        opt_buffers[2..6].copy_from_slice(&option.lifetime.to_be_bytes());
        opt_buffers[6..6 + prefix_len_bytes].copy_from_slice(&prefix.octets()[0..prefix_len_bytes]);

        opt.set_data(&opt_buffers);
        i += length;
    }

    for option in &args.dns_server {
        let length = PKT_NDP_OPT_SIZE
            + PKT_NDP_OPT_RECURSIVE_DNS_SERVER_SIZE
            + (option.addresses.len() * 16);
        let mut opt = MutableNdpOptionPacket::new(&mut buffer[i..i + length]).unwrap();
        opt.set_option_type(NdpOptionType(25));
        opt.set_length(1 + (option.addresses.len() as u8 * 2));

        let mut opt_buffers =
            vec![0u8; PKT_NDP_OPT_RECURSIVE_DNS_SERVER_SIZE + (option.addresses.len() * 16)];
        opt_buffers[2..6].copy_from_slice(&option.lifetime.to_be_bytes());
        let mut k: usize = 6;
        for address in &option.addresses {
            let address: Ipv6Addr = address
                .parse()
                .with_context(|| format!("Invalid DNS Server ipv6 address '{}'", address))?;
            opt_buffers[k..k + 16].copy_from_slice(&address.octets());
            k += 16;
        }

        opt.set_data(&opt_buffers);
        i += length;
    }

    Ok(())
}

pub fn finish_pkt_icmpv6(buffer: &mut [u8]) {
    // get ipv6 src and dst addr from packet
    let ipv6_pkt = Ipv6Packet::new(&buffer[PKT_ETH_SIZE..]).unwrap();
    let src = ipv6_pkt.get_source();
    let dst = ipv6_pkt.get_destination();
    drop(ipv6_pkt);

    let mut pkt = MutableIcmpv6Packet::new(&mut buffer[PKT_ETH_SIZE + PKT_IPV6_SIZE..]).unwrap();
    pkt.set_checksum(icmpv6::checksum(&pkt.to_immutable(), &src, &dst));
}

pub struct NdpPacket {
    pub mac_src: MacAddr,
    pub ipv6_src: Ipv6Addr,
    pub content: NdpPacketContent,
}

pub enum NdpPacketContent {
    NeighborAdvert {
        target: Ipv6Addr,
        mac_src: Option<MacAddr>,
    },
    RouterAdvert {
        cur_hop_limit: u8,
        managed_address_config: bool,
        other_stateful_config: bool,
        home_agent: bool,
        default_router_preference: u8,
        nd_proxy: bool,
        router_lifetime: u16,
        reachable_time: u32,
        retrans_timer: u32,
        options: Vec<NdpRouterAdvertOption>,
    },
}

pub enum NdpRouterAdvertOption {
    SourceLinkLayerAddress {
        addr: MacAddr,
    },
    Mtu {
        mtu: u32,
    },
    PrefixInformation {
        prefix_length: u8,
        on_link: bool,
        autonomous_addr_config: bool,
        valid_lifetime: u32,
        preferred_lifetime: u32,
        prefix: Ipv6Addr,
    },
    RouteInformation {
        prefix_length: u8,
        route_preference: u8,
        route_lifetime: u32,
        prefix: Ipv6Addr,
    },
    RecursiveDnsServer {
        lifetime: u32,
        addresses: Vec<Ipv6Addr>,
    },
}

pub fn parse_packet(
    buffer: &[u8],
    my_mac: MacAddr,
    mac_multicasts: &[MacAddr],
    ips: &[Ipv6Addr],
) -> Option<NdpPacket> {
    if buffer.len() < PKT_MIN_ICMPV6_SIZE {
        return None;
    }
    let eth_pkt = EthernetPacket::new(buffer).unwrap();
    if eth_pkt.get_ethertype() != EtherTypes::Ipv6 {
        return None;
    }
    let dst_mac = eth_pkt.get_destination();
    if !(dst_mac.is_broadcast()
        || dst_mac == my_mac
        || (dst_mac.is_multicast() && mac_multicasts.contains(&dst_mac)))
    {
        // the packet is not for me
        return None;
    }

    let ipv6_pkt = Ipv6Packet::new(eth_pkt.payload()).unwrap();
    if ipv6_pkt.get_version() != 6 {
        // wtf ???
        return None;
    }

    if !ips.contains(&ipv6_pkt.get_destination()) {
        // the packet is not for me
        return None;
    }

    if ipv6_pkt.get_next_header() != IpNextHeaderProtocols::Icmpv6 {
        // not a icmpv6 packet
        return None;
    }

    let icmpv6_pkt = Icmpv6Packet::new(ipv6_pkt.payload()).unwrap();
    let icmpv6_type = icmpv6_pkt.get_icmpv6_type();
    if icmpv6_type != Icmpv6Types::NeighborAdvert && icmpv6_type != Icmpv6Types::RouterAdvert {
        // not a neighbor advertisment or router advertisment
        return None;
    }
    let checksum = icmpv6::checksum(
        &icmpv6_pkt,
        &ipv6_pkt.get_source(),
        &ipv6_pkt.get_destination(),
    );
    if icmpv6_pkt.get_checksum() != checksum {
        // invalid checksum
        return None;
    }
    drop(icmpv6_pkt);

    let ndp_content = if icmpv6_type == Icmpv6Types::NeighborAdvert {
        let na_pkt = NeighborAdvertPacket::new(ipv6_pkt.payload()).unwrap();
        NdpPacketContent::NeighborAdvert {
            target: na_pkt.get_target_addr(),
            mac_src: na_pkt.get_options().into_iter().find_map(|opt| {
                if opt.option_type == NdpOptionTypes::SourceLLAddr
                    && opt.length == 1
                    && opt.data.len() == 6
                {
                    let c: [u8; 6] = opt.data.try_into().unwrap();
                    Some(c.into())
                } else {
                    None
                }
            }),
        }
    } else {
        // type is RouterAdvert
        let ra_pkt = RouterAdvertPacket::new(ipv6_pkt.payload()).unwrap();
        let options = ra_pkt
            .get_options_iter()
            .filter_map(|opt| {
                let data = opt.payload();
                match opt.get_option_type() {
                    NdpOptionTypes::SourceLLAddr => {
                        if data.len() == 6 {
                            let data: [u8; 6] = data.try_into().unwrap();
                            Some(NdpRouterAdvertOption::SourceLinkLayerAddress {
                                addr: data.into(),
                            })
                        } else {
                            None
                        }
                    }
                    NdpOptionTypes::MTU => {
                        if data.len() == 4 {
                            Some(NdpRouterAdvertOption::Mtu {
                                mtu: u32::from_be_bytes(data.try_into().unwrap()),
                            })
                        } else {
                            None
                        }
                    }
                    NdpOptionTypes::PrefixInformation => {
                        let prefix_len = u8::from_be(data[0]);
                        let flags = u8::from_be(data[1]);
                        let valid_lifetime = u32::from_be_bytes(data[2..6].try_into().unwrap());
                        let preferred_lifetime =
                            u32::from_be_bytes(data[6..10].try_into().unwrap());
                        let ip: [u8; 16] = data[14..30].try_into().unwrap();
                        Some(NdpRouterAdvertOption::PrefixInformation {
                            prefix_length: prefix_len,
                            on_link: flags >> 7 == 1,
                            autonomous_addr_config: (flags >> 6) & 0x01 == 1,
                            valid_lifetime,
                            preferred_lifetime,
                            prefix: ip.into(),
                        })
                    }
                    NdpOptionType(24) => {
                        // Route Information Option
                        let prefix_length = u8::from_be(data[0]);
                        let flags: u8 = u8::from_be(data[1]);
                        let route_lifetime = u32::from_be_bytes(data[2..6].try_into().unwrap());
                        let prefix = if prefix_length == 0 {
                            &[]
                        } else {
                            let prefix_length_octets = (((prefix_length - 1) >> 3) + 1) as usize;
                            &data[6..6 + prefix_length_octets]
                        };
                        let mut prefix = prefix.to_vec();
                        while prefix.len() < 16 {
                            prefix.push(0);
                        }
                        let prefix: [u8; 16] = prefix.try_into().unwrap();
                        Some(NdpRouterAdvertOption::RouteInformation {
                            prefix_length,
                            route_preference: (flags >> 3) & 0x03,
                            route_lifetime,
                            prefix: Ipv6Addr::from(prefix),
                        })
                    }
                    NdpOptionType(25) => {
                        // Recursive DNS Server Option
                        let lifetime = u32::from_be_bytes(data[2..6].try_into().unwrap());
                        let addresses_len = ((opt.get_length() - 1) / 2) as usize;
                        let mut addresses: Vec<Ipv6Addr> = Vec::with_capacity(addresses_len);
                        for i in 0..addresses_len {
                            let ip: [u8; 16] =
                                data[(6 + i * 16)..(22 + i * 16)].try_into().unwrap();
                            addresses.push(ip.into());
                        }
                        Some(NdpRouterAdvertOption::RecursiveDnsServer {
                            lifetime,
                            addresses,
                        })
                    }
                    _ => None,
                }
            })
            .collect::<Vec<_>>();

        let flags = ra_pkt.get_flags();
        NdpPacketContent::RouterAdvert {
            cur_hop_limit: ra_pkt.get_hop_limit(),
            managed_address_config: (flags >> 7) == 1,
            other_stateful_config: (flags >> 6) & 0x01 == 1,
            home_agent: (flags >> 5) & 0x01 == 1,
            default_router_preference: (flags >> 4) & 0x03,
            nd_proxy: (flags >> 3) & 0x01 == 1,
            router_lifetime: ra_pkt.get_lifetime(),
            reachable_time: ra_pkt.get_reachable_time(),
            retrans_timer: ra_pkt.get_retrans_time(),
            options,
        }
    };

    Some(NdpPacket {
        mac_src: eth_pkt.get_source(),
        ipv6_src: ipv6_pkt.get_source(),
        content: ndp_content,
    })
}
