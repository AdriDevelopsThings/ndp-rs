use std::{
    fs::read_to_string,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use args::{Args, Commands};
use clap::Parser;
use interface::{get_interface, InterfaceInformation};
use multicast::{
    ipv6_multicast_into_mac_multicast, ipv6_to_multicast, IPV6_MULTICAST_ALL,
    IPV6_MULTICAST_ROUTERS, MAC_MULTICAST_ALL_IPV6, MAC_MULTICAST_IPV6_ROUTERS,
};
use packet::{
    finish_pkt_icmpv6, parse_packet, prepare_buffer, prepare_pkt_eth, prepare_pkt_ipv6,
    prepare_pkt_ndp_neighbor_solicitation, prepare_pkt_ndp_router_advertisment,
    prepare_pkt_ndp_router_solicitation, NdpPacketContent,
};
use pnet::datalink::{self, Channel};
use ra_config::RouterAdvertismentConfig;

mod args;
mod display;
mod interface;
mod multicast;
mod packet;
mod ra_config;

fn main() -> Result<()> {
    let args = Args::parse();
    let InterfaceInformation {
        interface,
        link_local_addr,
        ips,
    } = get_interface(args.interface)?;
    let mac = interface
        .mac
        .context("Interface does not have a mac addr")?;

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default())? {
        Channel::Ethernet(tx, rx) => Ok((tx, rx)),
        _ => Err(anyhow!("Unsupported channel type on interface")),
    }?;

    // target_multicast is the multicast ipv6 addr that includes the target
    // target is the target ipv6 address (not relevant if command is router solicitation)
    // dst_mac is the destination multicast mac address
    let (target_multicast, target, dst_mac) = match &args.command {
        Commands::NeighborSolicitation { target: target_s } => {
            let target = target_s
                .parse()
                .with_context(|| format!("Target ipv6 address '{target_s}' seems to be invalid"))?;
            // ipv6 solicited-node multicast address ff02::1:ffXX:XXXX
            // X are last 3 bytes of the ipv6 address
            let multicast = ipv6_to_multicast(&target);
            (
                multicast,
                target,
                ipv6_multicast_into_mac_multicast(&multicast),
            )
        }
        Commands::RouterSolicitation => {
            // ipv6 router multicast is ff02::2
            (
                IPV6_MULTICAST_ROUTERS,
                IPV6_MULTICAST_ROUTERS,
                MAC_MULTICAST_IPV6_ROUTERS,
            )
        }
        Commands::RouterAdvertisment(args) => {
            let target = args.target.parse().with_context(|| {
                format!("Target ipv6 address '{}' seems to be invalid", args.target)
            })?;
            let multicast = ipv6_to_multicast(&target);
            (
                target,
                target,
                ipv6_multicast_into_mac_multicast(&multicast),
            )
        }
    };

    let ra_config = match &args.command {
        Commands::RouterAdvertisment(args) => {
            let content = read_to_string(&args.config_file)
                .context("Error while reading router advertisment config file")?;
            let config: RouterAdvertismentConfig =
                toml::from_str(&content).context("Error while parsing toml file")?;
            Some(config)
        }
        _ => None,
    };

    let mut buffer = prepare_buffer(&args.command, &ra_config);
    prepare_pkt_eth(&mut buffer, mac, dst_mac);
    prepare_pkt_ipv6(&mut buffer, link_local_addr, target_multicast);
    match &args.command {
        Commands::NeighborSolicitation { .. } => {
            prepare_pkt_ndp_neighbor_solicitation(&mut buffer, mac, target);
        }
        Commands::RouterSolicitation => {
            prepare_pkt_ndp_router_solicitation(&mut buffer, mac);
        }
        Commands::RouterAdvertisment(args) => {
            let content = read_to_string(&args.config_file)
                .context("Error while reading router advertisment config file")?;
            let config: RouterAdvertismentConfig =
                toml::from_str(&content).context("Error while parsing toml file")?;
            prepare_pkt_ndp_router_advertisment(&mut buffer, &config, mac)?;
        }
    };
    finish_pkt_icmpv6(&mut buffer);
    tx.send_to(&buffer, None);

    if matches!(args.command, Commands::RouterAdvertisment(_)) {
        return Ok(());
    }

    let mut multicast_ips = ips.iter().map(ipv6_to_multicast).collect::<Vec<_>>();
    multicast_ips.insert(0, IPV6_MULTICAST_ALL);

    let mut multicast_macs = multicast_ips
        .iter()
        .map(ipv6_multicast_into_mac_multicast)
        .collect::<Vec<_>>();
    multicast_macs.push(MAC_MULTICAST_ALL_IPV6);

    let mut target_ips = ips;
    target_ips.extend(multicast_ips);

    let timeout_duration = Duration::from_secs(args.timeout);
    let start = Instant::now();

    while start.elapsed() < timeout_duration {
        let pkt = rx
            .next()
            .context("Error while getting next ethernet frame")?;
        if let Some(pkt) = parse_packet(pkt, mac, &multicast_macs, &target_ips) {
            if matches!(pkt.content, NdpPacketContent::NeighborAdvert { .. })
                && pkt.ipv6_src != target
            {
                // this is not the neighbor advert I search for
                continue;
            }
            println!("{pkt}\n");
            if matches!(pkt.content, NdpPacketContent::NeighborAdvert { .. }) {
                // We search for just one neighbor advert packet
                break;
            }
        }
    }
    Ok(())
}
