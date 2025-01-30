use std::net::Ipv6Addr;

use pnet::util::MacAddr;

pub const IPV6_MULTICAST_ALL: Ipv6Addr =
    Ipv6Addr::new(0xff02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0001);
pub const IPV6_MULTICAST_ROUTERS: Ipv6Addr =
    Ipv6Addr::new(0xff02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0002);
pub const MAC_MULTICAST_ALL_IPV6: MacAddr = MacAddr(0x33, 0x33, 0x0, 0x0, 0x0, 0x01);
pub const MAC_MULTICAST_IPV6_ROUTERS: MacAddr = MacAddr(0x33, 0x33, 0x0, 0x0, 0x0, 0x02);

pub fn ipv6_to_multicast(ip: &Ipv6Addr) -> Ipv6Addr {
    let segs = ip.segments();
    let multicast: [u16; 8] = [
        0xff02,
        0x0,
        0x0,
        0x0,
        0x0,
        0x0001,
        0xff00 | segs[6],
        segs[7],
    ];
    multicast.into()
}

pub fn ipv6_multicast_into_mac_multicast(ip: &Ipv6Addr) -> MacAddr {
    let octs = ip.octets();
    let multicast: [u8; 6] = [0x33, 0x33, 0xff, octs[13], octs[14], octs[15]];
    multicast.into()
}
