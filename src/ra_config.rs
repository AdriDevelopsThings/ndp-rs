use serde::Deserialize;

fn default_zero_u8() -> u8 {
    0
}
fn default_zero_u16() -> u16 {
    0
}
fn default_zero_u32() -> u32 {
    0
}
fn default_false() -> bool {
    false
}

#[derive(Deserialize)]
pub struct RouterAdvertismentConfig {
    #[serde(default = "default_zero_u8")]
    pub cur_hop_limit: u8,
    #[serde(default = "default_false")]
    pub managed_address_configuration: bool,
    #[serde(default = "default_false")]
    pub other_stateful_configuration: bool,
    #[serde(default = "default_false")]
    pub home_agent: bool,
    #[serde(default = "default_zero_u8")]
    pub default_router_preference: u8,
    #[serde(default = "default_false")]
    pub nd_proxy: bool,
    #[serde(default = "default_zero_u16")]
    pub router_lifetime: u16,
    #[serde(default = "default_zero_u32")]
    pub reachable_time: u32,
    #[serde(default = "default_zero_u32")]
    pub retrans_timer: u32,
    #[serde(default)]
    pub prefix: Vec<PrefixInformation>,
    #[serde(default)]
    pub mtu: Vec<Mtu>,
    #[serde(default)]
    pub route: Vec<RouteInformation>,
    #[serde(default)]
    pub dns_server: Vec<RecursiveDnsServer>,
}

#[derive(Deserialize)]
pub struct PrefixInformation {
    #[serde(default = "default_false")]
    pub on_link: bool,
    #[serde(default = "default_false")]
    pub autonomous_address_configuration: bool,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    pub prefix: String,
}
#[derive(Deserialize)]
pub struct Mtu {
    pub mtu: u32,
}

#[derive(Deserialize)]
pub struct RouteInformation {
    #[serde(default = "default_zero_u8")]
    pub preference: u8,
    pub lifetime: u32,
    pub prefix: String,
}

#[derive(Deserialize)]
pub struct RecursiveDnsServer {
    pub lifetime: u32,
    pub addresses: Vec<String>,
}
