# ndp-rs
A Network Discovery Protocol cli written in Rust.

## Installation
Build with `cargo build --release` or install with `cargo install --git https://github.com/adridevelopsthings/ndp-rs`.

## Usage
```
Usage: ndp-rs [OPTIONS] <INTERFACE> <COMMAND>

Commands:
  neighbor-solicitation  
  router-solicitation    
  router-advertisment    
  help                   Print this message or the help of the given subcommand(s)

Arguments:
  <INTERFACE>  

Options:
      --timeout <TIMEOUT>  The program exists after timeout seconds if no neighbor advertisment was found and exits always after timeout seconds if we are searching for router advertisments [default: 3]
  -h, --help               Print help
  -V, --version            Print version
```

### Neighbor Solicitation
```
ndp-rs <INTERFACE> neighbor-solicitation <TARGET>
```
Target must be the ipv6 address which should receive this packet.

### Router Solicitation
```
ndp-rs <INTERFACE> router-solicitation
```

### Router Advertisment
Advertise a router using a toml configuration. Create a toml file that looks like the [ra.example.toml](ra.example.toml) file. Take a look to the [ra_config.rs](src/ra_config.rs) file, if you know how read rust code, to get more information.
```
ndp-rs <INTERFACE> router-advertisment <TARGET> <CONFIG_FILE>
```
Target must be the ipv6 address which should receive this packet. If you want to send this packet to multiple or all nodes use a ipv6 multicast address like `ff02::1` (All nodes in network). Config file must be the path to the config toml file.