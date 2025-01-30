use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Args {
    pub interface: String,
    #[command(subcommand)]
    pub command: Commands,
    #[arg(
        long,
        default_value_t = 3,
        help = "The program exists after timeout seconds if no neighbor advertisment was found and exits always after timeout seconds if we are searching for router advertisments"
    )]
    pub timeout: u64,
}

#[derive(Subcommand)]
pub enum Commands {
    NeighborSolicitation { target: String },
    RouterSolicitation,
    RouterAdvertisment(RouterAdvertiseArgs),
}

#[derive(clap::Args)]
pub struct RouterAdvertiseArgs {
    pub target: String,
    pub config_file: String,
}
