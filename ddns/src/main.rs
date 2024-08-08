use clap::Parser;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::exit;
use tracing::{error, info};

#[derive(clap::Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Path to the porkbun api key file.
    #[clap(short, long, value_parser, value_name = "PATH")]
    key: PathBuf,

    /// Silence successful log messages.
    #[clap(short, long)]
    silent: bool,

    /// Which subdomain to update, if any.
    // 'w' is for www, meaning you can do `ddns -wwww example.com`
    #[clap(short = 'w', long)]
    subdomain: Option<String>,

    /// Domain to update.
    #[clap(value_parser, value_name = "PATH")]
    domain: String,
}

fn matches_previous_ipv4(
    client: &porkbun::Client,
    config: &Cli,
    address: &Ipv4Addr,
) -> porkbun::Result<Option<bool>> {
    let ipv4_records = client.fetch_ipv4_records(&config.domain, config.subdomain.as_deref())?;

    let name = config
        .subdomain
        .as_deref()
        .unwrap_or(config.domain.as_ref());

    if let Some(previous_ip) = ipv4_records.iter().find(|x| x.name == name) {
        if previous_ip.address == *address {
            Ok(Some(true))
        } else {
            Ok(Some(false))
        }
    } else {
        Ok(None)
    }
}

fn main() {
    let config = Cli::parse();
    tracing_subscriber::fmt::init();

    // TODO: Config (keyfile path + domain name)
    let client = porkbun::Client::open_keys(&config.key).unwrap_or_else(|msg| {
        error!("failed to open key file: {msg}");
        exit(1);
    });
    let Some(ip_address) = client.ping_ipv4().unwrap_or_else(|msg| {
        error!("failed to retreive public ipv4 address: {msg}");
        exit(1);
    }) else {
        error!("ip address is not present; quitting");
        exit(1);
    };

    match matches_previous_ipv4(&client, &config, &ip_address) {
        Ok(Some(true)) => {
            if !config.silent {
                info!("current ipv4 record matches public ip address");
            }
            exit(0);
        }
        Ok(Some(false)) => {
            if let Err(msg) =
                client.edit_ipv4_address(&config.domain, config.subdomain.as_deref(), &ip_address)
            {
                error!("failed to edit ipv4 address: {msg}");
                exit(1);
            } else if !config.silent {
                info!("successfully updated ipv4 record to {ip_address}");
            }
        }
        Ok(None) => {
            if let Err(msg) = client.create_record(
                &config.domain,
                config.subdomain.as_deref(),
                porkbun::RecordType::A,
                &ip_address.to_string(),
                None,
                None,
            ) {
                error!("failed to create ipv4 record: {msg}");
                exit(1);
            } else if !config.silent {
                info!("successfully created ipv4 record: {ip_address}");
            }
        }
        Err(msg) => {
            error!("failed to retrieve previous ip address: {msg}");
        }
    }
}
