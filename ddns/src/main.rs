use clap::Parser;
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

    /// Update ipv4 address.
    #[clap(short = '4', long)]
    ipv4: bool,

    /// Update ipv6 address.
    #[clap(short = '6', long)]
    ipv6: bool,

    /// Which subdomain to update, if any.
    // 'w' is for www, meaning you can do `ddns -wwww example.com`
    #[clap(short = 'w', long)]
    subdomain: Option<String>,

    /// Domain to update.
    #[clap(value_parser, value_name = "PATH")]
    domain: String,
}

fn main() {
    let config = Cli::parse();
    tracing_subscriber::fmt::init();

    let client = porkbun::Client::open_keys(&config.key).unwrap_or_else(|msg| {
        error!("failed to open key file ({}): {msg}", config.key.display());
        exit(1);
    });

    let record_name = config
        .subdomain
        .as_deref()
        .unwrap_or(config.domain.as_ref());

    let mut error_count = 0;

    if config.ipv4 && !update_ipv4(&client, &config, record_name) {
        error_count += 1;
    }

    if config.ipv6 && !update_ipv6(&client, &config, record_name) {
        error_count += 1;
    }

    exit(error_count);
}

fn update_ipv6(client: &porkbun::Client, config: &Cli, record_name: &str) -> bool {
    let ip_address = match client.ping_ipv6() {
        Ok(Some(address)) => address,
        Ok(None) => {
            error!("ipv6 address is not present");
            return false;
        }
        Err(msg) => {
            error!("failed to retreive public ipv6 address: {msg}");
            return false;
        }
    };

    match client
        .fetch_ipv6_records(&config.domain, config.subdomain.as_deref())
        .map(|records| {
            records
                .iter()
                .find(|x| x.name == record_name)
                .map(|x| x.address == ip_address)
        }) {
        Ok(Some(true)) => {
            if !config.silent {
                info!("current ipv6 record matches public ip address");
            }
            true
        }
        Ok(Some(false)) => {
            if let Err(msg) =
                client.edit_ipv6_address(&config.domain, config.subdomain.as_deref(), &ip_address)
            {
                error!("failed to edit ipv6 address: {msg}");
                return false;
            } else if !config.silent {
                info!("successfully updated ipv6 record to {ip_address}");
            }
            true
        }
        Ok(None) => {
            if let Err(msg) = client.create_record(
                &config.domain,
                config.subdomain.as_deref(),
                porkbun::RecordType::Aaaa,
                &ip_address.to_string(),
                None,
                None,
            ) {
                error!("failed to create ipv6 record: {msg}");
                return false;
            } else if !config.silent {
                info!("successfully created ipv6 record: {ip_address}");
            }
            true
        }
        Err(msg) => {
            error!("failed to retrieve previous ipv6 address: {msg}");
            false
        }
    }
}

fn update_ipv4(client: &porkbun::Client, config: &Cli, record_name: &str) -> bool {
    let ip_address = match client.ping_ipv4() {
        Ok(Some(address)) => address,
        Ok(None) => {
            error!("ipv4 address is not present");
            return false;
        }
        Err(msg) => {
            error!("failed to retreive public ipv4 address: {msg}");
            return false;
        }
    };

    match client
        .fetch_ipv4_records(&config.domain, config.subdomain.as_deref())
        .map(|records| {
            records
                .iter()
                .find(|x| x.name == record_name)
                .map(|x| x.address == ip_address)
        }) {
        Ok(Some(true)) => {
            if !config.silent {
                info!("current ipv4 record matches public ip address");
            }
            true
        }
        Ok(Some(false)) => {
            if let Err(msg) =
                client.edit_ipv4_address(&config.domain, config.subdomain.as_deref(), &ip_address)
            {
                error!("failed to edit ipv4 address: {msg}");
                return false;
            } else if !config.silent {
                info!("successfully updated ipv4 record to {ip_address}");
            }
            true
        }
        Ok(None) => {
            if let Err(msg) = client.create_record(
                &config.domain,
                config.subdomain.as_deref(),
                porkbun::RecordType::Aaaa,
                &ip_address.to_string(),
                None,
                None,
            ) {
                error!("failed to create ipv4 record: {msg}");
                return false;
            } else if !config.silent {
                info!("successfully created ipv4 record: {ip_address}");
            }
            true
        }
        Err(msg) => {
            error!("failed to retrieve previous ipv4 address: {msg}");
            false
        }
    }
}
