mod cli;
mod ports;
mod target;

use std::time::Duration;

use anyhow::Result;
use clap::Parser;

use crate::cli::Cli;

/// Refuse to expand anything larger than this until the scan engine can stream.
const MAX_HOSTS: u128 = 65_536;

fn main() -> Result<()> {
    let cli = Cli::parse();
    let ports = cli.port_spec();
    let timeout = Duration::from_millis(cli.timeout_ms);

    let preview: Vec<String> = ports.iter().take(6).map(|p| p.to_string()).collect();
    let elision = if ports.count() > preview.len() { ", ..." } else { "" };

    println!("nazar scan plan");
    println!(
        "  ports:   {} [{}{}]",
        ports.count(),
        preview.join(", "),
        elision
    );
    println!("  timeout: {timeout:?} per port");
    println!();

    let mut total_probes: u128 = 0;

    for spec in &cli.targets {
        let approx = spec.approx_host_count();
        if approx > MAX_HOSTS {
            anyhow::bail!(
                "{} expands to ~{} hosts, over the current limit of {}",
                spec.raw(),
                approx,
                MAX_HOSTS
            );
        }

        let hosts = spec.resolve()?;
        total_probes += hosts.len() as u128 * ports.count() as u128;

        println!("  {} -> {} host(s)", spec.raw(), hosts.len());
        for host in hosts.iter().take(4) {
            match &host.hostname {
                Some(name) => println!("      {} ({name})", host.addr),
                None => println!("      {}", host.addr),
            }
        }
        if hosts.len() > 4 {
            println!("      ... and {} more", hosts.len() - 4);
        }
    }

    println!();
    println!("  {total_probes} probe(s) queued — the scan engine lands in block 2");

    Ok(())
}
