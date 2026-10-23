use clap::Parser;

use crate::ports::PortSpec;
use crate::target::TargetSpec;

/// A port scanner that shows its receipts.
#[derive(Debug, Parser)]
#[command(name = "nazar", version, about)]
pub struct Cli {
    /// What to scan: an IP, a CIDR block, or a hostname. Repeatable.
    #[arg(required = true, value_name = "TARGET")]
    pub targets: Vec<TargetSpec>,

    /// Ports to scan: `22`, `1-1000`, `22,80,443`, or any mix.
    #[arg(short, long, value_name = "SPEC", conflicts_with = "top_ports")]
    pub ports: Option<PortSpec>,

    /// Scan the 100 most common TCP ports instead of a custom spec.
    #[arg(long)]
    pub top_ports: bool,

    /// How long to wait on a single port before giving up.
    #[arg(long, default_value = "1500", value_name = "MS")]
    pub timeout_ms: u64,
}

impl Cli {
    /// The port set to scan. With no flags at all, the top-100 list is the default.
    pub fn port_spec(&self) -> PortSpec {
        if self.top_ports {
            return PortSpec::top_ports();
        }

        match &self.ports {
            Some(spec) => spec.clone(),
            None => PortSpec::top_ports(),
        }
    }
}
