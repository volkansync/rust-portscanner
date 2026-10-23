use std::str::FromStr;

use anyhow::{anyhow, bail, Result};

/// A parsed port specification: `22`, `1-1000`, `22,80,443`, or any mix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSpec {
    ranges: Vec<PortRange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PortRange {
    start: u16,
    end: u16,
}

impl PortSpec {
    /// Sorts and merges overlapping or adjacent ranges so every port is visited once.
    fn new(mut ranges: Vec<PortRange>) -> Self {
        ranges.sort_by_key(|r| (r.start, r.end));

        let mut merged: Vec<PortRange> = Vec::with_capacity(ranges.len());
        for range in ranges {
            match merged.last_mut() {
                Some(last) if range.start <= last.end.saturating_add(1) => {
                    last.end = last.end.max(range.end);
                }
                _ => merged.push(range),
            }
        }

        PortSpec { ranges: merged }
    }

    /// The 100 most commonly open TCP ports, in numeric order.
    pub fn top_ports() -> Self {
        PortSpec::new(
            TOP_100_TCP
                .iter()
                .map(|&p| PortRange { start: p, end: p })
                .collect(),
        )
    }

    pub fn iter(&self) -> impl Iterator<Item = u16> + '_ {
        self.ranges.iter().flat_map(|r| r.start..=r.end)
    }

    pub fn count(&self) -> usize {
        self.ranges
            .iter()
            .map(|r| r.end as usize - r.start as usize + 1)
            .sum()
    }
}

impl FromStr for PortSpec {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut ranges = Vec::new();

        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            ranges.push(part.parse::<PortRange>()?);
        }

        if ranges.is_empty() {
            bail!("port specification is empty");
        }

        Ok(PortSpec::new(ranges))
    }
}

impl FromStr for PortRange {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.split_once('-') {
            None => {
                let port = parse_port(s)?;
                Ok(PortRange { start: port, end: port })
            }
            Some((lo, hi)) => {
                let start = parse_port(lo.trim())?;
                let end = parse_port(hi.trim())?;
                if start > end {
                    bail!("port range {s:?} is inverted: {start} > {end}");
                }
                Ok(PortRange { start, end })
            }
        }
    }
}

fn parse_port(s: &str) -> Result<u16> {
    if s.is_empty() {
        bail!("expected a port number, found an empty field");
    }

    let port: u16 = s
        .parse()
        .map_err(|_| anyhow!("{s:?} is not a valid port (expected 1-65535)"))?;

    if port == 0 {
        bail!("port 0 is not scannable");
    }

    Ok(port)
}

const TOP_100_TCP: [u16; 100] = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53,
    79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
    139, 143, 144, 179, 199, 389, 427, 443, 444, 445,
    465, 513, 514, 515, 543, 544, 548, 554, 587, 631,
    646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029,
    1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121,
    2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
    5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
    6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888,
    9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_port() {
        let spec: PortSpec = "22".parse().unwrap();
        assert_eq!(spec.iter().collect::<Vec<_>>(), vec![22]);
    }

    #[test]
    fn merges_overlapping_ranges() {
        let spec: PortSpec = "80-90,85-100,443".parse().unwrap();
        assert_eq!(spec.count(), 22);
        assert_eq!(spec.iter().next(), Some(80));
    }

    #[test]
    fn rejects_inverted_range() {
        assert!("100-20".parse::<PortSpec>().is_err());
    }

    #[test]
    fn rejects_port_zero() {
        assert!("0".parse::<PortSpec>().is_err());
    }

    #[test]
    fn top_ports_keeps_all_hundred() {
        let spec = PortSpec::top_ports();
        assert_eq!(spec.count(), 100);

        let mut ports: Vec<u16> = spec.iter().collect();
        let before = ports.len();
        ports.dedup();
        assert_eq!(before, ports.len(), "iter() yielded duplicates");
    }
}
