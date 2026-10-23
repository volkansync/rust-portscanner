# nazar

A TCP port scanner in Rust that shows its receipts.

> **Status: early.** Block 1 of 13 is done — target/port parsing and the CLI.
> The scan engine itself lands in block 2. Nothing here sends packets yet.

---

## Why another port scanner?

Honestly: you will not beat `masscan` on raw speed — it ships its own userland
TCP stack and fires stateless SYNs at line rate. You will not beat `nmap` on
breadth — NSE, 2000+ service probes, and twenty-five years of accumulated data.

So "better" has to mean better at something those tools are actually weak at.
There is one such gap, and it is a real one:

**Nobody tells you how much to trust the result.**

When a probe gets no reply, that silence is ambiguous. It could be a firewall
dropping the packet, congestion losing it, the target rate-limiting you because
you scanned too fast, or simply a slow host and a short timeout. Existing
scanners collapse all of that into `filtered` and move on. Scan aggressively and
you quietly collect false negatives — open ports reported as closed. You get no
signal that it happened.

That is the problem `nazar` is built around:

| Where existing tools fall short | What `nazar` aims to do |
| --- | --- |
| Packet loss silently becomes a false negative | **Confidence score** per port, with an explicit `unknown` state |
| `-T4` is the operator guessing at a rate | **Closed-loop rate control** that tunes itself from RTT, loss, and ICMP rate-limit signals |
| `--reason` says `no-response` and stops there | **Evidence trail**: probe sent, bytes returned, retries, RTT distribution |
| Change detection is a cron job wrapped around `ndiff` | Native **snapshot + diff** — attack-surface monitoring built in |
| XML is painful, grepable output is lossy | **Streaming NDJSON** with a versioned schema, pipes straight into `jq` |
| `ssl-cert` is a script you have to remember to run | TLS as a first-class citizen: cert chain, SANs feeding **hostname discovery** |

The positioning in one line: **not the fastest scanner — the most trustworthy
one.** A scanner that admits what it does not know beats one that guesses wrong.

---

## What works today

Target and port specifications are parsed and validated into a scan plan.
Overlapping port ranges are merged, so no port is ever probed twice.

```console
$ nazar 10.0.0.0/30 192.168.1.1 -p 1-100,443
nazar scan plan
  ports:   101 [1, 2, 3, 4, 5, 6, ...]
  timeout: 1.5s per port

  10.0.0.0/30 -> 2 host(s)
      10.0.0.1
      10.0.0.2
  192.168.1.1 -> 1 host(s)
      192.168.1.1

  303 probe(s) queued — the scan engine lands in block 2
```

Bad input is rejected before anything touches the network:

```console
$ nazar 127.0.0.1 -p 100-20
error: invalid value '100-20' for '--ports <SPEC>': port range "100-20" is inverted: 100 > 20

$ nazar 10.0.0.0/8 -p 80
Error: 10.0.0.0/8 expands to ~16777214 hosts, over the current limit of 65536
```

Exit codes: `0` success, `1` runtime error, `2` invalid arguments.

---

## Roadmap

Each block is one self-contained commit.

- [x] **1 — CLI and parsing** · IP/CIDR/hostname targets, port specs with range merging
- [ ] **2 — Sequential connect scan** · real TCP handshakes, `Open`/`Closed`/`Filtered`/`Unknown`
- [ ] **3 — Evidence trail** · every verdict records how it was reached
- [ ] **4 — Thread pool** · `std::thread`, channels, shared state
- [ ] **5 — Async rewrite** · `tokio`, bounded concurrency
- [ ] **6 — Adaptive rate control** · AIMD controller driven by observed RTT and loss
- [ ] **7 — Confidence scoring** · probabilistic verdicts, adaptive re-probing
- [ ] **8 — NDJSON output** · versioned, streaming, pipeline-friendly
- [ ] **9 — Service probes** · HTTP, SSH, SMTP, Redis, MySQL banner dialogue
- [ ] **10 — TLS intelligence** · certificate chain, SAN extraction, hostname discovery
- [ ] **11 — Snapshot and diff** · track how an attack surface changes over time
- [ ] **12 — Polish** · progress reporting, CI, release profile
- [ ] **13 — Raw SYN scan** · half-open scanning behind `CAP_NET_RAW`

---

## Build

Requires a recent stable Rust toolchain.

```bash
git clone https://github.com/volkansync/rust-portscanner
cd rust-portscanner
cargo build --release
./target/release/nazar --help
```

Run the tests with `cargo test`.

## Usage

```
Usage: nazar [OPTIONS] <TARGET>...

Arguments:
  <TARGET>...  What to scan: an IP, a CIDR block, or a hostname. Repeatable

Options:
  -p, --ports <SPEC>     Ports to scan: `22`, `1-1000`, `22,80,443`, or any mix
      --top-ports        Scan the 100 most common TCP ports instead of a custom spec
      --timeout-ms <MS>  How long to wait on a single port before giving up [default: 1500]
  -h, --help             Print help
  -V, --version          Print version
```

With no port flag, the 100 most commonly open TCP ports are scanned — fast and
useful by default, with `-p 1-65535` available when you need to be thorough.

---

## Legal

Scan only hosts you own or have written authorisation to test. Unauthorised
port scanning is a criminal offence in many jurisdictions and a contract
violation in most others. `scanme.nmap.org` is maintained by the nmap project
as an explicitly permitted scanning target, and your own machines are always
fair game.

This tool is built for defensive security work, authorised penetration testing,
and learning.

## License

MIT — see [LICENSE](LICENSE).

---

## About this project

This is the foundation project of my Rust track, on the offensive-security and
embedded branch. It is deliberately built in public, one block at a time, as
first real contact with ownership, borrowing, and error handling — through
something that is genuinely useful once it is finished.

Progress notes live in [learning-log](https://github.com/volkansync/learning-log/tree/main/rust).
Bigger picture: [volkansync/volkansync](https://github.com/volkansync/volkansync).
