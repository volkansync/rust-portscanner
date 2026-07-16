# rust-portscanner

Foundation project for the Rust track — offensive security / embedded branch. First real contact with ownership, borrowing, and error handling, through something that's actually useful when it's done.

Progress notes go in [learning-log](https://github.com/volkansync/learning-log/tree/main/rust). Bigger picture: [volkansync/volkansync](https://github.com/volkansync/volkansync).

## stages

- [ ] **1 — sequential scan**: connect to a port range on a target, one at a time, `Result`/`Option` for every failure mode
- [ ] **2 — concurrent scan**: `std::thread`, shared state across threads without fighting the borrow checker
- [ ] **3 — async**: rewrite the scan loop on `tokio`
- [ ] **4 — banner grabbing**: pull and parse service banners from open ports
- [ ] **5 — fingerprinting**: flag likely-outdated service versions against a small known-vulnerable list

Currently: stage 1, not started.
