//! `nanodhcp` — a minimal DHCPv4 server for a single LAN.
//!
//! `main` only parses the command line and dispatches; all protocol and policy
//! logic lives in the modules below.

mod config;
mod dhcp;
mod lease;
mod server;
mod util;

use std::process::ExitCode;

use crate::lease::model::{Lease, LeaseKind};
use crate::lease::LeaseStore;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match dispatch(&args) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("nanodhcp: {}", msg);
            ExitCode::FAILURE
        }
    }
}

fn dispatch(args: &[String]) -> Result<ExitCode, String> {
    let first = match args.first() {
        Some(a) => a.as_str(),
        None => {
            print_help();
            return Ok(ExitCode::FAILURE);
        }
    };

    match first {
        "help" | "-h" | "--help" => {
            print_help();
            Ok(ExitCode::SUCCESS)
        }
        "run" => cmd_run(&config_path(&args[1..])?),
        "check" => cmd_check(&config_path(&args[1..])?),
        "leases" => cmd_leases(&config_path(&args[1..])?),
        // A bare argument is treated as a config path: `nanodhcp <config>`.
        path => cmd_run(path),
    }
}

/// Extract the value of `-c`/`--config` from the remaining arguments.
fn config_path(rest: &[String]) -> Result<String, String> {
    match rest.first().map(|s| s.as_str()) {
        Some("-c") | Some("--config") => rest
            .get(1)
            .cloned()
            .ok_or_else(|| "option -c requires a path".to_string()),
        Some(other) => Err(format!("unexpected argument '{}', expected -c <config>", other)),
        None => Err("missing -c <config>".to_string()),
    }
}

fn cmd_run(path: &str) -> Result<ExitCode, String> {
    let cfg = config::load(path)?;
    server::daemon::run(cfg).map_err(|e| format!("fatal: {}", e))?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_check(path: &str) -> Result<ExitCode, String> {
    match config::load(path) {
        Ok(_) => {
            println!("nanodhcp: config OK ({})", path);
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            eprintln!("nanodhcp: config error in {}:\n{}", path, e);
            Ok(ExitCode::FAILURE)
        }
    }
}

fn cmd_leases(path: &str) -> Result<ExitCode, String> {
    let cfg = config::load(path)?;
    let store = LeaseStore::load(&cfg.lease_file);

    // Present static bindings and dynamic leases in one IP-sorted table.
    let mut all: Vec<Lease> = Vec::new();
    for s in &cfg.statics {
        all.push(Lease {
            mac: s.mac,
            ip: s.ip,
            hostname: Some(s.name.clone()),
            expires_at: 0,
            kind: LeaseKind::Static,
        });
    }
    all.extend(store.iter().cloned());
    all.sort_by_key(|l| u32::from(l.ip));

    if all.is_empty() {
        println!("nanodhcp: no leases (lease file {})", cfg.lease_file);
        return Ok(ExitCode::SUCCESS);
    }

    println!("{:<8} {:<17} {:<15} {:<16} {}", "KIND", "MAC", "IP", "NAME/HOST", "EXPIRES");
    for l in &all {
        let expires = if l.expires_at == 0 {
            "-".to_string()
        } else {
            l.expires_at.to_string()
        };
        println!(
            "{:<8} {:<17} {:<15} {:<16} {}",
            l.kind.label(),
            l.mac,
            l.ip,
            l.hostname_str(),
            expires
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn print_help() {
    println!(
        "nanodhcp {} — minimal DHCPv4 server

USAGE:
    nanodhcp run    -c <config>   start the server (needs root for udp/67)
    nanodhcp check  -c <config>   parse and validate the config, then exit
    nanodhcp leases -c <config>   print static and dynamic leases
    nanodhcp help                 show this help

    nanodhcp <config>             alias for 'run -c <config>'",
        env!("CARGO_PKG_VERSION")
    );
}
