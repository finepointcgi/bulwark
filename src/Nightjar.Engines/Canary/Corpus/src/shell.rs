// Canary: dynamic shell command.
use std::process::Command;
fn run(x: &str) { Command::new("sh").arg("-c").arg(x).status(); }
