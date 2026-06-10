use std::process::Command;

use anyhow::{Context, Result};
use clap::Parser;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Option<BuildCommand>,
}

#[derive(clap::Subcommand)]
enum BuildCommand {
    /// Build eBPF programs
    BuildEbpf,
    /// Build userspace binary
    BuildAgent,
    /// Build CNI plugin
    BuildCni,
    /// Build everything
    All,
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.command.unwrap_or(BuildCommand::All) {
        BuildCommand::BuildEbpf => build_ebpf()?,
        BuildCommand::BuildAgent => build_agent()?,
        BuildCommand::BuildCni => build_cni()?,
        BuildCommand::All => {
            build_ebpf()?;
            build_agent()?;
            build_cni()?;
        }
    }
    Ok(())
}

fn build_ebpf() -> Result<()> {
    println!("building eBPF programs...");
    let status = Command::new("cargo")
        .args([
            "build", "--package", "nomad-p2p-ebpf",
            "--target", "bpfel-unknown-none",
            "--release",
            "-Z", "build-std=core",
        ])
        .status()
        .context("build eBPF")?;
    if !status.success() {
        anyhow::bail!("eBPF build failed");
    }
    // Copy .o files to bin/
    let _ = std::fs::create_dir_all("bin");
    let src = "target/bpfel-unknown-none/release/nomad-p2p-ebpf";
    let dst = "bin/mesh.bpf.o";
    match std::fs::copy(src, dst) {
        Ok(_) => println!("copied {} -> {}", src, dst),
        Err(e) => println!("copy failed: {}", e),
    }
    // Also install the combined .o files for each BPF program
    // (In a full setup, xtask would split the ELF sections into separate .o files)
    // For now, mesh.bpf.o contains all programs (classifier + cgroup_connect4 + xdp)
    Ok(())
}

fn build_agent() -> Result<()> {
    println!("building agent...");
    let status = Command::new("cargo")
        .args(["build", "--package", "nomad-p2p-agent", "--release"])
        .status()
        .context("build agent")?;
    if !status.success() {
        anyhow::bail!("agent build failed");
    }
    Ok(())
}

fn build_cni() -> Result<()> {
    println!("building CNI plugin...");
    let status = Command::new("cargo")
        .args(["build", "--package", "nomad-p2p-cni", "--release"])
        .status()
        .context("build cni")?;
    if !status.success() {
        anyhow::bail!("CNI build failed");
    }
    Ok(())
}
