use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use clap::Parser;
use tokio::fs;
use tracing_subscriber::EnvFilter;

use nomad_p2p_agent::*;

#[derive(Parser)]
#[command(name = "nomad-p2p-agent", about = "eBPF P2P CNI agent for Nomad", version = "0.4.0")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Start control plane agent
    Agent {
        #[arg(short, long, default_value = "/etc/nomad-p2p/config.json")]
        config: String,
    },
    /// Start seed-mode agent (also acts as route registry)
    Seed {
        #[arg(short, long, default_value = "/etc/nomad-p2p/config.json")]
        config: String,
    },
    /// CNI plugin (called by Nomad)
    Cni,
    /// Print version
    Version,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env()
            .add_directive(tracing::Level::INFO.into()))
        .init();

    let cli = Cli::parse();
    let cmd = cli.command.unwrap_or(Command::Agent { config: "/etc/nomad-p2p/config.json".into() });

    match cmd {
        Command::Agent { config } | Command::Seed { config } => {
            let seed_mode = matches!(cmd, Command::Seed { .. });
            run_agent(&config, seed_mode).await?;
        }
        Command::Cni => {
            run_cni().await?;
        }
        Command::Version => {
            println!("nomad-p2p v0.4.0");
        }
    }

    Ok(())
}

async fn run_agent(config_path: &str, seed_mode: bool) -> Result<()> {
    let data = fs::read_to_string(config_path).await
        .context("read config")?;
    let cfg: AgentConfig = serde_json::from_str(&data)
        .context("parse config")?;

    let state = Arc::new(AgentState::new(cfg));
    tracing::info!("starting agent (seed_mode={})", seed_mode);

    let mut bpf = bpf::BpfManager::load()
        .context("load BPF programs")?;
    bpf.set_tunnel_cfg(state.cfg.tunnel_vni)?;

    let ifindex = bpf::find_default_ifindex().await
        .unwrap_or(1);
    bpf.attach_all(ifindex)?;

    stun::discover(&state).await?;

    let proto = protocol::UdpProtocol::bind(
        *state.public_port.read().await,
        &state.cfg.psk,
    ).await?;
    let proto = Arc::new(tokio::sync::Mutex::new(proto));

    let mut seed_client = seed::SeedClient::new(&state, seed_mode);
    seed_client.register_all().await;
    let seed_client = Arc::new(tokio::sync::Mutex::new(seed_client));

    let stop = Arc::new(AtomicBool::new(false));

    spawn_tasks(&state, &bpf, &proto, &seed_client, &stop).await;

    tokio::signal::ctrl_c().await.ok();
    tracing::info!("shutting down...");
    stop.store(true, Ordering::SeqCst);
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    Ok(())
}

async fn spawn_tasks(
    state: &Arc<AgentState>,
    bpf: &bpf::BpfManager,
    proto: &Arc<tokio::sync::Mutex<protocol::UdpProtocol>>,
    seed_client: &Arc<tokio::sync::Mutex<seed::SeedClient>>,
    stop: &Arc<AtomicBool>,
) {
    let _ = (bpf, proto, seed_client, stop);

    if state.cfg.metrics_port > 0 {
        tokio::spawn(metrics::serve(
            state.clone(),
            state.cfg.metrics_port,
            stop.clone(),
        ));
    }

    // STUN refresh
    let refresh = state.cfg.stun_refresh_interval;
    tokio::spawn(stun::refresh_loop(
        state.clone(),
        refresh,
        stop.clone(),
    ));
}

async fn run_cni() -> Result<()> {
    tracing::info!("CNI plugin invoked");
    let _stdin = tokio::io::stdin();
    Ok(())
}
