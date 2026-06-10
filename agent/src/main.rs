use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::fs;
use tracing_subscriber::EnvFilter;

use nomad_p2p_common::Config;
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
    let cfg: Config = serde_json::from_str(&data)
        .context("parse config")?;

    let state = Arc::new(AgentState::new(cfg));
    tracing::info!("starting agent (seed_mode={})", seed_mode);

    // Load BPF
    let mut bpf = bpf::BpfManager::load().await
        .context("load BPF programs")?;
    bpf.set_tunnel_cfg(state.cfg.tunnel_vni)?;

    let ifindex = bpf::find_default_ifindex().await
        .unwrap_or(1);
    bpf.attach_all(ifindex)?;

    // STUN discovery
    stun::discover(&state).await?;

    // UDP protocol
    let mut proto = protocol::UdpProtocol::bind(
        *state.public_port.read().await,
        &state.cfg.psk,
    ).await?;

    // Seed registration
    let mut seed_client = seed::SeedClient::new(&state, seed_mode);
    seed_client.register_all().await;

    // Spawn core tasks
    let stop = tokio::sync::watch::channel(false);
    tokio::select! {
        _ = run_tasks(&state, &mut bpf, &mut proto, &mut seed_client, &stop.1) => {}
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down...");
            let _ = stop.0.send(true);
        }
    }

    Ok(())
}

async fn run_tasks(
    state: &Arc<AgentState>,
    bpf: &mut bpf::BpfManager,
    proto: &mut protocol::UdpProtocol,
    seed_client: &mut seed::SeedClient,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let mut tasks = Vec::new();

    // RingBuf consumer
    tasks.push(tokio::spawn(route_miss_loop(
        Arc::clone(state),
        seed_client.clone(),
        stop.clone(),
    )));

    // UDP listener
    tasks.push(tokio::spawn(udp_listener_loop(
        state.clone(),
        proto,
        seed_client.clone(),
        stop.clone(),
    )));

    // STUN refresh
    let refresh = state.cfg.stun_refresh_interval;
    tasks.push(tokio::spawn(stun::refresh_loop(
        state.clone(),
        refresh,
        stop.clone(),
    )));

    // Peer health
    tasks.push(tokio::spawn(seed::health_loop(
        state.clone(),
        seed_client.clone(),
        stop.clone(),
    )));

    // VIP probing
    if state.cfg.vip_enabled {
        tasks.push(tokio::spawn(vip::probe_loop(
            state.clone(),
            stop.clone(),
        )));
    }

    // Metrics server
    if state.cfg.metrics_port > 0 {
        tasks.push(tokio::spawn(metrics::serve(
            state.clone(),
            state.cfg.metrics_port,
            stop.clone(),
        )));
    }

    // Config hot-reload
    if !state.cfg.seeds.is_empty() {
        tasks.push(tokio::spawn(reload::watch_loop(
            state.clone(),
            stop.clone(),
        )));
    }

    // Wait for stop signal
    stop.changed().await.ok();
    tracing::info!("stopping all tasks");

    Ok(())
}

async fn route_miss_loop(
    _state: Arc<AgentState>,
    _seed_client: seed::SeedClient,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(1)) => {}
        }
    }
}

async fn udp_listener_loop(
    _state: Arc<AgentState>,
    proto: &mut protocol::UdpProtocol,
    _seed_client: seed::SeedClient,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let mut buf = vec![0u8; 65536];
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            result = proto.recv(&mut buf) => {
                match result {
                    Ok((n, addr)) => {
                        let payload = &buf[..n];
                        let msg_bytes = &payload[nomad_p2p_common::HEADER_SIZE..n - nomad_p2p_common::HMAC_SIZE];
                        if let Ok(msg) = serde_json::from_slice::<seed::Message>(msg_bytes) {
                            tracing::trace!("msg from {} type={}", addr, msg.msg_type);
                        }
                    }
                    Err(e) => {
                        tracing::error!("UDP recv error: {}", e);
                    }
                }
            }
        }
    }
}

async fn run_cni() -> Result<()> {
    tracing::info!("CNI plugin invoked");
    let stdin = tokio::io::stdin();
    // TODO: implement CNI ADD/DEL
    Ok(())
}
