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
    Agent {
        #[arg(short, long, default_value = "/etc/nomad-p2p/config.json")]
        config: String,
    },
    Seed {
        #[arg(short, long, default_value = "/etc/nomad-p2p/config.json")]
        config: String,
    },
    Cni,
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
            run_cni()?;
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

    let bpf = {
        let mut bpf = bpf::BpfManager::load()
            .context("load BPF programs")?;
        bpf.set_tunnel_cfg(state.cfg.read().await.tunnel_vni)?;
        let ifindex = bpf::find_default_ifindex().await
            .unwrap_or(1);
        bpf.attach_all(ifindex)?;
        Arc::new(std::sync::Mutex::new(bpf))
    };

    stun::discover(&state).await?;

    let proto = protocol::UdpProtocol::bind(
        state.cfg.read().await.listen_port,
        &state.cfg.read().await.psk,
    ).await?;
    let proto = Arc::new(tokio::sync::Mutex::new(proto));

    let mut seed_client = seed::SeedClient::new(seed_mode, proto.clone());
    seed_client.register_all(&state).await;
    let seed_client = Arc::new(tokio::sync::Mutex::new(seed_client));

    let route_mgr = Arc::new(route::RouteManager::new());
    let container_mgr = api::ContainerManager::new();

    // Recover containers from pinned BPF map (restart persistence)
    container_mgr.recover_from_bpf(&bpf).await;

    let ipsec_mgr = if state.cfg.read().await.ipsec_enabled {
        Some(Arc::new(std::sync::Mutex::new(ipsec::IpsecManager::new(
            state.cfg.read().await.ipsec_spi,
            &state.cfg.read().await.ipsec_key,
        ))))
    } else {
        None
    };

    let seed_addrs = state.cfg.read().await.seeds.iter().map(|s| s.addr.clone()).collect::<Vec<_>>();
    let p2p = kademlia::build_p2p(&state, &seed_addrs).await.ok();

    let (kad_tx, kad_rx) = tokio::sync::mpsc::unbounded_channel();
    let stop = Arc::new(AtomicBool::new(false));

    let ctx = AppContext {
        state,
        bpf,
        proto,
        seed_client,
        route_mgr,
        container_mgr,
        ipsec_mgr,
        p2p,
        kad_tx,
        kad_rx,
        stop: stop.clone(),
    };
    ctx.spawn_all().await;

    tokio::signal::ctrl_c().await.ok();
    tracing::info!("shutting down...");
    stop.store(true, Ordering::SeqCst);
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    Ok(())
}

fn run_cni() -> Result<()> {
    nomad_p2p_cni::run()
}