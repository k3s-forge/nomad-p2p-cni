use nomad_p2p_cni;

fn main() {
    if let Err(e) = nomad_p2p_cni::run() {
        eprintln!("CNI error: {}", e);
        std::process::exit(1);
    }
}
