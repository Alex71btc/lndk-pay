use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    println!("cargo:rerun-if-env-changed=LND_REPO_DIR");
    let dir = match std::env::var_os("LND_REPO_DIR") {
        Some(lnd_repo_path) => PathBuf::from(lnd_repo_path).join("lnrpc"),
        None => PathBuf::from("vendor"),
    };

    let lnd_rpc_proto_file = dir.join("lightning.proto");
    println!("cargo:rerun-if-changed={}", lnd_rpc_proto_file.display());

    let protos = [
        "signrpc/signer.proto",
        "walletrpc/walletkit.proto",
        "lightning.proto",
        "peersrpc/peers.proto",
        "verrpc/verrpc.proto",
        "routerrpc/router.proto",
        "invoicesrpc/invoices.proto",
    ];

    let proto_paths: Vec<_> = protos.iter().map(|proto| dir.join(proto)).collect();

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(false)
        .compile_protos(&proto_paths, &[dir])?;
    Ok(())
}
