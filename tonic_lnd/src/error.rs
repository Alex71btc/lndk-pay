pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Filesystem error: {0}")]
    Filesystem(#[from] std::io::Error),
    #[error("Tonic error: {0}")]
    Tonic(#[from] tonic::transport::Error),
    #[error("Invalid address: {0}")]
    InvalidAddress(#[from] http::uri::InvalidUri),
    #[error("Rustls error: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("Verifier error: {0}")]
    Verifier(#[from] rustls::client::VerifierBuilderError),
    #[error("Missing address")]
    MissingAddress,
    #[error("Missing macaroon")]
    MissingMacaroon,
    #[error("Missing TLS certificate")]
    MissingTlsCert,
}
