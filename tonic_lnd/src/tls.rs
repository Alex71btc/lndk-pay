use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::ClientConfig;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TLSError, RootCertStore, SignatureScheme};

use crate::error::Result;

pub(crate) async fn config<P: AsRef<Path> + Into<PathBuf>>(cert: Cert<P>) -> Result<ClientConfig> {
    let hybrid_verifier = HybridCertVerifier::load(cert).await?;

    Ok(ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(hybrid_verifier))
        .with_no_client_auth())
}

#[derive(Debug)]
pub(crate) struct HybridCertVerifier {
    exact_certs: Vec<CertificateDer<'static>>,
    standard_verifier: Arc<dyn ServerCertVerifier>,
}

impl HybridCertVerifier {
    pub(crate) async fn load<P: AsRef<Path> + Into<PathBuf>>(cert: Cert<P>) -> Result<Self> {
        let contents = match cert {
            Cert::Path(path) => tokio::fs::read(&path).await?,
            Cert::Bytes(bytes) => bytes,
        };

        let mut reader = &*contents;
        let cert_data: Vec<CertificateDer> =
            rustls_pemfile::certs(&mut reader).collect::<std::result::Result<Vec<_>, _>>()?;

        let mut root_store = RootCertStore::empty();
        for cert_bytes in &cert_data {
            root_store.add(cert_bytes.clone())?
        }

        let standard_verifier =
            rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store)).build()?;

        Ok(HybridCertVerifier {
            exact_certs: cert_data,
            standard_verifier,
        })
    }

    fn try_exact_match(
        &self,
        end_entity: &CertificateDer,
        intermediates: &[CertificateDer],
    ) -> bool {
        let mut presented_certs = intermediates.to_vec();
        presented_certs.push(end_entity.clone());

        if self.exact_certs.len() != presented_certs.len() {
            return false;
        }

        for (expected, presented) in self.exact_certs.iter().zip(presented_certs.iter()) {
            if presented != expected {
                return false;
            }
        }

        true
    }
}

impl ServerCertVerifier for HybridCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TLSError> {
        if self.try_exact_match(end_entity, intermediates) {
            return Ok(ServerCertVerified::assertion());
        }

        self.standard_verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TLSError> {
        self.standard_verifier.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TLSError> {
        self.standard_verifier.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.standard_verifier.supported_verify_schemes()
    }
}

pub(crate) enum Cert<P: AsRef<Path> + Into<PathBuf>> {
    Path(P),
    Bytes(Vec<u8>),
}
