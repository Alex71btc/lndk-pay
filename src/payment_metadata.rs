use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const STORE_FILE_NAME: &str = "incoming-payment-metadata.json";
const STORE_FORMAT_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncomingPaymentMetadata {
    pub payment_hash: String,
    pub payer_note: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct StoredMetadata {
    version: u32,
    payments: BTreeMap<String, String>,
}

impl Default for StoredMetadata {
    fn default() -> Self {
        Self {
            version: STORE_FORMAT_VERSION,
            payments: BTreeMap::new(),
        }
    }
}

/// Durable metadata that LND cannot attach to an invoice itself.
///
/// Entries are keyed by LND's payment hash. The file lives in LNDK's data
/// directory and is atomically replaced after every change, so payer notes are
/// available to API clients after an LNDK restart.
pub struct IncomingPaymentMetadataStore {
    path: PathBuf,
    metadata: Mutex<StoredMetadata>,
}

impl IncomingPaymentMetadataStore {
    pub fn open(data_dir: &Path) -> io::Result<Self> {
        let path = data_dir.join(STORE_FILE_NAME);
        let metadata = if path.exists() {
            let reader = BufReader::new(File::open(&path)?);
            let metadata: StoredMetadata = serde_json::from_reader(reader)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

            if metadata.version != STORE_FORMAT_VERSION {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "unsupported incoming payment metadata version {}",
                        metadata.version
                    ),
                ));
            }

            metadata
        } else {
            StoredMetadata::default()
        };

        Ok(Self {
            path,
            metadata: Mutex::new(metadata),
        })
    }

    pub fn record(&self, payment_hash: [u8; 32], payer_note: String) -> io::Result<()> {
        let payment_hash = hex::encode(payment_hash);
        let mut metadata = self.metadata.lock().unwrap();

        if metadata.payments.get(&payment_hash) == Some(&payer_note) {
            return Ok(());
        }

        let previous = metadata.payments.insert(payment_hash.clone(), payer_note);
        if let Err(error) = self.persist(&metadata) {
            match previous {
                Some(previous) => {
                    metadata.payments.insert(payment_hash, previous);
                }
                None => {
                    metadata.payments.remove(&payment_hash);
                }
            }
            return Err(error);
        }

        Ok(())
    }

    pub fn list(&self, payment_hashes: &HashSet<String>) -> Vec<IncomingPaymentMetadata> {
        let metadata = self.metadata.lock().unwrap();
        metadata
            .payments
            .iter()
            .filter(|(payment_hash, _)| {
                payment_hashes.is_empty() || payment_hashes.contains(*payment_hash)
            })
            .map(|(payment_hash, payer_note)| IncomingPaymentMetadata {
                payment_hash: payment_hash.clone(),
                payer_note: payer_note.clone(),
            })
            .collect()
    }

    fn persist(&self, metadata: &StoredMetadata) -> io::Result<()> {
        let temporary_path = self.path.with_extension("json.tmp");
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&temporary_path)?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, metadata).map_err(io::Error::other)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        fs::rename(&temporary_path, &self.path)?;

        if let Some(parent) = self.path.parent() {
            File::open(parent)?.sync_all()?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn preserves_notes_exactly_across_restarts() {
        let data_dir = tempdir().unwrap();
        let first_hash = [1; 32];
        let second_hash = [2; 32];
        let note = format!("Erste Zeile\nZweite Zeile 🚀\n{}", "💛".repeat(200));

        {
            let store = IncomingPaymentMetadataStore::open(data_dir.path()).unwrap();
            store.record(first_hash, note.clone()).unwrap();
            store
                .record(second_hash, "another payment".to_string())
                .unwrap();
        }

        let reopened = IncomingPaymentMetadataStore::open(data_dir.path()).unwrap();
        let requested = HashSet::from([hex::encode(first_hash)]);
        assert_eq!(
            reopened.list(&requested),
            vec![IncomingPaymentMetadata {
                payment_hash: hex::encode(first_hash),
                payer_note: note,
            }]
        );
        assert_eq!(reopened.list(&HashSet::new()).len(), 2);
    }
}
