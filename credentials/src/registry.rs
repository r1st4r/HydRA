use std::collections::BTreeMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::model::{DeviceRecord, DeviceStatus};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct FileRegistry {
    devices: BTreeMap<String, DeviceRecord>,
}

impl FileRegistry {
    pub fn load_or_default(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let bytes = std::fs::read(path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(self)?;
        std::fs::write(path, bytes)?;
        Ok(())
    }

    pub fn get_by_hash(&self, public_key_hash: &str) -> Option<&DeviceRecord> {
        self.devices.get(public_key_hash)
    }

    pub fn upsert(&mut self, record: DeviceRecord) {
        self.devices
            .insert(record.public_key_hash_hex.clone(), record);
    }

    pub fn expire_trusted(&mut self, now: DateTime<Utc>) -> usize {
        let mut expired = 0;
        for record in self.devices.values_mut() {
            if record.should_expire(now) {
                record.status = DeviceStatus::Expired;
                record.updated_at = now;
                expired += 1;
            }
        }
        expired
    }
}

