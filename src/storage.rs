//! Crash-Safe Disk Persistence Layer:
//! 1. 4-Step Atomic Metadata & Snapshot Persistence (`staging -> fsync -> rename -> dir fsync`)
//!    with `"CKMF"` magic header and IEEE CRC32 verification.
//! 2. Pure Append-Only Raft WAL (`"CWAL"` frames) with `TruncateAfter(index)` log-rewind records
//!    (never overwriting conflicting entries in place) and boot-time Torn-Write detection + `ftruncate`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::crc32::{crc32, Crc32Hasher};
use crate::protocol::LogEntry;
use crate::wire::{ByteReader, ByteWriter, WireError};

const META_MAGIC: [u8; 4] = *b"CKMF";
const WAL_MAGIC: [u8; 4] = *b"CWAL";

const WAL_REC_APPEND_ENTRY: u8 = 1;
const WAL_REC_TRUNCATE_AFTER: u8 = 2;

/// Best-effort POSIX directory `fsync` (tolerates EINVAL on virtual filesystems if any,
/// while executing real kernel directory metadata flush on Linux ext4/xfs).
pub fn sync_directory(dir: &Path) -> io::Result<()> {
    match File::open(dir) {
        Ok(d) => match d.sync_all() {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(22) => Ok(()), // EINVAL on some 9p mounts
            Err(e) => Err(e),
        },
        Err(_) => Ok(()),
    }
}

/// Writes `[CKMF][crc32: u32][len: u32][payload]` atomically via `<filename>.staging` -> `fsync` -> `rename` -> `dir fsync`.
/// Never truncates the live target file in place, preventing 0-byte metadata corruption on `SIGKILL`.
pub fn atomic_write_file(dir: &Path, filename: &str, payload: &[u8]) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let staging_path = dir.join(format!("{}.staging", filename));
    let final_path = dir.join(filename);

    let checksum = crc32(payload);
    let len = payload.len() as u32;

    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&staging_path)?;
        f.write_all(&META_MAGIC)?;
        f.write_all(&checksum.to_le_bytes())?;
        f.write_all(&len.to_le_bytes())?;
        f.write_all(payload)?;
        f.sync_all()?;
    }

    fs::rename(&staging_path, &final_path)?;
    sync_directory(dir)?;
    Ok(())
}

/// Reads and verifies an atomically persisted file. Returns `Ok(None)` if the file does not exist yet.
pub fn atomic_read_file(dir: &Path, filename: &str) -> Result<Option<Vec<u8>>, WireError> {
    let path = dir.join(filename);
    if !path.exists() {
        return Ok(None);
    }
    let mut raw = Vec::new();
    File::open(&path)?.read_to_end(&mut raw)?;
    if raw.len() < 12 {
        return Err(WireError::DecodeUnderflow("atomic_read_file header < 12B"));
    }
    if raw[0..4] != META_MAGIC {
        let mut m = [0u8; 4];
        m.copy_from_slice(&raw[0..4]);
        return Err(WireError::BadMagic(m));
    }
    let expected_crc = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
    let len = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]) as usize;
    if raw.len() != 12 + len {
        return Err(WireError::DecodeUnderflow("atomic_read_file truncated payload"));
    }
    let payload = &raw[12..12 + len];
    let actual_crc = crc32(payload);
    if actual_crc != expected_crc {
        return Err(WireError::CrcMismatch {
            expected: expected_crc,
            actual: actual_crc,
        });
    }
    Ok(Some(payload.to_vec()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersistedRaftMeta {
    pub current_term: u64,
    pub voted_for: Option<u16>,
}

pub fn save_raft_meta(dir: &Path, meta: &PersistedRaftMeta) -> io::Result<()> {
    let mut w = ByteWriter::with_capacity(16);
    w.put_u64(meta.current_term);
    w.put_opt_u16(meta.voted_for);
    atomic_write_file(dir, "raft_meta.bin", &w.into_vec())
}

pub fn load_raft_meta(dir: &Path) -> Result<PersistedRaftMeta, WireError> {
    match atomic_read_file(dir, "raft_meta.bin")? {
        Some(buf) => {
            let mut r = ByteReader::new(&buf);
            Ok(PersistedRaftMeta {
                current_term: r.get_u64("RaftMeta.current_term")?,
                voted_for: r.get_opt_u16("RaftMeta.voted_for")?,
            })
        }
        None => Ok(PersistedRaftMeta {
            current_term: 0,
            voted_for: None,
        }),
    }
}

#[derive(Debug, Clone)]
pub struct PersistedSnapshot {
    pub last_included_index: u64,
    pub last_included_term: u64,
    pub state_bytes: Vec<u8>,
}

pub fn save_snapshot(dir: &Path, snap: &PersistedSnapshot) -> io::Result<()> {
    let mut w = ByteWriter::with_capacity(24 + snap.state_bytes.len());
    w.put_u64(snap.last_included_index);
    w.put_u64(snap.last_included_term);
    w.put_bytes(&snap.state_bytes);
    atomic_write_file(dir, "raft_snapshot.bin", &w.into_vec())
}

pub fn load_snapshot(dir: &Path) -> Result<Option<PersistedSnapshot>, WireError> {
    match atomic_read_file(dir, "raft_snapshot.bin")? {
        Some(buf) => {
            let mut r = ByteReader::new(&buf);
            Ok(Some(PersistedSnapshot {
                last_included_index: r.get_u64("Snap.last_included_index")?,
                last_included_term: r.get_u64("Snap.last_included_term")?,
                state_bytes: r.get_bytes("Snap.state_bytes")?,
            }))
        }
        None => Ok(None),
    }
}

#[derive(Debug, Clone)]
pub struct WalRecoveryReport {
    pub entries_recovered: usize,
    pub torn_bytes_truncated: u64,
}

/// Append-Only Write-Ahead Log (`raft_wal.log`).
/// Frame format:
///   [0..4]   magic       : b"CWAL"
///   [4..8]   crc32       : u32 (LE, over [8..13+payload_len])
///   [8..12]  payload_len : u32 (LE)
///   [12]     rec_type    : u8 (1 = AppendEntry, 2 = TruncateAfter)
///   [13..]   payload     : [u8; payload_len]
pub struct WalStorage {
    dir: PathBuf,
    wal_path: PathBuf,
    file: File,
}

impl WalStorage {
    pub fn open_and_recover(
        dir: &Path,
        snapshot_index: u64,
    ) -> Result<(Self, Vec<LogEntry>, WalRecoveryReport), WireError> {
        fs::create_dir_all(dir)?;
        let wal_path = dir.join("raft_wal.log");
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&wal_path)?;

        let mut raw = Vec::new();
        file.seek(SeekFrom::Start(0))?;
        file.read_to_end(&mut raw)?;

        let total_file_len = raw.len() as u64;
        let mut offset = 0usize;
        let mut entries: Vec<LogEntry> = Vec::new();
        let mut torn_detected = false;

        while offset < raw.len() {
            let rem = raw.len() - offset;
            if rem < 13 {
                torn_detected = true;
                break;
            }
            if raw[offset..offset + 4] != WAL_MAGIC {
                torn_detected = true;
                break;
            }
            let expected_crc = u32::from_le_bytes([
                raw[offset + 4],
                raw[offset + 5],
                raw[offset + 6],
                raw[offset + 7],
            ]);
            let payload_len = u32::from_le_bytes([
                raw[offset + 8],
                raw[offset + 9],
                raw[offset + 10],
                raw[offset + 11],
            ]) as usize;

            if payload_len > 32 * 1024 * 1024 || rem < 13 + payload_len {
                torn_detected = true;
                break;
            }

            let crc_region = &raw[offset + 8..offset + 13 + payload_len];
            if crc32(crc_region) != expected_crc {
                torn_detected = true;
                break;
            }

            let rec_type = raw[offset + 12];
            let rec_payload = &raw[offset + 13..offset + 13 + payload_len];

            match rec_type {
                WAL_REC_APPEND_ENTRY => {
                    let mut r = ByteReader::new(rec_payload);
                    match LogEntry::decode_from(&mut r) {
                        Ok(entry) => {
                            if entry.index > snapshot_index {
                                // Keep contiguous ordering after snapshot_index
                                while entries.last().map_or(false, |e| e.index >= entry.index) {
                                    entries.pop();
                                }
                                entries.push(entry);
                            }
                        }
                        Err(_) => {
                            torn_detected = true;
                            break;
                        }
                    }
                }
                WAL_REC_TRUNCATE_AFTER => {
                    let mut r = ByteReader::new(rec_payload);
                    match r.get_u64("WalTruncate.new_last_index") {
                        Ok(new_last_idx) => {
                            while entries.last().map_or(false, |e| e.index > new_last_idx) {
                                entries.pop();
                            }
                        }
                        Err(_) => {
                            torn_detected = true;
                            break;
                        }
                    }
                }
                _ => {
                    torn_detected = true;
                    break;
                }
            }

            offset += 13 + payload_len;
        }

        let valid_len = offset as u64;
        let torn_bytes_truncated = if torn_detected && valid_len < total_file_len {
            let cut = total_file_len - valid_len;
            eprintln!(
                "[WAL-RECOVERY] dir={} detected torn/corrupt WAL tail at offset {} (file_len={}); truncating {} bytes",
                dir.display(),
                valid_len,
                total_file_len,
                cut
            );
            file.set_len(valid_len)?;
            file.sync_all()?;
            cut
        } else {
            0
        };

        file.seek(SeekFrom::End(0))?;
        let report = WalRecoveryReport {
            entries_recovered: entries.len(),
            torn_bytes_truncated,
        };
        Ok((
            Self {
                dir: dir.to_path_buf(),
                wal_path,
                file,
            },
            entries,
            report,
        ))
    }

    fn encode_record(rec_type: u8, payload: &[u8]) -> Vec<u8> {
        let len_bytes = (payload.len() as u32).to_le_bytes();
        let mut hasher = Crc32Hasher::new();
        hasher.update(&len_bytes);
        hasher.update(&[rec_type]);
        hasher.update(payload);
        let checksum = hasher.finalize();

        let mut out = Vec::with_capacity(13 + payload.len());
        out.extend_from_slice(&WAL_MAGIC);
        out.extend_from_slice(&checksum.to_le_bytes());
        out.extend_from_slice(&len_bytes);
        out.push(rec_type);
        out.extend_from_slice(payload);
        out
    }

    /// Appends an optional `TruncateAfter` record followed by zero or more `LogEntry` records in a single `fsync`.
    pub fn append_batch(
        &mut self,
        truncate_after: Option<u64>,
        entries: &[LogEntry],
    ) -> io::Result<()> {
        let mut batch = Vec::new();
        if let Some(new_last_idx) = truncate_after {
            batch.extend_from_slice(&Self::encode_record(
                WAL_REC_TRUNCATE_AFTER,
                &new_last_idx.to_le_bytes(),
            ));
        }
        for e in entries {
            let mut w = ByteWriter::with_capacity(24 + e.cmd_bytes.len());
            e.encode_into(&mut w);
            batch.extend_from_slice(&Self::encode_record(WAL_REC_APPEND_ENTRY, &w.into_vec()));
        }
        if !batch.is_empty() {
            self.file.seek(SeekFrom::End(0))?;
            self.file.write_all(&batch)?;
            self.file.sync_all()?;
        }
        Ok(())
    }

    /// Atomically rewrites the WAL to contain only `suffix_entries` (`index > snapshot_index`).
    /// Must ONLY be called AFTER `save_snapshot` has completed its atomic rename + dir fsync.
    pub fn compact_with_suffix(&mut self, suffix_entries: &[LogEntry]) -> io::Result<()> {
        let staging_path = self.dir.join("raft_wal.log.staging");
        {
            let mut sf = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&staging_path)?;
            let mut buf = Vec::new();
            for e in suffix_entries {
                let mut w = ByteWriter::with_capacity(24 + e.cmd_bytes.len());
                e.encode_into(&mut w);
                buf.extend_from_slice(&Self::encode_record(WAL_REC_APPEND_ENTRY, &w.into_vec()));
            }
            if !buf.is_empty() {
                sf.write_all(&buf)?;
            }
            sf.sync_all()?;
        }
        fs::rename(&staging_path, &self.wal_path)?;
        sync_directory(&self.dir)?;
        self.file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&self.wal_path)?;
        self.file.seek(SeekFrom::End(0))?;
        Ok(())
    }
}
