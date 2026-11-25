//! `chronos-tso`: Standalone Monotonic Timestamp Oracle OS Process.
//!
//! Pre-allocates timestamps in batches (`--batch-window`, default 10,000) and persists
//! `allocated_max_ts` via 4-step atomic rename (`staging -> fsync -> rename -> dir fsync`)
//! before serving timestamps from memory. Guarantees strict monotonicity across `SIGKILL`.

use std::env;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use chronos_kv::protocol::{TsoAllocReq, TsoAllocResp, MSG_TSO_ALLOC_REQ};
use chronos_kv::storage::{atomic_read_file, atomic_write_file};
use chronos_kv::wire::{ByteReader, ByteWriter, FrameDecoder, WireError};

const TSO_META_FILE: &str = "tso_meta.bin";

struct TsoState {
    data_dir: PathBuf,
    batch_window: u64,
    next_ts: u64,
    allocated_max_ts: u64,
}

impl TsoState {
    fn open(data_dir: &Path, batch_window: u64) -> Result<Self, WireError> {
        let persisted_max = match atomic_read_file(data_dir, TSO_META_FILE)? {
            Some(buf) => {
                let mut r = ByteReader::new(&buf);
                r.get_u64("TsoMeta.allocated_max_ts")?
            }
            None => 0,
        };
        // On boot (or after SIGKILL), jump strictly past the previously persisted ceiling!
        let start_next = persisted_max + 1;
        eprintln!(
            "[chronos-tso] Booted with persisted_max={}, starting next_ts={}",
            persisted_max, start_next
        );
        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            batch_window: batch_window.max(100),
            next_ts: start_next,
            allocated_max_ts: persisted_max,
        })
    }

    fn allocate(&mut self, count: u32) -> Result<(u64, u32), std::io::Error> {
        let cnt = count.max(1) as u64;
        let needed_end = self.next_ts + cnt - 1;
        if needed_end > self.allocated_max_ts {
            let advance = self.batch_window.max(cnt);
            let new_ceiling = self.next_ts + advance - 1;
            let mut w = ByteWriter::with_capacity(8);
            w.put_u64(new_ceiling);
            atomic_write_file(&self.data_dir, TSO_META_FILE, &w.into_vec())?;
            self.allocated_max_ts = new_ceiling;
        }
        let base = self.next_ts;
        self.next_ts += cnt;
        Ok((base, count.max(1)))
    }
}

fn handle_client(mut stream: TcpStream, state: Arc<Mutex<TsoState>>) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let mut dec = FrameDecoder::new();

    loop {
        match dec.read_frame(&mut stream) {
            Ok(Some(frame)) => {
                if frame.msg_type != MSG_TSO_ALLOC_REQ {
                    break;
                }
                let Ok(req) = TsoAllocReq::decode(&frame.payload) else {
                    break;
                };
                let alloc_res = {
                    let mut g = state.lock().unwrap();
                    g.allocate(req.count)
                };
                match alloc_res {
                    Ok((base_ts, count)) => {
                        let resp = TsoAllocResp { base_ts, count };
                        if let Ok(resp_frame) = resp.to_frame(frame.req_id) {
                            if resp_frame.write_to(&mut stream).is_err() {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("[chronos-tso] persistence error: {}", e);
                        break;
                    }
                }
            }
            Ok(None) => break,
            Err(WireError::Io(ref e))
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => break,
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut listen_addr = String::from("127.0.0.1:17000");
    let mut data_dir = String::from("/tmp/chronos_tso");
    let mut batch_window: u64 = 10_000;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" if i + 1 < args.len() => {
                listen_addr = args[i + 1].clone();
                i += 2;
            }
            "--data-dir" if i + 1 < args.len() => {
                data_dir = args[i + 1].clone();
                i += 2;
            }
            "--batch-window" if i + 1 < args.len() => {
                batch_window = args[i + 1].parse().unwrap_or(10_000);
                i += 2;
            }
            _ => i += 1,
        }
    }

    let state = Arc::new(Mutex::new(
        TsoState::open(Path::new(&data_dir), batch_window).expect("failed to initialize TSO state"),
    ));

    let listener = TcpListener::bind(&listen_addr).expect("failed to bind TSO TCP listener");
    eprintln!("[chronos-tso] Listening on {}", listen_addr);

    for incoming in listener.incoming() {
        if let Ok(stream) = incoming {
            let st = Arc::clone(&state);
            thread::spawn(move || handle_client(stream, st));
        }
    }
}
