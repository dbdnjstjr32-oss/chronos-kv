//! `chronos-chaos-proxy`: Standalone External L4 Raw-Byte TCP Chaos Proxy Process.
//!
//! Operates strictly outside the SUT over real kernel TCP sockets (`127.0.0.1`).
//! Each `--route <fwd_name>,<rev_name>,<listen_addr>,<target_addr>` creates a TCP listener
//! whose two half-duplex byte pumps (`client->target` = `fwd_name`, `target->client` = `rev_name`)
//! are independently governed by dynamic chaos policies controlled over `--control-listen`:
//! - Directional blackhole (`drop_all`) -> true asymmetric network partitions!
//! - Micro-fragmentation (`max_chunk_bytes = 1..=3`) -> splits wire frames down to 1-3 byte TCP segments!
//! - Latency injection (`delay_ms`) -> delays packets in flight!
//! - Abrupt connection reset (`reset_existing`) -> tears down live TCP sockets mid-frame!

use std::collections::HashMap;
use std::env;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use chronos_kv::protocol::{
    ChaosSetPolicyReq, MSG_CHAOS_SET_POLICY_REQ, MSG_CHAOS_SET_POLICY_RESP,
};
use chronos_kv::wire::{ByteWriter, FrameDecoder, WireError, WireFrame};

#[derive(Debug, Clone)]
struct LinkPolicy {
    drop_all: bool,
    delay_ms: u32,
    max_chunk_bytes: u32,
    generation: u64,
}

impl Default for LinkPolicy {
    fn default() -> Self {
        Self {
            drop_all: false,
            delay_ms: 0,
            max_chunk_bytes: 0,
            generation: 0,
        }
    }
}

struct ChaosTable {
    policies: HashMap<String, LinkPolicy>,
}

impl ChaosTable {
    fn new(link_names: &[String]) -> Self {
        let mut policies = HashMap::new();
        for name in link_names {
            policies.insert(name.clone(), LinkPolicy::default());
        }
        Self { policies }
    }

    fn apply_req(&mut self, req: &ChaosSetPolicyReq) -> u32 {
        let mut updated = 0u32;
        if req.link_name == "*" {
            for pol in self.policies.values_mut() {
                pol.drop_all = req.drop_all;
                pol.delay_ms = req.delay_ms;
                pol.max_chunk_bytes = req.max_chunk_bytes;
                if req.reset_existing {
                    pol.generation += 1;
                }
                updated += 1;
            }
        } else if let Some(pol) = self.policies.get_mut(&req.link_name) {
            pol.drop_all = req.drop_all;
            pol.delay_ms = req.delay_ms;
            pol.max_chunk_bytes = req.max_chunk_bytes;
            if req.reset_existing {
                pol.generation += 1;
            }
            updated = 1;
        } else {
            let mut pol = LinkPolicy {
                drop_all: req.drop_all,
                delay_ms: req.delay_ms,
                max_chunk_bytes: req.max_chunk_bytes,
                generation: if req.reset_existing { 1 } else { 0 },
            };
            let _ = &mut pol;
            self.policies.insert(req.link_name.clone(), pol);
            updated = 1;
        }
        updated
    }

    fn get_policy(&self, link_name: &str) -> LinkPolicy {
        self.policies.get(link_name).cloned().unwrap_or_default()
    }
}

fn pump_half_duplex(
    link_name: String,
    mut reader: TcpStream,
    mut writer: TcpStream,
    table: Arc<Mutex<ChaosTable>>,
) {
    let _ = reader.set_read_timeout(Some(Duration::from_millis(200)));
    let _ = writer.set_nodelay(true);
    let _ = writer.set_write_timeout(Some(Duration::from_millis(500)));

    let initial_gen = table.lock().unwrap().get_policy(&link_name).generation;
    let mut buf = [0u8; 8192];
    let mut step_counter: usize = 0;

    loop {
        let cur_pol = table.lock().unwrap().get_policy(&link_name);
        if cur_pol.generation != initial_gen {
            let _ = reader.shutdown(Shutdown::Both);
            let _ = writer.shutdown(Shutdown::Both);
            break;
        }

        match reader.read(&mut buf) {
            Ok(0) => {
                let _ = writer.shutdown(Shutdown::Write);
                break;
            }
            Ok(n) => {
                let pol = table.lock().unwrap().get_policy(&link_name);
                if pol.generation != initial_gen {
                    let _ = reader.shutdown(Shutdown::Both);
                    let _ = writer.shutdown(Shutdown::Both);
                    break;
                }
                if pol.drop_all {
                    // Blackhole: silently swallow raw bytes in this direction only!
                    continue;
                }
                if pol.delay_ms > 0 {
                    thread::sleep(Duration::from_millis(pol.delay_ms as u64));
                }

                let data = &buf[..n];
                if pol.max_chunk_bytes > 0 {
                    let cap = (pol.max_chunk_bytes as usize).max(1);
                    let mut pos = 0usize;
                    let mut write_failed = false;
                    while pos < data.len() {
                        // Alternate chunk sizes 1..=cap for adversarial stream boundary slicing
                        let step = ((step_counter % cap) + 1).min(data.len() - pos);
                        step_counter = step_counter.wrapping_add(1);
                        if writer.write_all(&data[pos..pos + step]).is_err()
                            || writer.flush().is_err()
                        {
                            write_failed = true;
                            break;
                        }
                        pos += step;
                        if pos < data.len() && (step_counter % 4 == 0) {
                            thread::sleep(Duration::from_micros(150));
                        }
                    }
                    if write_failed {
                        let _ = reader.shutdown(Shutdown::Both);
                        break;
                    }
                } else if writer.write_all(data).is_err() || writer.flush().is_err() {
                    let _ = reader.shutdown(Shutdown::Both);
                    break;
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => {
                let _ = writer.shutdown(Shutdown::Both);
                break;
            }
        }
    }
}

fn run_route_listener(
    fwd_name: String,
    rev_name: String,
    listen_addr: String,
    target_addr: String,
    table: Arc<Mutex<ChaosTable>>,
) {
    let listener = TcpListener::bind(&listen_addr)
        .unwrap_or_else(|e| panic!("chaos proxy failed to bind route {}: {}", listen_addr, e));

    for incoming in listener.incoming() {
        let Ok(client_stream) = incoming else {
            continue;
        };
        let _ = client_stream.set_nodelay(true);

        let Ok(sock_addr) = target_addr.parse() else {
            continue;
        };
        let Ok(target_stream) = TcpStream::connect_timeout(&sock_addr, Duration::from_millis(300))
        else {
            let _ = client_stream.shutdown(Shutdown::Both);
            continue;
        };
        let _ = target_stream.set_nodelay(true);

        let (Ok(c_read), Ok(t_read)) = (client_stream.try_clone(), target_stream.try_clone()) else {
            continue;
        };

        let fwd = fwd_name.clone();
        let rev = rev_name.clone();
        let tbl1 = Arc::clone(&table);
        let tbl2 = Arc::clone(&table);

        thread::spawn(move || pump_half_duplex(fwd, c_read, target_stream, tbl1));
        thread::spawn(move || pump_half_duplex(rev, t_read, client_stream, tbl2));
    }
}

fn handle_control_conn(mut stream: TcpStream, table: Arc<Mutex<ChaosTable>>) {
    let _ = stream.set_nodelay(true);
    let mut dec = FrameDecoder::new();
    loop {
        match dec.read_frame(&mut stream) {
            Ok(Some(frame)) => {
                if frame.msg_type != MSG_CHAOS_SET_POLICY_REQ {
                    break;
                }
                let Ok(req) = ChaosSetPolicyReq::decode(&frame.payload) else {
                    break;
                };
                let updated = table.lock().unwrap().apply_req(&req);
                let mut w = ByteWriter::with_capacity(8);
                w.put_u32(updated);
                let resp = WireFrame::new(MSG_CHAOS_SET_POLICY_RESP, frame.req_id, w.into_vec());
                if resp.write_to(&mut stream).is_err() {
                    break;
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
    let mut control_listen = String::from("127.0.0.1:19999");
    // Vec of (fwd_name, rev_name, listen_addr, target_addr)
    let mut routes: Vec<(String, String, String, String)> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--control-listen" if i + 1 < args.len() => {
                control_listen = args[i + 1].clone();
                i += 2;
            }
            "--route" if i + 1 < args.len() => {
                let parts: Vec<&str> = args[i + 1].split(',').collect();
                if parts.len() == 4 {
                    routes.push((
                        parts[0].trim().to_string(),
                        parts[1].trim().to_string(),
                        parts[2].trim().to_string(),
                        parts[3].trim().to_string(),
                    ));
                }
                i += 2;
            }
            _ => i += 1,
        }
    }

    let mut all_names = Vec::new();
    for (fwd, rev, _, _) in &routes {
        all_names.push(fwd.clone());
        all_names.push(rev.clone());
    }
    let table = Arc::new(Mutex::new(ChaosTable::new(&all_names)));

    let ctrl_listener = TcpListener::bind(&control_listen)
        .unwrap_or_else(|e| panic!("failed to bind chaos control on {}: {}", control_listen, e));

    for (fwd, rev, l_addr, t_addr) in routes {
        let tbl = Arc::clone(&table);
        thread::spawn(move || run_route_listener(fwd, rev, l_addr, t_addr, tbl));
    }

    eprintln!(
        "[chronos-chaos-proxy] Control ready on {}",
        control_listen
    );

    for incoming in ctrl_listener.incoming() {
        if let Ok(stream) = incoming {
            let tbl = Arc::clone(&table);
            thread::spawn(move || handle_control_conn(stream, tbl));
        }
    }
}
