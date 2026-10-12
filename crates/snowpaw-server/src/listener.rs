//! TLS accept loop. Our own (instead of axum::serve) so we control the limits that
//! matter for resource exhaustion: a global connection cap, a per-address cap (so one
//! peer can't take every slot), a TLS handshake deadline, a total header deadline,
//! and a header size cap.
//!
//! Keep-alive stays on (turning it off makes hyper send `Connection: upgrade, close`
//! on the WebSocket 101, which strict clients reject). Idle keep-alive connections are
//! still bounded: hyper starts the header deadline as soon as it waits for the next
//! request, so a connection that goes quiet is closed after `http_header_timeout_secs`.

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::Router;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::{debug, warn};

use crate::api::PeerAddr;
use crate::config::LimitsSection;

/// Request line + headers must fit in this. hyper's minimum is 8 KiB.
const MAX_HEADER_BUF: usize = 16 * 1024;

/// The unit a per-address cap applies to: one IPv4 address, or one IPv6 /64 (a single
/// host or LAN usually controls a whole /64, so per-/128 caps would be meaningless).
fn peer_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        v4 => v4,
    }
}

/// Open-connection counts per peer key.
#[derive(Debug)]
struct PerPeer {
    max: u32,
    counts: Mutex<HashMap<IpAddr, u32>>,
}

/// Holds one of a peer's slots; releases it on drop.
#[derive(Debug)]
struct PeerSlot {
    tracker: Arc<PerPeer>,
    key: IpAddr,
}

impl PerPeer {
    fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<PeerSlot> {
        let key = peer_key(ip);
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let n = counts.entry(key).or_insert(0);
        if *n >= self.max {
            return None;
        }
        *n += 1;
        Some(PeerSlot { tracker: Arc::clone(self), key })
    }
}

impl Drop for PeerSlot {
    fn drop(&mut self) {
        let mut counts = self.tracker.counts.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(n) = counts.get_mut(&self.key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                counts.remove(&self.key);
            }
        }
    }
}

pub async fn serve(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    app: Router,
    limits: LimitsSection,
    shutdown: impl Future<Output = ()>,
) {
    let acceptor = TlsAcceptor::from(tls);
    let slots = Arc::new(Semaphore::new(limits.max_connections as usize));
    let per_peer =
        Arc::new(PerPeer { max: limits.max_connections_per_ip, counts: Mutex::default() });
    let handshake_timeout = Duration::from_secs(limits.tls_handshake_timeout_secs);
    let header_timeout = Duration::from_secs(limits.http_header_timeout_secs);
    tokio::pin!(shutdown);

    loop {
        let (tcp, peer) = tokio::select! {
            () = &mut shutdown => return,
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    // e.g. out of file descriptors: back off instead of spinning.
                    warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let Some(peer_slot) = per_peer.try_acquire(peer.ip()) else {
            debug!(?peer, "per-address connection limit reached; dropping connection");
            drop(tcp);
            continue;
        };
        let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
            debug!(?peer, "connection limit reached; dropping connection");
            drop(tcp);
            continue;
        };
        let _ = tcp.set_nodelay(true);
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let _slots = (slot, peer_slot);
            let tls_stream =
                match tokio::time::timeout(handshake_timeout, acceptor.accept(tcp)).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        debug!(?peer, error = %e, "TLS handshake failed");
                        return;
                    }
                    Err(_) => {
                        debug!(?peer, "TLS handshake timed out");
                        return;
                    }
                };
            let service = hyper::service::service_fn(move |mut req: hyper::Request<Incoming>| {
                req.extensions_mut().insert(PeerAddr(peer));
                let app = app.clone();
                async move { Ok::<_, Infallible>(app.oneshot(req).await.unwrap_or_else(|e| match e {})) }
            });
            let conn = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Some(header_timeout))
                .max_buf_size(MAX_HEADER_BUF)
                .serve_connection(TokioIo::new(tls_stream), service)
                .with_upgrades();
            if let Err(e) = conn.await {
                debug!(?peer, error = %e, "connection ended with error");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_keys_group_ipv6_by_64() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().expect("ip");
        let b: IpAddr = "2001:db8:1:2:bbbb::2".parse().expect("ip");
        let c: IpAddr = "2001:db8:1:3::1".parse().expect("ip");
        assert_eq!(peer_key(a), peer_key(b));
        assert_ne!(peer_key(a), peer_key(c));
        let v4: IpAddr = "10.0.0.1".parse().expect("ip");
        let mapped: IpAddr = "::ffff:10.0.0.1".parse().expect("ip");
        assert_eq!(peer_key(v4), peer_key(mapped), "v4-mapped IPv6 counts as the IPv4 address");
        assert_ne!(peer_key(v4), peer_key("10.0.0.2".parse().expect("ip")));
    }

    #[test]
    fn per_peer_slots_are_capped_and_released() {
        let t = Arc::new(PerPeer { max: 2, counts: Mutex::default() });
        let ip: IpAddr = "10.0.0.1".parse().expect("ip");
        let other: IpAddr = "10.0.0.2".parse().expect("ip");
        let s1 = t.try_acquire(ip).expect("1");
        let _s2 = t.try_acquire(ip).expect("2");
        assert!(t.try_acquire(ip).is_none(), "third from the same peer is refused");
        assert!(t.try_acquire(other).is_some(), "other peers are unaffected");
        drop(s1);
        assert!(t.try_acquire(ip).is_some(), "slot released on drop");
    }
}
