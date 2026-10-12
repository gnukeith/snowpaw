//! Fetching URLs for plugins, safely.
//!
//! A plugin can only ask; the server decides:
//! - HTTPS on port 443 only, to a host name (never an IP literal) that the user granted
//!   this agent for this plugin.
//! - The name is resolved here, every address it resolves to must be on the public
//!   internet (no loopback, private, link-local, CGNAT, multicast, documentation or
//!   reserved ranges, IPv6 included, IPv4-mapped/NAT64/6to4 forms unwrapped), and we
//!   connect to the address we checked (no second lookup to rebind).
//! - Redirects are followed at most 3 times, each one checked from scratch the same way.
//! - GET only, no cookies or credentials, TLS 1.3 with public CA roots, size and time
//!   limited; the body is returned as text.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use hyper::body::{Bytes, Incoming};
use hyper::header::{ACCEPT, CONTENT_TYPE, HOST, LOCATION, USER_AGENT};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use snowpaw_proto::plugin::{FetchFailure, Fetched, MAX_FETCH_BYTES, MAX_URL_CHARS};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const MAX_REDIRECTS: usize = 3;
const STEP_TIMEOUT: Duration = Duration::from_secs(15);

/// Is this an address on the public internet?
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => public_v4(v4),
        IpAddr::V6(v6) => public_v6(v6),
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

fn public_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    // Forms that embed an IPv4 address: judge the IPv4 address.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return public_v4(v4);
    }
    if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        let v4 = Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8);
        return public_v4(v4);
    }
    if s[0] == 0x2002 {
        let v4 = Ipv4Addr::new((s[1] >> 8) as u8, s[1] as u8, (s[2] >> 8) as u8, s[2] as u8);
        return public_v4(v4);
    }
    // Only global unicast (2000::/3), minus special-purpose blocks inside it.
    (s[0] & 0xe000) == 0x2000
        && !(s[0] == 0x2001 && s[1] < 0x0200) // 2001::/23: Teredo, ORCHID, benchmarking…
        && !(s[0] == 0x2001 && s[1] == 0x0db8) // documentation
        && !(s[0] == 0x3fff && s[1] < 0x1000) // documentation (3fff::/20)
}

/// A URL a plugin may ask for: `https://host[:443]/path?query`, no user info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    /// Path and query, starting with `/`.
    pub path: String,
}

pub fn parse_url(url: &str) -> Option<Target> {
    if url.len() > MAX_URL_CHARS || !url.bytes().all(|b| b.is_ascii_graphic()) {
        return None;
    }
    let rest = url.strip_prefix("https://")?;
    let rest = rest.split('#').next()?;
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.contains(['@', '[', ']', '\\']) {
        return None;
    }
    let host = match authority.split_once(':') {
        Some((h, "443")) => h,
        Some(_) => return None,
        None => authority,
    };
    let host = host.to_ascii_lowercase();
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && host.parse::<IpAddr>().is_err()
        && host.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if !host_ok {
        return None;
    }
    let path = if path.starts_with('?') { format!("/{path}") } else { path.to_owned() };
    Some(Target { host, path })
}

/// Where a redirect points, resolved against the current target.
fn redirect(from: &Target, location: &str) -> Option<Target> {
    if location.starts_with("https://") {
        parse_url(location)
    } else if location.starts_with('/') && !location.starts_with("//") {
        parse_url(&format!("https://{}{location}", from.host))
    } else {
        None
    }
}

/// Fetch `url` if its host is in `allowed`.
pub async fn get(url: &str, allowed: &[String]) -> Result<Fetched, FetchFailure> {
    let mut target = parse_url(url).ok_or(FetchFailure::NotAllowed)?;
    for _ in 0..=MAX_REDIRECTS {
        if !allowed.contains(&target.host) {
            return Err(FetchFailure::NotAllowed);
        }
        let step = tokio::time::timeout(STEP_TIMEOUT, get_once(&target)).await;
        match step.map_err(|_| FetchFailure::Timeout)?? {
            Step::Done(f) => return Ok(f),
            Step::Redirect(location) => {
                target = redirect(&target, &location).ok_or(FetchFailure::NotAllowed)?;
            }
        }
    }
    Err(FetchFailure::Failed)
}

enum Step {
    Done(Fetched),
    Redirect(String),
}

async fn resolve(host: &str) -> Result<SocketAddr, FetchFailure> {
    let addrs: Vec<SocketAddr> =
        tokio::net::lookup_host((host, 443)).await.map_err(|_| FetchFailure::Failed)?.collect();
    // Every answer must be public: a name that also resolves somewhere private is
    // refused outright rather than raced.
    if addrs.is_empty() {
        return Err(FetchFailure::Failed);
    }
    if !addrs.iter().all(|a| is_public(a.ip())) {
        return Err(FetchFailure::Blocked);
    }
    Ok(addrs[0])
}

fn tls() -> Result<Arc<ClientConfig>, FetchFailure> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| FetchFailure::Failed)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

async fn get_once(t: &Target) -> Result<Step, FetchFailure> {
    let addr = resolve(&t.host).await?;
    let tcp = TcpStream::connect(addr).await.map_err(|_| FetchFailure::Failed)?;
    let name = ServerName::try_from(t.host.clone()).map_err(|_| FetchFailure::NotAllowed)?;
    let stream =
        TlsConnector::from(tls()?).connect(name, tcp).await.map_err(|_| FetchFailure::Failed)?;
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake::<_, http_body_util_empty::Empty>(TokioIo::new(
            stream,
        ))
        .await
        .map_err(|_| FetchFailure::Failed)?;
    let task = tokio::spawn(conn);
    let result = async {
        let req = Request::builder()
            .method(Method::GET)
            .uri(t.path.as_str())
            .header(HOST, t.host.as_str())
            .header(USER_AGENT, "snowpaw-plugin-fetch/1")
            .header(ACCEPT, "*/*")
            .body(http_body_util_empty::Empty)
            .map_err(|_| FetchFailure::NotAllowed)?;
        let resp = sender.send_request(req).await.map_err(|_| FetchFailure::Failed)?;
        let status = resp.status();
        if status.is_redirection() {
            let location = resp
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or(FetchFailure::Failed)?
                .to_owned();
            return Ok(Step::Redirect(location));
        }
        let content_type: String = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .chars()
            .filter(|c| !c.is_control())
            .take(100)
            .collect();
        let body = read_capped(resp.into_body()).await?;
        Ok(Step::Done(Fetched {
            status: status.as_u16(),
            content_type,
            body: String::from_utf8_lossy(&body).replace('\0', ""),
        }))
    }
    .await;
    task.abort();
    result
}

async fn read_capped(mut body: Incoming) -> Result<Vec<u8>, FetchFailure> {
    use hyper::body::Body;
    let mut out = Vec::new();
    while let Some(frame) = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
        let frame = frame.map_err(|_| FetchFailure::Failed)?;
        if let Ok(data) = frame.into_data() {
            let data: Bytes = data;
            if out.len() + data.len() > MAX_FETCH_BYTES {
                return Err(FetchFailure::TooLarge);
            }
            out.extend_from_slice(&data);
        }
    }
    Ok(out)
}

/// An empty request body.
mod http_body_util_empty {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use hyper::body::{Body, Bytes, Frame, SizeHint};

    #[derive(Debug, Clone, Copy)]
    pub struct Empty;

    impl Body for Empty {
        type Data = Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(None)
        }

        fn is_end_stream(&self) -> bool {
            true
        }

        fn size_hint(&self) -> SizeHint {
            SizeHint::with_exact(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_addresses() {
        for ip in
            ["93.184.216.34", "1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "2a00:1450:4001::1"]
        {
            assert!(is_public(ip.parse().expect("ip")), "{ip}");
        }
        for ip in [
            "0.0.0.0",
            "10.1.2.3",
            "127.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.8",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.5",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "2001::1",
            "3fff::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::7f00:1",
            "64:ff9b::a9fe:a9fe",
            "2002:7f00:1::",
            "2002:c0a8:101::",
            "::127.0.0.1",
            "100::1",
            "fec0::1",
        ] {
            assert!(!is_public(ip.parse().expect("ip")), "{ip}");
        }
        assert!(is_public("::ffff:8.8.8.8".parse().expect("ip")), "mapped public v4");
        assert!(is_public("64:ff9b::808:808".parse().expect("ip")), "NAT64 of a public v4");
    }

    #[test]
    fn urls() {
        assert_eq!(
            parse_url("https://API.example.com/v1/x?q=1#frag"),
            Some(Target { host: "api.example.com".into(), path: "/v1/x?q=1".into() })
        );
        assert_eq!(parse_url("https://example.com").map(|t| t.path), Some("/".into()));
        assert_eq!(parse_url("https://example.com?q=1").map(|t| t.path), Some("/?q=1".into()));
        assert!(parse_url("https://example.com:443/x").is_some());
        for bad in [
            "http://example.com/",
            "https://example.com:8443/",
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://user:pw@example.com/",
            "https://example.com@evil.com/",
            "https://exa mple.com/",
            "https://exämple.com/",
            "https://example.com\\@evil.com/",
            "ftp://example.com/",
            "https:///x",
            "file:///etc/passwd",
        ] {
            assert_eq!(parse_url(bad), None, "{bad}");
        }
        let from = Target { host: "a.example.com".into(), path: "/".into() };
        assert_eq!(redirect(&from, "/next").map(|t| t.host), Some("a.example.com".into()));
        assert_eq!(
            redirect(&from, "https://b.example.com/").map(|t| t.host),
            Some("b.example.com".into())
        );
        for bad in ["http://a.example.com/", "//evil.com/x", "next", "https://169.254.169.254/"] {
            assert_eq!(redirect(&from, bad), None, "{bad}");
        }
    }

    #[tokio::test]
    async fn refuses_hosts_that_were_not_granted_and_private_names() {
        let allowed = vec!["localhost.".into(), "example.com".into()];
        assert_eq!(get("https://other.com/", &allowed).await, Err(FetchFailure::NotAllowed));
        // `localhost` resolves to loopback: blocked after resolution.
        let allowed = vec!["localhost".into()];
        assert_eq!(get("https://localhost/", &allowed).await, Err(FetchFailure::Blocked));
    }
}
