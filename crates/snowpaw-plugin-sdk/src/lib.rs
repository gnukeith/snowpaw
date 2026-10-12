//! Write snowpaw plugins: tools for agents, compiled to WebAssembly.
//!
//! A plugin is a function from a tool call to a reply. It runs in a sandbox with
//! nothing to reach: no files, no network, no clock. To get data from the web it
//! returns [`Reply::Fetch`]; the agent's runtime asks the snowpaw server, which
//! fetches the URL only if the user allowed that host for this plugin, and calls the
//! plugin again with the response in [`Call::fetched`] and your `state` back.
//!
//! ```ignore
//! use snowpaw_plugin_sdk::{Call, Reply, json};
//!
//! snowpaw_plugin_sdk::manifest!("../manifest.json");
//! snowpaw_plugin_sdk::plugin!(handle);
//!
//! fn handle(call: Call) -> Reply {
//!     match call.tool.as_str() {
//!         "hello" => Reply::Result(format!("Hello, {}!", call.args["name"].as_str().unwrap_or("you"))),
//!         _ => Reply::Error("unknown tool".into()),
//!     }
//! }
//! ```
//!
//! Build with `cargo build --release --target wasm32-unknown-unknown` (crate type
//! `cdylib`), then install the `.wasm` file from the snowpaw app.
//!
//! The manifest (JSON, embedded by [`manifest!`]) names the plugin, its tools with
//! their JSON Schema parameters, and the hosts it wants to fetch from:
//!
//! ```json
//! {"api": 1, "name": "hello", "version": "1.0.0", "description": "Says hello",
//!  "tools": [{"name": "hello", "description": "Greet someone",
//!             "parameters": {"type": "object", "properties": {"name": {"type": "string"}}}}],
//!  "capabilities": {"http": []}}
//! ```

pub use serde_json::{self, Value, json};

/// The plugin API this SDK implements.
pub const API_VERSION: i32 = 1;

/// One call of a tool.
#[derive(Debug, Clone, PartialEq)]
pub struct Call {
    pub tool: String,
    pub args: Value,
    /// What you returned with your last [`Reply::Fetch`] (`null` on the first step).
    pub state: Value,
    /// The response to your last [`Reply::Fetch`], if any.
    pub fetched: Option<Fetched>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetched {
    Ok {
        status: u16,
        content_type: String,
        body: String,
    },
    /// The fetch was refused or failed (host not allowed, not public, too large...).
    Failed(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    /// Text for the model.
    Result(String),
    /// Something went wrong; the model is told.
    Error(String),
    /// Fetch this HTTPS URL, then call me again with the response and `state`.
    Fetch { url: String, state: Value },
}

fn parse(input: &[u8]) -> Option<Call> {
    let v: Value = serde_json::from_slice(input).ok()?;
    let fetched = match v.get("fetched") {
        None | Some(Value::Null) => None,
        Some(f) => Some(match f.get("error").and_then(Value::as_str) {
            Some(e) => Fetched::Failed(e.to_owned()),
            None => Fetched::Ok {
                status: u16::try_from(f.get("status")?.as_u64()?).ok()?,
                content_type: f.get("content_type")?.as_str()?.to_owned(),
                body: f.get("body")?.as_str()?.to_owned(),
            },
        }),
    };
    Some(Call {
        tool: v.get("tool")?.as_str()?.to_owned(),
        args: v.get("args").cloned().unwrap_or(Value::Null),
        state: v.get("state").cloned().unwrap_or(Value::Null),
        fetched,
    })
}

/// Used by [`plugin!`]: input bytes -> output bytes.
#[doc(hidden)]
pub fn __handle(input: &[u8], handler: fn(Call) -> Reply) -> Vec<u8> {
    let reply = match parse(input) {
        Some(call) => handler(call),
        None => Reply::Error("the plugin couldn't read its input".into()),
    };
    let out = match reply {
        Reply::Result(r) => json!({ "result": r }),
        Reply::Error(e) => json!({ "error": e }),
        Reply::Fetch { url, state } => json!({ "fetch": { "url": url }, "state": state }),
    };
    serde_json::to_vec(&out).unwrap_or_default()
}

/// Export the plugin API v1 functions around `handler: fn(Call) -> Reply`.
///
/// Expands to the four exported functions the runtime calls. Use it once, in your
/// plugin crate (a `cdylib` built for `wasm32-unknown-unknown`).
#[macro_export]
macro_rules! plugin {
    ($handler:path) => {
        static __SNOWPAW_BUF: ::std::sync::Mutex<::std::vec::Vec<u8>> =
            ::std::sync::Mutex::new(::std::vec::Vec::new());

        fn __snowpaw_buf() -> ::std::sync::MutexGuard<'static, ::std::vec::Vec<u8>> {
            __SNOWPAW_BUF.lock().unwrap_or_else(|e| e.into_inner())
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn snowpaw_api() -> i32 {
            $crate::API_VERSION
        }

        /// Room for `len` input bytes; the runtime writes them at the returned address.
        #[unsafe(no_mangle)]
        pub extern "C" fn snowpaw_buffer(len: i32) -> i32 {
            let mut buf = __snowpaw_buf();
            buf.clear();
            buf.resize(usize::try_from(len).unwrap_or(0), 0);
            buf.as_mut_ptr() as usize as i32
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn snowpaw_run(len: i32) -> i32 {
            let mut buf = __snowpaw_buf();
            let n = usize::try_from(len).unwrap_or(0).min(buf.len());
            let input = buf[..n].to_vec();
            *buf = $crate::__handle(&input, $handler);
            i32::try_from(buf.len()).unwrap_or(0)
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn snowpaw_output() -> i32 {
            __snowpaw_buf().as_ptr() as usize as i32
        }
    };
}

/// Embed the manifest (a JSON file, path relative to the calling file) in the
/// module's `snowpaw-manifest` custom section.
#[macro_export]
macro_rules! manifest {
    ($path:literal) => {
        #[unsafe(link_section = "snowpaw-manifest")]
        #[used]
        static __SNOWPAW_MANIFEST: [u8; include_bytes!($path).len()] = *include_bytes!($path);
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn echo(call: Call) -> Reply {
        match (call.tool.as_str(), &call.fetched) {
            ("get", None) => {
                Reply::Fetch { url: "https://example.com/".into(), state: json!({"step": 1}) }
            }
            ("get", Some(Fetched::Ok { body, .. })) => {
                Reply::Result(format!("got {body} at {}", call.state["step"]))
            }
            ("get", Some(Fetched::Failed(e))) => Reply::Error(e.clone()),
            _ => Reply::Result(call.args["text"].as_str().unwrap_or_default().to_owned()),
        }
    }

    fn run(input: Value) -> Value {
        serde_json::from_slice(&__handle(&serde_json::to_vec(&input).expect("json"), echo))
            .expect("out")
    }

    #[test]
    fn round_trips() {
        assert_eq!(
            run(json!({"tool":"echo","args":{"text":"hi"},"state":null,"fetched":null})),
            json!({"result":"hi"})
        );
        assert_eq!(
            run(json!({"tool":"get","args":{},"state":null,"fetched":null})),
            json!({"fetch":{"url":"https://example.com/"},"state":{"step":1}})
        );
        assert_eq!(
            run(json!({"tool":"get","args":{},"state":{"step":1},
                       "fetched":{"status":200,"content_type":"text/plain","body":"data"}})),
            json!({"result":"got data at 1"})
        );
        assert_eq!(
            run(
                json!({"tool":"get","args":{},"state":{"step":1},"fetched":{"error":"not_allowed"}})
            ),
            json!({"error":"not_allowed"})
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&__handle(b"garbage", echo)).expect("out"),
            json!({"error":"the plugin couldn't read its input"})
        );
    }
}
