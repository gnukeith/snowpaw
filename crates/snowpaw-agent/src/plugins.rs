//! Running plugins: WebAssembly modules, in wasmtime, with nothing to reach.
//!
//! - A plugin module imports nothing (plugin API v1): no WASI, no host functions, so it
//!   can't touch files, the network, the clock, randomness or this process. A module
//!   that imports anything is refused.
//! - The code is checked against the SHA-256 the server sent with the grant.
//! - Every step runs in a fresh instance (no state carried between calls except what
//!   the plugin hands back explicitly), with a fuel budget (CPU), an epoch deadline
//!   (wall clock), a memory cap, a small stack, and bounded input and output.
//! - Network access only by returning `{"fetch": {"url": ...}}`: the runtime asks the
//!   server, which checks the URL against the hosts the user granted and fetches it.
//!   At most `MAX_FETCHES` per tool call.

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snowpaw_proto::Id;
use snowpaw_proto::agent::ToolSpec;
use snowpaw_proto::plugin::{Fetched, GrantedPlugin, PLUGIN_API_VERSION};
use wasmtime::{
    Config, Engine, ExternType, Linker, Module, OptLevel, Store, StoreLimits, StoreLimitsBuilder,
    ValType,
};

/// CPU per step (roughly a few seconds of work).
const FUEL_PER_STEP: u64 = 2_000_000_000;
const EPOCH_TICK: Duration = Duration::from_millis(50);
/// Wall clock per step: 100 ticks of 50 ms.
const DEADLINE_TICKS: u64 = 100;
const MAX_MEMORY_BYTES: usize = 64 * 1024 * 1024;
const MAX_STACK_BYTES: usize = 512 * 1024;
const MAX_INPUT_BYTES: usize = 2 * 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 256 * 1024;
/// Fetches one tool call may make.
pub const MAX_FETCHES: usize = 4;
/// Longest tool result given back to the model.
pub const MAX_RESULT_CHARS: usize = 16 * 1024;

/// What a plugin step is given.
#[derive(Debug, Clone, Serialize)]
pub struct StepInput {
    pub tool: String,
    pub args: serde_json::Value,
    pub state: serde_json::Value,
    pub fetched: Option<FetchOutcome>,
}

/// A fetch result as a plugin sees it.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum FetchOutcome {
    Ok(Fetched),
    Failed { error: String },
}

/// What a plugin step returned.
#[derive(Debug, Clone, PartialEq)]
pub enum StepOutput {
    Result(String),
    Error(String),
    Fetch { url: String, state: serde_json::Value },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOutput {
    #[serde(default)]
    result: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    fetch: Option<RawFetch>,
    #[serde(default)]
    state: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFetch {
    url: String,
}

fn parse_output(bytes: &[u8]) -> Result<StepOutput, String> {
    let raw: RawOutput = serde_json::from_slice(bytes)
        .map_err(|_| "the plugin returned malformed output".to_owned())?;
    match (raw.result, raw.error, raw.fetch) {
        (Some(r), None, None) => Ok(StepOutput::Result(r)),
        (None, Some(e), None) => Ok(StepOutput::Error(e)),
        (None, None, Some(f)) => Ok(StepOutput::Fetch { url: f.url, state: raw.state }),
        _ => Err("the plugin returned malformed output".into()),
    }
}

struct Loaded {
    grant: GrantedPlugin,
    module: Module,
}

pub struct PluginHost {
    engine: Engine,
    plugins: HashMap<Id, Loaded>,
}

impl std::fmt::Debug for PluginHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PluginHost({} plugins)", self.plugins.len())
    }
}

/// Exported functions every plugin must have, with their (params, results).
const EXPORTS: [(&str, &[ValType], &[ValType]); 4] = [
    ("snowpaw_api", &[], &[ValType::I32]),
    ("snowpaw_buffer", &[ValType::I32], &[ValType::I32]),
    ("snowpaw_run", &[ValType::I32], &[ValType::I32]),
    ("snowpaw_output", &[], &[ValType::I32]),
];

fn check_exports(module: &Module) -> Result<(), String> {
    if module.imports().len() != 0 {
        return Err("the plugin imports functions; plugins may not import anything".into());
    }
    if !matches!(module.get_export("memory"), Some(ExternType::Memory(_))) {
        return Err("the plugin doesn't export its memory".into());
    }
    for (name, params, results) in EXPORTS {
        let Some(ExternType::Func(f)) = module.get_export(name) else {
            return Err(format!("the plugin doesn't export {name}"));
        };
        let same = |a: &mut dyn ExactSizeIterator<Item = ValType>, b: &[ValType]| {
            a.len() == b.len() && a.zip(b).all(|(x, y)| ValType::eq(&x, y))
        };
        if !same(&mut f.params(), params) || !same(&mut f.results(), results) {
            return Err(format!("{name} has the wrong signature"));
        }
    }
    Ok(())
}

struct Limits {
    limits: StoreLimits,
}

/// One step in a fresh, limited instance.
fn run_step(engine: &Engine, module: &Module, input: &[u8]) -> Result<Vec<u8>, String> {
    let limits = StoreLimitsBuilder::new()
        .memory_size(MAX_MEMORY_BYTES)
        .table_elements(100_000)
        .instances(1)
        .tables(1)
        .memories(1)
        .trap_on_grow_failure(true)
        .build();
    let mut store = Store::new(engine, Limits { limits });
    store.limiter(|s| &mut s.limits);
    store.set_fuel(FUEL_PER_STEP).map_err(|e| e.to_string())?;
    store.set_epoch_deadline(DEADLINE_TICKS);
    store.epoch_deadline_trap();
    fn fail(what: &'static str) -> impl Fn(wasmtime::Error) -> String {
        move |e| format!("the plugin {what}: {}", e.root_cause())
    }
    let instance =
        Linker::new(engine).instantiate(&mut store, module).map_err(fail("failed to start"))?;
    let memory = instance.get_memory(&mut store, "memory").ok_or("no memory")?;
    let api =
        instance.get_typed_func::<(), i32>(&mut store, "snowpaw_api").map_err(fail("is broken"))?;
    if u32::try_from(api.call(&mut store, ()).map_err(fail("failed"))?) != Ok(PLUGIN_API_VERSION) {
        return Err("the plugin was built for a different plugin API version".into());
    }
    let buffer = instance
        .get_typed_func::<i32, i32>(&mut store, "snowpaw_buffer")
        .map_err(fail("is broken"))?;
    let run = instance
        .get_typed_func::<i32, i32>(&mut store, "snowpaw_run")
        .map_err(fail("is broken"))?;
    let output = instance
        .get_typed_func::<(), i32>(&mut store, "snowpaw_output")
        .map_err(fail("is broken"))?;
    let len = i32::try_from(input.len()).map_err(|_| "input too large")?;
    let at = buffer.call(&mut store, len).map_err(fail("failed"))?;
    let at = usize::try_from(at).map_err(|_| "the plugin gave a bad buffer address")?;
    // Bounds-checked by wasmtime: a bad address is an error, never a host write.
    memory.write(&mut store, at, input).map_err(|_| "the plugin gave a bad buffer address")?;
    let out_len = run.call(&mut store, len).map_err(fail("failed"))?;
    let out_len = usize::try_from(out_len)
        .ok()
        .filter(|n| *n <= MAX_OUTPUT_BYTES)
        .ok_or("the plugin's output is too large")?;
    let out_at = usize::try_from(output.call(&mut store, ()).map_err(fail("failed"))?)
        .map_err(|_| "the plugin gave a bad output address")?;
    let mut out = vec![0u8; out_len];
    memory.read(&store, out_at, &mut out).map_err(|_| "the plugin gave a bad output address")?;
    Ok(out)
}

impl PluginHost {
    pub fn new() -> Result<Self, String> {
        let mut config = Config::new();
        config
            .consume_fuel(true)
            .epoch_interruption(true)
            .max_wasm_stack(MAX_STACK_BYTES)
            .wasm_multi_memory(false)
            .wasm_memory64(false)
            .cranelift_opt_level(OptLevel::Speed);
        let engine = Engine::new(&config).map_err(|e| e.to_string())?;
        // Wall-clock deadlines: one epoch tick every 50 ms for the life of the process
        // (a runtime has one host).
        let ticker = engine.clone();
        std::thread::Builder::new()
            .name("plugin-epoch".into())
            .spawn(move || {
                loop {
                    ticker.increment_epoch();
                    std::thread::sleep(EPOCH_TICK);
                }
            })
            .map_err(|e| e.to_string())?;
        Ok(Self { engine, plugins: HashMap::new() })
    }

    /// Compile a granted plugin. The code must match the grant's hash.
    pub fn load(&mut self, grant: GrantedPlugin, wasm: &[u8]) -> Result<(), String> {
        let hash: [u8; 32] = Sha256::digest(wasm).into();
        if &hash != grant.hash.as_bytes() {
            return Err("the plugin's code doesn't match its hash".into());
        }
        let module =
            Module::new(&self.engine, wasm).map_err(|e| format!("not a valid module: {e}"))?;
        check_exports(&module)?;
        self.plugins.insert(grant.plugin, Loaded { grant, module });
        Ok(())
    }

    /// Keep only these plugins (grants can be revoked).
    pub fn retain(&mut self, granted: &[GrantedPlugin]) {
        self.plugins
            .retain(|id, p| granted.iter().any(|g| g.plugin == *id && g.hash == p.grant.hash));
    }

    pub fn has(&self, grant: &GrantedPlugin) -> bool {
        self.plugins.get(&grant.plugin).is_some_and(|p| p.grant.hash == grant.hash)
    }

    pub fn tools(&self) -> Vec<ToolSpec> {
        let mut tools: Vec<ToolSpec> =
            self.plugins.values().flat_map(|p| p.grant.tools.clone()).collect();
        tools.sort_by(|a, b| a.name.cmp(&b.name));
        tools
    }

    /// The plugin and tool behind a model-facing tool name (`<plugin>__<tool>`).
    pub fn find(&self, name: &str) -> Option<(Id, String)> {
        let (_, tool) = name.split_once("__")?;
        self.plugins
            .values()
            .find(|p| p.grant.tools.iter().any(|t| t.name == name))
            .map(|p| (p.grant.plugin, tool.to_owned()))
    }

    /// A job that runs one step on a blocking thread.
    pub fn step_job(
        &self,
        plugin: Id,
        input: &StepInput,
    ) -> Option<impl FnOnce() -> Result<StepOutput, String> + Send + 'static> {
        let p = self.plugins.get(&plugin)?;
        let (engine, module) = (self.engine.clone(), p.module.clone());
        let bytes = serde_json::to_vec(input).ok()?;
        Some(move || {
            if bytes.len() > MAX_INPUT_BYTES {
                return Err("the input for the plugin is too large".into());
            }
            parse_output(&run_step(&engine, &module, &bytes)?)
        })
    }
}

/// Cut a tool result to what the model gets.
pub fn clip(text: &str) -> String {
    if text.chars().count() <= MAX_RESULT_CHARS {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(MAX_RESULT_CHARS).collect();
    out.push_str("\n[cut: the result was longer]");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use snowpaw_proto::profile::BlobHash;

    /// A plugin whose `snowpaw_run` is `body` (it can read the input length in local 0
    /// and must leave the output length on the stack). Output lives at 4096; the input
    /// buffer at 1024.
    fn plugin(body: &str, data: &str) -> Vec<u8> {
        let escaped = data.replace('\\', "\\\\").replace('"', "\\\"");
        wat::parse_str(format!(
            r#"(module
                (memory (export "memory") 1)
                (func (export "snowpaw_api") (result i32) (i32.const 1))
                (func (export "snowpaw_buffer") (param i32) (result i32) (i32.const 1024))
                (func (export "snowpaw_output") (result i32) (i32.const 4096))
                (func (export "snowpaw_run") (param i32) (result i32) {body})
                (data (i32.const 4096) "{escaped}"))"#
        ))
        .expect("wat")
    }

    fn grant(wasm: &[u8]) -> GrantedPlugin {
        GrantedPlugin {
            plugin: Id::from_bytes([1; 16]),
            name: "demo".into(),
            version: "1".into(),
            hash: BlobHash::from_bytes(Sha256::digest(wasm).into()),
            tools: vec![ToolSpec {
                name: "demo__hello".into(),
                description: "d".into(),
                parameters: "{}".into(),
            }],
            http_hosts: vec![],
        }
    }

    fn input() -> StepInput {
        StepInput {
            tool: "hello".into(),
            args: serde_json::json!({}),
            state: serde_json::Value::Null,
            fetched: None,
        }
    }

    fn run(wasm: &[u8]) -> Result<StepOutput, String> {
        let mut host = PluginHost::new().expect("host");
        host.load(grant(wasm), wasm)?;
        let job = host.step_job(Id::from_bytes([1; 16]), &input()).expect("job");
        job()
    }

    #[test]
    fn a_plugin_answers() {
        let out = r#"{"result":"hello from wasm"}"#;
        let wasm = plugin(&format!("(i32.const {})", out.len()), out);
        assert_eq!(run(&wasm), Ok(StepOutput::Result("hello from wasm".into())));
        let fetch = r#"{"fetch":{"url":"https://api.example.com/x"},"state":{"n":1}}"#;
        let wasm = plugin(&format!("(i32.const {})", fetch.len()), fetch);
        assert_eq!(
            run(&wasm),
            Ok(StepOutput::Fetch {
                url: "https://api.example.com/x".into(),
                state: serde_json::json!({"n":1})
            })
        );
    }

    #[test]
    fn the_code_must_match_the_grant() {
        let out = r#"{"result":"x"}"#;
        let wasm = plugin(&format!("(i32.const {})", out.len()), out);
        let mut host = PluginHost::new().expect("host");
        let mut g = grant(&wasm);
        g.hash = BlobHash::from_bytes([0; 32]);
        assert!(host.load(g, &wasm).is_err());
    }

    #[test]
    fn plugins_cannot_import_anything() {
        let wasm = wat::parse_str(
            r#"(module
                (import "wasi_snapshot_preview1" "fd_write" (func (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (func (export "snowpaw_api") (result i32) (i32.const 1))
                (func (export "snowpaw_buffer") (param i32) (result i32) (i32.const 0))
                (func (export "snowpaw_output") (result i32) (i32.const 0))
                (func (export "snowpaw_run") (param i32) (result i32) (i32.const 0)))"#,
        )
        .expect("wat");
        let err = run(&wasm).expect_err("refused");
        assert!(err.contains("import"), "{err}");
    }

    #[test]
    fn endless_loops_run_out_of_fuel_or_time() {
        let wasm = plugin("(loop (br 0)) (i32.const 0)", "");
        let started = std::time::Instant::now();
        let err = run(&wasm).expect_err("stopped");
        assert!(err.contains("failed"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(20));
    }

    #[test]
    fn memory_is_capped() {
        // Try to grow to 4 GiB.
        let wasm = plugin("(drop (memory.grow (i32.const 65535))) (i32.const 0)", "");
        assert!(run(&wasm).is_err());
    }

    #[test]
    fn bad_addresses_and_sizes_are_refused() {
        let huge = plugin("(i32.const 100000000)", "");
        assert!(run(&huge).is_err(), "output length out of range");
        let negative = plugin("(i32.const -1)", "");
        assert!(run(&negative).is_err());
        let garbage = plugin("(i32.const 5)", "nope!");
        assert!(run(&garbage).is_err(), "not JSON");
        let ambiguous = r#"{"result":"a","error":"b"}"#;
        assert!(run(&plugin(&format!("(i32.const {})", ambiguous.len()), ambiguous)).is_err());
        // The module claims its buffer is beyond its memory.
        let wasm = wat::parse_str(
            r#"(module (memory (export "memory") 1)
                (func (export "snowpaw_api") (result i32) (i32.const 1))
                (func (export "snowpaw_buffer") (param i32) (result i32) (i32.const 65530))
                (func (export "snowpaw_output") (result i32) (i32.const 0))
                (func (export "snowpaw_run") (param i32) (result i32) (i32.const 0)))"#,
        )
        .expect("wat");
        let err = run(&wasm).expect_err("refused");
        assert!(err.contains("address"), "{err}");
    }

    #[test]
    fn wrong_signatures_and_api_versions_are_refused() {
        let wasm = wat::parse_str(
            r#"(module (memory (export "memory") 1)
                (func (export "snowpaw_api") (result i32) (i32.const 2))
                (func (export "snowpaw_buffer") (param i32) (result i32) (i32.const 0))
                (func (export "snowpaw_output") (result i32) (i32.const 0))
                (func (export "snowpaw_run") (param i32) (result i32) (i32.const 0)))"#,
        )
        .expect("wat");
        assert!(run(&wasm).expect_err("api").contains("API version"));
        let wasm = wat::parse_str(
            r#"(module (memory (export "memory") 1)
                (func (export "snowpaw_api") (result i32) (i32.const 1))
                (func (export "snowpaw_buffer") (param i64) (result i32) (i32.const 0))
                (func (export "snowpaw_output") (result i32) (i32.const 0))
                (func (export "snowpaw_run") (param i32) (result i32) (i32.const 0)))"#,
        )
        .expect("wat");
        assert!(run(&wasm).expect_err("sig").contains("signature"));
    }

    #[test]
    fn tool_names_map_back_to_plugins() {
        let out = r#"{"result":"x"}"#;
        let wasm = plugin(&format!("(i32.const {})", out.len()), out);
        let mut host = PluginHost::new().expect("host");
        host.load(grant(&wasm), &wasm).expect("load");
        assert_eq!(host.find("demo__hello"), Some((Id::from_bytes([1; 16]), "hello".into())));
        assert_eq!(host.find("demo__nope"), None);
        assert_eq!(host.tools().len(), 1);
        host.retain(&[]);
        assert!(host.tools().is_empty(), "revoked grants unload");
    }
}
