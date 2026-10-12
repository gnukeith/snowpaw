//! Example snowpaw plugin: current weather from Open-Meteo.
//!
//! Step 1 asks the runtime to fetch the forecast URL; step 2 gets the response and
//! turns it into a sentence for the model. The plugin itself can't reach anything:
//! the fetch happens on the server, only to the host the user allowed.

use snowpaw_plugin_sdk::{Call, Fetched, Reply, Value, json};

snowpaw_plugin_sdk::manifest!("../manifest.json");
snowpaw_plugin_sdk::plugin!(handle);

fn handle(call: Call) -> Reply {
    if call.tool != "current" {
        return Reply::Error(format!("unknown tool {}", call.tool));
    }
    let (Some(lat), Some(lon)) = (call.args["latitude"].as_f64(), call.args["longitude"].as_f64()) else {
        return Reply::Error("latitude and longitude must be numbers".into());
    };
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return Reply::Error("latitude or longitude out of range".into());
    }
    match call.fetched {
        None => Reply::Fetch {
            url: format!(
                "https://api.open-meteo.com/v1/forecast?latitude={lat:.4}&longitude={lon:.4}&current=temperature_2m,wind_speed_10m"
            ),
            state: json!({}),
        },
        Some(Fetched::Failed(e)) => Reply::Error(format!("couldn't reach Open-Meteo: {e}")),
        Some(Fetched::Ok { status, body, .. }) if status == 200 => {
            let Ok(v) = serde_json_from(&body) else {
                return Reply::Error("Open-Meteo sent something unexpected".into());
            };
            let current = &v["current"];
            match (current["temperature_2m"].as_f64(), current["wind_speed_10m"].as_f64()) {
                (Some(t), Some(w)) => Reply::Result(format!("It's {t:.1} °C with wind at {w:.0} km/h.")),
                _ => Reply::Error("Open-Meteo's answer had no current weather".into()),
            }
        }
        Some(Fetched::Ok { status, .. }) => Reply::Error(format!("Open-Meteo answered {status}")),
    }
}

fn serde_json_from(text: &str) -> Result<Value, ()> {
    snowpaw_plugin_sdk::serde_json::from_str(text).map_err(|_| ())
}
