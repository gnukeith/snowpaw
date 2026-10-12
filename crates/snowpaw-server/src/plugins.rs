//! Plugin views for the user and for agent runtimes. The server stores plugins and
//! grants and checks fetches; it never runs plugin code (runtimes do, in wasmtime).

use snowpaw_proto::Id;
use snowpaw_proto::plugin::{GrantedPlugin, Manifest, PluginGrant, PluginView};
use snowpaw_proto::profile::BlobHash;
use tracing::error;

use crate::api::AppState;
use crate::db::{self, DbError, PluginRow};

fn manifest(row: &PluginRow) -> Option<Manifest> {
    // Validated at install; a row that no longer parses is skipped, not served.
    match Manifest::parse(&row.manifest) {
        Ok(m) => Some(m),
        Err(e) => {
            error!(plugin = %row.id, error = %e, "stored plugin manifest doesn't parse");
            None
        }
    }
}

pub fn view(row: &PluginRow, grants: Vec<(Id, Vec<String>)>) -> Option<PluginView> {
    let m = manifest(row)?;
    Some(PluginView {
        id: row.id,
        tools: m.tool_specs(),
        name: m.name,
        version: m.version,
        description: m.description,
        hash: BlobHash::from_bytes(row.hash),
        http_hosts: m.capabilities.http,
        grants: grants
            .into_iter()
            .map(|(agent, http_hosts)| PluginGrant { agent, http_hosts })
            .collect(),
    })
}

pub async fn list(st: &AppState) -> Result<Vec<PluginView>, DbError> {
    st.db
        .call(|c| {
            let mut out = vec![];
            for row in db::plugins(c)? {
                let grants = db::plugin_grants(c, row.id)?;
                out.extend(view(&row, grants));
            }
            Ok(out)
        })
        .await
}

pub async fn granted(st: &AppState, agent: Id) -> Result<Vec<GrantedPlugin>, DbError> {
    let rows = st.db.call(move |c| db::grants_for(c, agent)).await?;
    Ok(rows
        .into_iter()
        .filter_map(|(row, http_hosts)| {
            let m = manifest(&row)?;
            Some(GrantedPlugin {
                plugin: row.id,
                tools: m.tool_specs(),
                name: m.name,
                version: m.version,
                hash: BlobHash::from_bytes(row.hash),
                http_hosts,
            })
        })
        .collect())
}

/// Hosts `agent` may fetch from for `plugin` (`None`: not granted).
pub async fn granted_hosts(
    st: &AppState,
    agent: Id,
    plugin: Id,
) -> Result<Option<Vec<String>>, DbError> {
    Ok(granted(st, agent).await?.into_iter().find(|g| g.plugin == plugin).map(|g| g.http_hosts))
}
