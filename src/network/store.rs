//! networks.json：网络对象与 endpoint 的持久化。
//!
//! 与 state.json 共用 `state.lock` 上的 flock，所有 read-modify-write 串行化；
//! 写入走 tmp + rename，避免 supervisor / CLI 并发读到半截文件。

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::model::{self, Network};
use crate::state;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct NetworkStore {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub networks: BTreeMap<String, Network>,
}

pub fn path(root: &Path) -> PathBuf {
    root.join("networks.json")
}

fn read_file(root: &Path) -> Result<NetworkStore> {
    let p = path(root);
    match fs::read(&p) {
        Ok(data) => {
            serde_json::from_slice(&data).with_context(|| format!("解析 {} 失败", p.display()))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(NetworkStore::default()),
        Err(e) => Err(e).with_context(|| format!("读取 {} 失败", p.display())),
    }
}

fn write_file(root: &Path, store: &NetworkStore) -> Result<()> {
    fs::create_dir_all(root).with_context(|| format!("创建状态根目录 {} 失败", root.display()))?;
    let final_path = path(root);
    let tmp = root.join("networks.json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(store)?)
        .with_context(|| format!("写入 {} 失败", tmp.display()))?;
    fs::rename(&tmp, &final_path).with_context(|| format!("提交 {} 失败", final_path.display()))?;
    Ok(())
}

/// 载入并补齐内置网络（bridge / host / none）。内置网络按名字去重，
/// 首次生成的随机 id 会随文件持久化，后续启动保持不变。
fn load(root: &Path) -> Result<NetworkStore> {
    let mut store = read_file(root)?;
    store.version = 1;
    let mut changed = false;
    for builtin in model::default_networks(state::now()) {
        let exists = store
            .networks
            .values()
            .any(|n| n.builtin && n.name == builtin.name);
        if !exists {
            store.networks.insert(builtin.id.clone(), builtin);
            changed = true;
        }
    }
    // 首次访问就落盘：只读命令（ls / inspect）也必须让内置网络的 id 与 Created
    // 在后续进程里保持稳定，否则每条命令都会重新生成一套内置网络。
    if changed {
        write_file(root, &store)?;
    }
    Ok(store)
}

/// 只读快照（仍持锁，保证读到的 JSON 是完整提交的）。
pub fn read_only(root: &Path) -> Result<NetworkStore> {
    let _g = state::lock(root)?;
    load(root)
}

/// 修改网络的唯一入口：持 flock -> 载入 -> 闭包 -> 原子写回。
/// 注意：闭包内不要再调用任何会拿同一把锁的函数（会读到未提交的旧快照）。
pub fn with_store<R>(root: &Path, f: impl FnOnce(&mut NetworkStore) -> Result<R>) -> Result<R> {
    let _g = state::lock(root)?;
    let mut store = load(root)?;
    let result = f(&mut store)?;
    write_file(root, &store)?;
    Ok(result)
}

/// 精确 id / 精确 name / 唯一 id 前缀。
pub fn find_id(store: &NetworkStore, reference: &str) -> Result<String> {
    if store.networks.contains_key(reference) {
        return Ok(reference.to_string());
    }
    if let Some(n) = store.networks.values().find(|n| n.name == reference) {
        return Ok(n.id.clone());
    }
    let hits: Vec<&str> = store
        .networks
        .keys()
        .filter(|id| id.starts_with(reference))
        .map(String::as_str)
        .collect();
    match hits.len() {
        0 => bail!("找不到网络 {reference:?}（用 miko network ls 查看）"),
        1 => Ok(hits[0].to_string()),
        n => bail!("{reference:?} 匹配到 {n} 个网络，请给出完整 id"),
    }
}

pub fn get<'a>(store: &'a NetworkStore, reference: &str) -> Result<&'a Network> {
    let id = find_id(store, reference)?;
    Ok(&store.networks[&id])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_networks_are_created_once_and_stable() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let first = read_only(root).unwrap();
        assert_eq!(first.networks.len(), 3);
        let bridge_id = first
            .networks
            .values()
            .find(|n| n.name == "bridge")
            .unwrap()
            .id
            .clone();
        // 写回后再读，内置网络不会重复生成、id 不变
        write_file(root, &first).unwrap();
        let second = read_only(root).unwrap();
        assert_eq!(second.networks.len(), 3);
        assert_eq!(
            second.networks[&bridge_id].driver,
            model::DriverKind::Bridge
        );
    }

    #[test]
    fn lookup_by_name_id_and_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let store = read_only(root).unwrap();
        let id = find_id(&store, "bridge").unwrap();
        assert_eq!(find_id(&store, &id).unwrap(), id);
        assert_eq!(find_id(&store, &id[..8]).unwrap(), id);
        assert!(find_id(&store, "missing").is_err());
        assert_eq!(get(&store, "none").unwrap().driver, model::DriverKind::None);
    }
}
