pub mod layer;
pub mod registry;
pub mod source;
pub mod store;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// OCI / Docker image config（`config.json` blob 或 save tar 里的 `<hash>.json`）
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ImageConfigFile {
    #[serde(default)]
    pub architecture: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub config: ImageRuntimeConfig,
    #[serde(default)]
    pub rootfs: RootFs,
    #[serde(default)]
    pub history: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ImageRuntimeConfig {
    #[serde(rename = "Entrypoint", default)]
    pub entrypoint: Option<Vec<String>>,
    #[serde(rename = "Cmd", default)]
    pub cmd: Option<Vec<String>>,
    #[serde(rename = "Env", default)]
    pub env: Vec<String>,
    #[serde(rename = "WorkingDir", default)]
    pub working_dir: String,
    #[serde(rename = "User", default)]
    pub user: String,
    #[serde(rename = "StopSignal", default)]
    pub stop_signal: String,
    #[serde(rename = "Labels", default)]
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RootFs {
    #[serde(rename = "type", default)]
    pub typ: String,
    #[serde(default)]
    pub diff_ids: Vec<String>,
}

/// 一层镜像：压缩方式由内容魔数自动判定（tar / tar+gzip / tar+zstd）
#[derive(Debug, Clone)]
pub struct LayerSource {
    pub path: PathBuf,
    /// 压缩后 blob 的 `sha256:...`（blob 库内可校验）
    pub digest: Option<String>,
    /// 未压缩 tar 的 `sha256:...`，对应 rootfs.diff_ids[i]
    pub diff_id: Option<String>,
}

/// 解析一份镜像输入得到的中间结果；`config_raw` 是 config blob 的原始字节，
/// 本地导入时按它算 image id（与 registry / OCI 语义一致）。
pub struct Loaded {
    pub config: ImageConfigFile,
    pub config_raw: Vec<u8>,
    pub layers: Vec<LayerSource>,
    pub description: String,
    /// 源镜像自带的引用：docker save 的 `RepoTags` / OCI layout 的
    /// `org.opencontainers.image.ref.name`（逗号分隔）；`load --tag` 会在此基础上追加。
    pub repo_tags: Vec<String>,
}

/// 交给 spec::build 的镜像视图：所有层都已落在本地 blob 库里，
/// 不再持有临时目录（TempDir 在导入 store 时就结束了生命周期）。
pub struct Image {
    pub config: ImageConfigFile,
    pub layers: Vec<LayerSource>,
    pub description: String,
}

impl Image {
    pub fn new(config: ImageConfigFile, layers: Vec<LayerSource>, description: String) -> Self {
        Self {
            config,
            layers,
            description,
        }
    }
}

pub fn hex(data: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0x0f) as usize] as char);
    }
    s
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    hex(&h.finalize())
}

pub fn digest_hex(digest: &str) -> Result<&str> {
    let (_, h) = digest
        .split_once(':')
        .with_context(|| format!("非法 digest {digest:?}"))?;
    Ok(h)
}
