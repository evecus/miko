//! 镜像输入解析：OCI image layout 目录、docker save tar（含新旧两种结构）。

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs::File;
use std::path::Path;
use tempfile::TempDir;

use super::{digest_hex, sha256_hex, ImageConfigFile, LayerSource, Loaded};
use crate::arch::HostArch;

#[derive(Debug, Clone, Deserialize)]
struct Descriptor {
    #[serde(rename = "mediaType", default)]
    media_type: String,
    digest: String,
    #[serde(default)]
    platform: Option<Platform>,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Platform {
    #[serde(default)]
    os: String,
    #[serde(default)]
    architecture: String,
}

#[derive(Debug, Deserialize)]
struct Index {
    #[serde(rename = "schemaVersion", default)]
    _schema_version: i32,
    #[serde(default)]
    manifests: Vec<Descriptor>,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    #[serde(rename = "schemaVersion", default)]
    _schema_version: i32,
    config: Descriptor,
    #[serde(default)]
    layers: Vec<Descriptor>,
}

#[derive(Debug, Deserialize)]
struct SaveManifest {
    #[serde(rename = "Config")]
    config: String,
    #[serde(rename = "RepoTags", default)]
    repo_tags: Vec<String>,
    #[serde(rename = "Layers", default)]
    layers: Vec<String>,
}

fn is_index_type(mt: &str) -> bool {
    mt.ends_with("index.v1+json") || mt.contains("manifest.list")
}

fn platform_match(d: &Descriptor, arch: HostArch) -> bool {
    match &d.platform {
        Some(p) => p.os == "linux" && arch.matches(&p.architecture),
        None => false,
    }
}

/// 从 index 里挑与宿主架构匹配的 manifest。
/// 唯一例外：只有一个条目且没写 platform 元数据时直接采用——很多工具导出的
/// 单架构 OCI layout 会省略该字段，此时不存在"选错架构"的问题。
fn pick(manifests: &[Descriptor], arch: HostArch) -> Result<&Descriptor> {
    if let Some(d) = manifests.iter().find(|d| platform_match(d, arch)) {
        return Ok(d);
    }
    if manifests.len() == 1 && manifests[0].platform.is_none() {
        return Ok(&manifests[0]);
    }
    let avail: Vec<String> = manifests
        .iter()
        .map(|d| match &d.platform {
            Some(p) => format!("{}/{} ({})", p.os, p.architecture, short(&d.digest)),
            None => format!("no platform ({})", short(&d.digest)),
        })
        .collect();
    bail!(
        "index.json 中没有匹配 {} 的 manifest，可用: [{}]（可用 --platform 覆盖）",
        arch.label(),
        avail.join(", ")
    )
}

fn short(d: &str) -> String {
    d.split(':')
        .nth(1)
        .map(|h| h[..8.min(h.len())].to_string())
        .unwrap_or_else(|| d.to_string())
}

fn blob_path(dir: &Path, digest: &str) -> Result<std::path::PathBuf> {
    let (algo, h) = digest
        .split_once(':')
        .with_context(|| format!("非法 digest {digest:?}"))?;
    if algo != "sha256" {
        bail!("不支持的摘要算法 {algo:?}（只实现 sha256）");
    }
    Ok(dir.join("blobs").join(algo).join(h))
}

fn read_blob(dir: &Path, digest: &str) -> Result<Vec<u8>> {
    let path = blob_path(dir, digest)?;
    let data =
        std::fs::read(&path).with_context(|| format!("读取 blob 失败: {}", path.display()))?;
    let got = sha256_hex(&data);
    if got != digest_hex(digest)? {
        bail!(
            "blob 摘要校验失败: {} (期望 {}, 实际 {})",
            path.display(),
            digest_hex(digest)?,
            got
        );
    }
    Ok(data)
}

fn resolve_manifest(dir: &Path, desc: &Descriptor, arch: HostArch) -> Result<Manifest> {
    let blob = read_blob(dir, &desc.digest)?;
    if is_index_type(&desc.media_type) {
        let idx: Index = serde_json::from_slice(&blob)
            .with_context(|| format!("解析 manifest list {} 失败", desc.digest))?;
        let sub = pick(&idx.manifests, arch)?;
        return resolve_manifest(dir, sub, arch);
    }
    serde_json::from_slice(&blob).with_context(|| format!("解析 manifest {} 失败", desc.digest))
}

/// OCI image layout：`oci-layout` + `index.json` + `blobs/<algo>/<hex>`
pub fn load_oci_layout(dir: &Path, arch: HostArch) -> Result<Loaded> {
    let index_data = std::fs::read(dir.join("index.json"))
        .with_context(|| format!("读取 {}/index.json 失败", dir.display()))?;
    let index: Index = serde_json::from_slice(&index_data).context("解析 index.json 失败")?;
    let desc = pick(&index.manifests, arch)?;
    let manifest = resolve_manifest(dir, desc, arch)?;

    let config_blob = read_blob(dir, &manifest.config.digest)?;
    let config: ImageConfigFile =
        serde_json::from_slice(&config_blob).context("解析 image config blob 失败")?;

    if manifest.layers.len() != config.rootfs.diff_ids.len() {
        bail!(
            "manifest 层数 {} 与 rootfs.diff_ids 数量 {} 不一致",
            manifest.layers.len(),
            config.rootfs.diff_ids.len()
        );
    }

    let layers = manifest
        .layers
        .iter()
        .enumerate()
        .map(|(i, l)| {
            Ok(LayerSource {
                path: blob_path(dir, &l.digest)?,
                digest: Some(l.digest.clone()),
                diff_id: Some(config.rootfs.diff_ids[i].clone()),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(Loaded {
        config,
        config_raw: config_blob,
        layers,
        description: format!(
            "oci-layout:{} ({})",
            dir.display(),
            desc.annotations
                .get("org.opencontainers.image.ref.name")
                .cloned()
                .unwrap_or_else(|| desc.digest.clone())
        ),
        repo_tags: desc
            .annotations
            .get("org.opencontainers.image.ref.name")
            .map(|s| {
                s.split(',')
                    .map(|x| x.trim().to_string())
                    .filter(|x| !x.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
    })
}

/// 已解包的 `docker save` 目录：manifest.json + Config json + Layers[]。
/// 兼容旧结构 `<layerid>/layer.tar` 与新结构 `blobs/sha256/<hex>`。
pub fn load_save_dir(dir: &Path) -> Result<Loaded> {
    let mf_data = std::fs::read(dir.join("manifest.json"))
        .with_context(|| format!("读取 {}/manifest.json 失败", dir.display()))?;
    let entries: Vec<SaveManifest> =
        serde_json::from_slice(&mf_data).context("解析 manifest.json 失败")?;
    let entry = entries.first().context("manifest.json 中没有镜像条目")?;

    let config_data = std::fs::read(dir.join(&entry.config))
        .with_context(|| format!("读取 image config {} 失败", entry.config))?;
    let config: ImageConfigFile =
        serde_json::from_slice(&config_data).context("解析 image config 失败")?;

    if config.rootfs.diff_ids.len() != entry.layers.len() {
        bail!(
            "rootfs.diff_ids 数量 {} 与 Layers 数量 {} 不一致",
            config.rootfs.diff_ids.len(),
            entry.layers.len()
        );
    }

    let layers = entry
        .layers
        .iter()
        .enumerate()
        .map(|(i, l)| LayerSource {
            path: dir.join(l),
            digest: None,
            diff_id: Some(config.rootfs.diff_ids[i].clone()),
        })
        .collect();

    Ok(Loaded {
        config,
        config_raw: config_data,
        layers,
        description: format!(
            "docker-save:{} ({})",
            dir.display(),
            entry
                .repo_tags
                .first()
                .cloned()
                .unwrap_or_else(|| "untagged".into())
        ),
        repo_tags: entry.repo_tags.clone(),
    })
}

/// 解析本地镜像输入：OCI layout 目录 / 已解包的 save 目录 / `docker save` tar
/// （新版 tar 直接是 OCI layout 结构，旧版是 manifest.json + Layers[]）。
/// `TempDir` 必须一直持有到调用方用完 `Loaded.layers` 里的路径为止。
pub fn load_local(path: &Path, platform: HostArch) -> Result<(Loaded, Option<TempDir>)> {
    if path.is_dir() {
        let loaded = if path.join("oci-layout").is_file() {
            load_oci_layout(path, platform)?
        } else if path.join("manifest.json").is_file() {
            load_save_dir(path)?
        } else {
            bail!(
                "目录 {} 不是 OCI image layout（缺少 oci-layout），也不是已解包的 save tar（缺少 manifest.json）",
                path.display()
            );
        };
        return Ok((loaded, None));
    }

    if path.is_file() {
        let tmp = tempfile::Builder::new()
            .prefix("miko-img-")
            .tempdir()
            .context("创建镜像解包临时目录失败")?;
        unpack_tar(path, tmp.path())?;
        let loaded =
            if tmp.path().join("oci-layout").is_file() && tmp.path().join("index.json").is_file() {
                load_oci_layout(tmp.path(), platform)?
            } else {
                load_save_dir(tmp.path())?
            };
        return Ok((loaded, Some(tmp)));
    }

    bail!("镜像输入 {} 既不是文件也不是目录", path.display())
}

pub fn unpack_tar(path: &Path, dir: &Path) -> Result<()> {
    let f = File::open(path).with_context(|| format!("打开 {} 失败", path.display()))?;
    let mut ar = tar::Archive::new(f);
    ar.unpack(dir)
        .with_context(|| format!("解包 {} 失败（不是合法的 tar？）", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desc(os: &str, arch: &str, digest: &str) -> Descriptor {
        Descriptor {
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            digest: digest.into(),
            platform: Some(Platform {
                os: os.into(),
                architecture: arch.into(),
            }),
            annotations: Default::default(),
        }
    }

    #[test]
    fn index_picks_host_arch() {
        let want = crate::arch::host().unwrap();
        let other = if want == HostArch::Amd64 {
            HostArch::Arm64
        } else {
            HostArch::Amd64
        };
        let items = vec![
            desc("linux", "amd64", "sha256:aaa"),
            desc("linux", "arm64", "sha256:bbb"),
        ];
        let picked = pick(&items, want).unwrap();
        assert_eq!(
            picked.platform.as_ref().unwrap().architecture,
            want.oci_name()
        );
        assert!(pick(&items, other).is_ok()); // 另一架构也有对应条目
    }

    #[test]
    fn index_rejects_missing_arch_but_accepts_single_unlabelled() {
        let want = crate::arch::host().unwrap();
        let items = vec![desc("linux", "riscv64", "sha256:aaa")];
        assert!(pick(&items, want).is_err());

        let single = vec![Descriptor {
            media_type: String::new(),
            digest: "sha256:x".into(),
            platform: None,
            annotations: Default::default(),
        }];
        assert!(pick(&single, want).is_ok());
        assert!(pick(&[], want).is_err());
    }
}
