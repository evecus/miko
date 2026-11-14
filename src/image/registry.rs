//! Registry Distribution v2 直拉：Bearer token 鉴权 -> manifest(list) -> config/layer blob。
//!
//! 拉下来的 blob 直接按 `sha256:<hex>` 落到本地镜像库 `<state_root>/images/blobs/`，
//! 不落成临时 OCI layout：内容寻址天然跨镜像复用（同一层只存一份、只下一次）。
//! config 与各层用线程池并发下载，不调用 docker / skopeo / crane，HTTP 由 ureq(rustls) 完成。

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, Permissions};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::Duration;

use super::{digest_hex, hex, sha256_hex, ImageConfigFile};
use crate::arch::HostArch;

const MT_OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const MT_DOCKER_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";

const ACCEPT_MANIFEST: &str = "application/vnd.oci.image.index.v1+json, \
     application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.list.v2+json, \
     application/vnd.docker.distribution.manifest.v2+json";

// ---------------------------------------------------------------- 引用解析

#[derive(Debug, Clone)]
pub struct ImageRef {
    pub base: String,
    pub repo: String,
    pub reference: String,
}

/// 规范化后的引用：本地镜像库的 tag key，以及给用户看的展示串。
#[derive(Debug, Clone)]
pub struct RefKey {
    pub key: String,
    pub display: String,
}

/// 判断一个非本地路径字符串是否像镜像引用。
pub fn looks_like_ref(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('.')
        && !s.starts_with('/')
        && !s.contains(char::is_whitespace)
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "./_:@-".contains(c))
}

pub fn parse_ref(input: &str, insecure: bool) -> Result<ImageRef> {
    let mut s = input.to_string();
    let mut force_http = insecure;
    if let Some(rest) = s.strip_prefix("http://") {
        force_http = true;
        s = rest.to_string();
    } else if let Some(rest) = s.strip_prefix("https://") {
        s = rest.to_string();
    }

    // 只有带 '/' 且第一段像 host（含 '.' / ':' 端口 / localhost）时才是第三方 registry；
    // 否则一律按 Docker Hub 处理，避免把 `busybox:latest` 的 :tag 误认成端口。
    let has_slash = s.contains('/');
    let first = s.split('/').next().unwrap_or("");
    let (host, rest) =
        if has_slash && (first.contains('.') || first.contains(':') || first == "localhost") {
            let (h, r) = s.split_once('/').context("registry 引用缺少仓库名")?;
            (h.to_string(), r.to_string())
        } else {
            ("docker.io".to_string(), s.clone())
        };

    // 分离 tag / digest
    let (name, reference) = if let Some((n, d)) = rest.rsplit_once('@') {
        if !d.starts_with("sha256:") {
            bail!("只支持 sha256 digest 引用，收到 {d:?}");
        }
        (n.to_string(), d.to_string())
    } else if let Some((n, t)) = rest.rsplit_once(':') {
        // 端口里的冒号已在 host 部分被切走，这里的冒号一定是 tag
        (n.to_string(), t.to_string())
    } else {
        (rest.clone(), "latest".to_string())
    };
    if name.is_empty() || reference.is_empty() {
        bail!("非法镜像引用 {input:?}");
    }

    // `library/` 是 Docker Hub 的官方镜像命名空间，第三方 registry 不适用。
    let repo = if name.contains('/') || host != "docker.io" {
        name
    } else {
        format!("library/{name}")
    };

    let base = match host.as_str() {
        "docker.io" | "registry-1.docker.io" | "index.docker.io" => {
            if force_http {
                "http://registry-1.docker.io".to_string()
            } else {
                "https://registry-1.docker.io".to_string()
            }
        }
        h => {
            let scheme = if force_http { "http" } else { "https" };
            format!("{scheme}://{h}")
        }
    };

    Ok(ImageRef {
        base,
        repo,
        reference,
    })
}

/// tag key 不含 scheme：http/https（--insecure-registry）不影响缓存身份，
/// `busybox`、`busybox:latest`、`docker.io/library/busybox:latest` 归一到同一个 key。
pub fn canonical_ref(input: &str, insecure: bool) -> Result<RefKey> {
    let r = parse_ref(input, insecure)?;
    let mut host = r
        .base
        .split_once("://")
        .map(|(_, h)| h)
        .unwrap_or(&r.base)
        .to_string();
    if host == "registry-1.docker.io" {
        host = "docker.io".to_string();
    }
    let sep = if r.reference.starts_with("sha256:") {
        '@'
    } else {
        ':'
    };
    let display = format!("{}/{}{}{}", host, r.repo, sep, r.reference);
    Ok(RefKey {
        key: display.clone(),
        display,
    })
}

// ---------------------------------------------------------------- manifest 结构

#[derive(Debug, Deserialize)]
struct Descriptor {
    digest: String,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    platform: Option<Platform>,
}

#[derive(Debug, Deserialize)]
struct Platform {
    #[serde(default)]
    os: String,
    #[serde(default)]
    architecture: String,
}

#[derive(Debug, Deserialize)]
struct Index {
    #[serde(default)]
    manifests: Vec<Descriptor>,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    #[serde(rename = "schemaVersion", default)]
    schema_version: i32,
    config: Descriptor,
    #[serde(default)]
    layers: Vec<Descriptor>,
}

fn is_index(mt: &str) -> bool {
    mt == MT_OCI_INDEX || mt == MT_DOCKER_LIST
}

/// 一次拉取的结果：所有内容已在 blob 库中，元数据交给 store 落索引。
#[derive(Debug, Clone)]
pub struct PulledLayer {
    pub digest: String,
    pub diff_id: String,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct Pulled {
    pub ref_key: RefKey,
    pub manifest_digest: String,
    pub config_digest: String,
    pub config: ImageConfigFile,
    pub layers: Vec<PulledLayer>,
}

// ---------------------------------------------------------------- HTTP 客户端

struct Client {
    agent: ureq::Agent,
    base: String,
    repo: String,
    token: Option<String>,
}

impl Client {
    fn new(r: &ImageRef) -> Result<Self> {
        // `tls` feature 让 ureq 使用 rustls + 内联 webpki-roots 根证书，
        // 不链接系统 OpenSSL：aarch64 交叉编译 / Armbian 部署都不需要目标机 libssl。
        let agent = ureq::builder().timeout(Duration::from_secs(180)).build();
        Ok(Self {
            agent,
            base: r.base.clone(),
            repo: r.repo.clone(),
            token: None,
        })
    }

    /// 并发 worker：复用主线程已换到的 token，但各自持有独立 agent（ureq::Agent 非 Sync）。
    fn worker(r: &ImageRef, token: Option<String>) -> Result<Self> {
        Ok(Self {
            agent: ureq::builder().timeout(Duration::from_secs(180)).build(),
            base: r.base.clone(),
            repo: r.repo.clone(),
            token,
        })
    }

    fn url(&self, tail: &str) -> String {
        format!("{}/v2/{}/{}", self.base, self.repo, tail)
    }

    /// 带 Bearer token 的 GET；首次 401 时按 WWW-Authenticate 取 token 并重试一次。
    fn get(&mut self, url: &str, accept: Option<&str>) -> Result<ureq::Response> {
        let agent = &self.agent;
        let do_call = |token: Option<&String>| -> Result<ureq::Response, ureq::Error> {
            let mut req = agent.get(url);
            if let Some(a) = accept {
                req = req.set("Accept", a);
            }
            if let Some(t) = token {
                req = req.set("Authorization", &format!("Bearer {t}"));
            }
            req.call()
        };

        match do_call(self.token.as_ref()) {
            Ok(resp) => Ok(resp),
            Err(ureq::Error::Status(401, challenge)) => {
                let www = challenge
                    .header("WWW-Authenticate")
                    .context("registry 返回 401 但没有 WWW-Authenticate 头")?
                    .to_string();
                let token = fetch_token(agent, &www).context("获取 registry Bearer token 失败")?;
                self.token = Some(token);
                do_call(self.token.as_ref())
                    .with_context(|| format!("携带 token 请求 {url} 仍失败"))
            }
            Err(e) => bail!("请求 {url} 失败: {e}"),
        }
    }

    fn get_bytes(&mut self, url: &str, accept: Option<&str>) -> Result<(Vec<u8>, Option<String>)> {
        let resp = self.get(url, accept)?;
        let mt = resp
            .header("Content-Type")
            .map(|s| s.split(';').next().unwrap_or(s).trim().to_string());
        let mut buf = Vec::new();
        resp.into_reader()
            .read_to_end(&mut buf)
            .context("读取响应体失败")?;
        Ok((buf, mt))
    }
}

/// 解析 `Bearer realm="...",service="...",scope="..."` 并换取 token。
fn fetch_token(agent: &ureq::Agent, www: &str) -> Result<String> {
    let rest = www
        .strip_prefix("Bearer ")
        .or_else(|| www.strip_prefix("bearer "))
        .with_context(|| format!("不支持的 WWW-Authenticate: {www:?}"))?;
    let mut params: BTreeMap<String, String> = BTreeMap::new();
    for part in split_auth_params(rest) {
        if let Some((k, v)) = part.split_once('=') {
            params.insert(
                k.trim().to_ascii_lowercase(),
                v.trim().trim_matches('"').to_string(),
            );
        }
    }
    let realm = params
        .get("realm")
        .context("Bearer 挑战缺少 realm")?
        .clone();
    let mut url = realm;
    let mut first = true;
    for key in ["service", "scope"] {
        if let Some(v) = params.get(key) {
            url.push(if first { '?' } else { '&' });
            url.push_str(key);
            url.push('=');
            url.push_str(&percent_encode(v));
            first = false;
        }
    }
    let mut body = String::new();
    agent
        .get(&url)
        .call()
        .with_context(|| format!("请求 token 端点 {url} 失败"))?
        .into_reader()
        .read_to_string(&mut body)
        .context("读取 token 响应失败")?;
    let json: serde_json::Value = serde_json::from_str(&body).context("token 响应不是 JSON")?;
    json.get("token")
        .or_else(|| json.get("access_token"))
        .and_then(|v| v.as_str())
        .map(String::from)
        .context("token 响应中没有 token / access_token 字段")
}

/// 按逗号切分，但忽略引号内的逗号。
fn split_auth_params(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in s.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                cur.push(c);
            }
            ',' if !quoted => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

// ---------------------------------------------------------------- blob 库（内容寻址）

/// `<blobs>/sha256/<hex>`；digest 严格校验，顺手建好目录。
pub fn blob_path(blobs: &Path, digest: &str) -> Result<PathBuf> {
    let (algo, h) = digest
        .split_once(':')
        .with_context(|| format!("非法 digest {digest:?}"))?;
    if algo != "sha256" || h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("非法 digest {digest:?}");
    }
    let dir = blobs.join(algo);
    fs::create_dir_all(&dir)?;
    Ok(dir.join(h))
}

/// 把一段内容写入 blob 库，返回 `sha256:<hex>`；已存在则直接返回（幂等）。
/// 用临时文件 + rename，避免崩溃留下"看起来存在"的半成品 blob。
pub fn store_blob(blobs: &Path, data: &[u8]) -> Result<String> {
    let digest = format!("sha256:{}", sha256_hex(data));
    let dest = blob_path(blobs, &digest)?;
    if dest.is_file() {
        return Ok(digest);
    }
    let mut tmp = tempfile::Builder::new()
        .prefix(".blob-")
        .tempfile_in(dest.parent().unwrap())?;
    tmp.write_all(data)?;
    tmp.flush()?;
    let f = tmp
        .persist(&dest)
        .with_context(|| format!("落盘 blob {} 失败", dest.display()))?;
    drop(f);
    fs::set_permissions(&dest, Permissions::from_mode(0o644))?;
    Ok(digest)
}

/// 从 blob 库读取并校验摘要（缓存被手工改坏时fail-fast，提示删掉重拉）。
pub fn read_blob_checked(blobs: &Path, digest: &str) -> Result<Vec<u8>> {
    let path = blob_path(blobs, digest)?;
    let data = fs::read(&path).with_context(|| format!("读取 blob 失败: {}", path.display()))?;
    let got = sha256_hex(&data);
    if got != digest_hex(digest)? {
        bail!(
            "blob 摘要校验失败: {} (期望 {}, 实际 {}）；缓存可能损坏，删除后重拉",
            path.display(),
            digest_hex(digest)?,
            got
        );
    }
    Ok(data)
}

fn short_digest(d: &str) -> String {
    d.split(':')
        .nth(1)
        .map(|h| h[..12.min(h.len())].to_string())
        .unwrap_or_else(|| d.to_string())
}

// ---------------------------------------------------------------- 拉取主流程

/// 拉取镜像到 blob 库。manifest 仍串行取（要按平台下钻），
/// config + 所有层 blob 并发下载；已缓存的 blob 直接跳过。
pub fn pull(
    input: &str,
    insecure: bool,
    platform: HostArch,
    blobs: &Path,
    concurrency: usize,
) -> Result<Pulled> {
    let r = parse_ref(input, insecure)?;
    let ref_key = canonical_ref(input, insecure)?;
    println!(
        "miko: pull  = {} ({})",
        ref_key.display,
        platform.label()
    );
    let mut client = Client::new(&r)?;

    // 1. 取 manifest（可能是 index/list，需要按平台下钻）
    let (manifest_bytes, _manifest_mt) = fetch_manifest(&mut client, &r.reference, platform)?;
    let manifest_digest = store_blob(blobs, &manifest_bytes)?;
    let manifest: Manifest =
        serde_json::from_slice(&manifest_bytes).context("解析最终 manifest 失败")?;
    if manifest.schema_version != 2 {
        bail!(
            "只支持 schemaVersion=2 的 manifest，收到 {}（schema1 已废弃）",
            manifest.schema_version
        );
    }
    if manifest.layers.is_empty() {
        bail!("manifest 中没有任何 layer");
    }

    // 2. config + 各层：先逐层打印，再并发下载
    let mut tasks: Vec<(String, u64)> =
        vec![(manifest.config.digest.clone(), manifest.config.size)];
    for (i, layer) in manifest.layers.iter().enumerate() {
        println!(
            "miko: layer {}/{} {} ({} bytes)",
            i + 1,
            manifest.layers.len(),
            short_digest(&layer.digest),
            layer.size
        );
        tasks.push((layer.digest.clone(), layer.size));
    }
    fetch_blobs_parallel(&r, blobs, &tasks, concurrency, client.token.clone())?;

    // 3. 校验 config 摘要并解析，diff_ids 与层数必须一致
    let config_raw = read_blob_checked(blobs, &manifest.config.digest)?;
    let config: ImageConfigFile =
        serde_json::from_slice(&config_raw).context("解析 image config blob 失败")?;
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
        .zip(config.rootfs.diff_ids.iter())
        .map(|(l, diff_id)| PulledLayer {
            digest: l.digest.clone(),
            diff_id: diff_id.clone(),
            size: l.size,
        })
        .collect();

    Ok(Pulled {
        ref_key,
        manifest_digest,
        config_digest: manifest.config.digest,
        config,
        layers,
    })
}

fn fetch_manifest(
    client: &mut Client,
    reference: &str,
    platform: HostArch,
) -> Result<(Vec<u8>, String)> {
    let url = client.url(&format!("manifests/{reference}"));
    let (bytes, mt) = client.get_bytes(&url, Some(ACCEPT_MANIFEST))?;
    let media = mt.unwrap_or_default();

    if is_index(&media) {
        let idx: Index = serde_json::from_slice(&bytes).context("解析 manifest list 失败")?;
        let candidates: Vec<String> = idx
            .manifests
            .iter()
            .map(|d| match &d.platform {
                Some(p) => format!("{} ({}/{})", short_digest(&d.digest), p.os, p.architecture),
                None => format!("{} (no platform)", short_digest(&d.digest)),
            })
            .collect();
        let picked = idx
            .manifests
            .iter()
            .find(|d| {
                d.platform
                    .as_ref()
                    .is_some_and(|p| p.os == "linux" && platform.matches(&p.architecture))
            })
            .with_context(|| {
                format!(
                    "manifest list 中没有 {} 条目，可用: [{}]",
                    platform.label(),
                    candidates.join(", ")
                )
            })?;
        println!(
            "miko: index  = 选中 {} / {}",
            short_digest(&picked.digest),
            platform.label()
        );
        let (sub, sub_mt) = fetch_manifest(client, &picked.digest, platform)?;
        return Ok((sub, sub_mt));
    }

    Ok((bytes, media))
}

/// 并发下载 config + layer blob。每个 worker 独立 agent、独立 token，
/// 失败不影响其它任务；全部结束后返回第一个错误（并已跳过所有成功项）。
fn fetch_blobs_parallel(
    r: &ImageRef,
    blobs: &Path,
    tasks: &[(String, u64)],
    concurrency: usize,
    token: Option<String>,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    let mut pending: VecDeque<(usize, String, u64)> = VecDeque::new();
    let mut cached = 0usize;
    for (i, (digest, size)) in tasks.iter().enumerate() {
        if !seen.insert(digest.as_str()) {
            continue;
        }
        if blob_path(blobs, digest)?.is_file() {
            cached += 1;
        } else {
            pending.push_back((i, digest.clone(), *size));
        }
    }
    let need = pending.len();
    if need == 0 {
        println!("miko: blob  = 全部 {cached} 个已在缓存，跳过下载");
        return Ok(());
    }
    let workers = concurrency.max(1).min(need);
    println!("miko: blob  = 并发下载 {need} 个（并发度 {workers}），{cached} 个已缓存");

    let queue: Mutex<VecDeque<(usize, String, u64)>> = Mutex::new(pending);
    let (tx, rx) = mpsc::channel::<(usize, String, u64, Result<()>)>();
    std::thread::scope(|scope| -> Result<()> {
        for _ in 0..workers {
            let tx = tx.clone();
            let queue = &queue;
            let token = token.clone();
            scope.spawn(move || loop {
                let item = queue.lock().unwrap_or_else(|e| e.into_inner()).pop_front();
                let Some((i, digest, size)) = item else { break };
                let res = download_blob(r, blobs, &digest, size, token.clone());
                if tx.send((i, digest, size, res)).is_err() {
                    break;
                }
            });
        }
        drop(tx);
        let mut first_err: Option<anyhow::Error> = None;
        let mut done = 0usize;
        for (i, digest, size, res) in rx {
            match res {
                Ok(()) => {
                    done += 1;
                    println!(
                        "miko: blob  {done}/{need} {} 已下载 ({} bytes)",
                        short_digest(&digest),
                        size
                    );
                    let _ = i;
                }
                Err(e) => {
                    eprintln!("miko: blob {} 下载失败: {e:#}", short_digest(&digest));
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }
        match first_err {
            Some(e) => Err(e.context("并发下载 blob 失败")),
            None => Ok(()),
        }
    })
}

/// 单个 blob：流式下载 + 边下边算 sha256，校验通过才 rename 进 blob 库。
fn download_blob(
    r: &ImageRef,
    blobs: &Path,
    digest: &str,
    size: u64,
    token: Option<String>,
) -> Result<()> {
    let dest = blob_path(blobs, digest)?;
    if dest.is_file() {
        return Ok(());
    }
    let mut client = Client::worker(r, token)?;
    let url = client.url(&format!("blobs/{digest}"));
    let resp = client.get(&url, None)?;
    let mut reader = resp.into_reader();
    let mut tmp = tempfile::Builder::new()
        .prefix(".blob-")
        .tempfile_in(dest.parent().unwrap())?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf).context("读取 blob 流失败")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        tmp.write_all(&buf[..n])?;
        total += n as u64;
    }
    tmp.flush()?;
    let got = hex(&hasher.finalize());
    if got != digest_hex(digest)? {
        bail!("blob 摘要校验失败 {digest}: 实际 sha256:{got}（{total} bytes）");
    }
    // 另一个 worker 可能已经完成同一 digest（去重后一般不会出现，仍做兜底）
    if dest.is_file() {
        return Ok(());
    }
    let f = tmp
        .persist(&dest)
        .with_context(|| format!("落盘 blob {} 失败", dest.display()))?;
    drop(f);
    fs::set_permissions(&dest, Permissions::from_mode(0o644))?;
    let _ = size; // size 只用于进度显示，registry 的 Content-Length 不参与完整性判定
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ref_looks_like_ref() {
        assert!(looks_like_ref("busybox:latest"));
        assert!(looks_like_ref("ghcr.io/org/app:v1"));
        assert!(looks_like_ref("localhost:5000/img"));
        assert!(!looks_like_ref("/tmp/image.tar"));
        assert!(!looks_like_ref("./oci-layout"));
        assert!(!looks_like_ref("has space"));
    }

    #[test]
    fn ref_parsing_docker_hub() {
        let r = parse_ref("busybox:latest", false).unwrap();
        assert_eq!(r.repo, "library/busybox");
        assert_eq!(r.reference, "latest");
        assert_eq!(r.base, "https://registry-1.docker.io");

        let r = parse_ref("alpine", false).unwrap();
        assert_eq!(r.reference, "latest");
    }

    #[test]
    fn ref_parsing_third_party_and_digest() {
        let r = parse_ref("ghcr.io/org/app:v1.2", false).unwrap();
        assert_eq!(r.base, "https://ghcr.io");
        assert_eq!(r.repo, "org/app");
        assert_eq!(r.reference, "v1.2");

        let r = parse_ref("localhost:5000/foo/bar:v1", false).unwrap();
        assert_eq!(r.base, "https://localhost:5000");
        assert_eq!(r.repo, "foo/bar");

        let digest = format!("ghcr.io/org/app@sha256:{}", "a".repeat(64));
        let r = parse_ref(&digest, false).unwrap();
        assert!(r.reference.starts_with("sha256:"));

        let r = parse_ref("myreg.local/foo:v1", false).unwrap();
        assert_eq!(r.repo, "foo", "第三方 registry 单段仓库不加 library/ 前缀");

        let r = parse_ref("http://127.0.0.1:5000/img", false).unwrap();
        assert_eq!(r.base, "http://127.0.0.1:5000");

        assert!(parse_ref("bad@md5:xxx", false).is_err());
        assert!(parse_ref("", false).is_err());
    }

    #[test]
    fn canonical_ref_is_stable_across_spellings() {
        let a = canonical_ref("busybox", false).unwrap();
        let b = canonical_ref("busybox:latest", false).unwrap();
        let c = canonical_ref("docker.io/library/busybox:latest", false).unwrap();
        assert_eq!(a.key, "docker.io/library/busybox:latest");
        assert_eq!(a.key, b.key);
        assert_eq!(b.key, c.key);

        let d = canonical_ref("http://localhost:5000/foo/bar:v1", false).unwrap();
        assert_eq!(d.key, "localhost:5000/foo/bar:v1");

        let hex = "a".repeat(64);
        let e = canonical_ref(&format!("alpine@sha256:{hex}"), false).unwrap();
        assert_eq!(e.key, format!("docker.io/library/alpine@sha256:{hex}"));
    }

    #[test]
    fn auth_params_split_respects_quotes() {
        let parts = split_auth_params("realm=\"https://auth/x,y\",service=\"reg\",scope=\"a,b\"");
        assert_eq!(parts.len(), 3);
        assert!(parts[0].contains("x,y"));
        assert!(parts[2].contains("a,b"));
        assert_eq!(
            percent_encode("repository:x/y pull"),
            "repository%3Ax%2Fy%20pull"
        );
    }

    #[test]
    fn blob_path_validates_digest_and_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let good = format!("sha256:{}", "a".repeat(64));
        let p = blob_path(tmp.path(), &good).unwrap();
        assert_eq!(p, tmp.path().join("sha256").join("a".repeat(64)));
        assert!(blob_path(tmp.path(), "md5:xyz").is_err());
        assert!(blob_path(tmp.path(), "sha256:short").is_err());
    }

    #[test]
    fn store_blob_is_content_addressed_and_checked() {
        let tmp = tempfile::tempdir().unwrap();
        let data = b"hello miko".to_vec();
        let d1 = store_blob(tmp.path(), &data).unwrap();
        let d2 = store_blob(tmp.path(), &data).unwrap();
        assert_eq!(d1, d2);
        assert_eq!(read_blob_checked(tmp.path(), &d1).unwrap(), data);
        // 手工改坏缓存必须被摘要校验拦住
        fs::write(blob_path(tmp.path(), &d1).unwrap(), b"broken").unwrap();
        assert!(read_blob_checked(tmp.path(), &d1).is_err());
    }
}
