//! 本地镜像库：content-addressable blob + 镜像索引 + rootfs 快照缓存。
//!
//! - `<state_root>/images/blobs/sha256/<hex>`：manifest / config / layer 一律按内容摘要存放，
//!   跨镜像、跨 tag 天然复用，同一层只下一次、只存一份。
//! - `images.json`：镜像记录（config digest 即 image id）、tag 引用、本地导入源指纹。
//! - `cache/<chain>/rootfs`：按 OCI chainID（diff_ids 的有序前缀链）缓存**已合并**的 rootfs，
//!   重复 run 命中快照后只做一次目录树复制（reflink 优先），不再逐层解压 / 校验。
//!
//! 所有 read-modify-write 都包在 state.lock 的 flock 里，多个 run / pull / rmi 并发安全。

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{self, File, Permissions};
use std::io::{self, Cursor, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{digest_hex, layer, registry, sha256_hex, source, Image, ImageConfigFile, LayerSource};
use crate::arch::{self, HostArch};
use crate::state;

const INDEX_VERSION: u32 = 1;
/// `FICLONE`（linux/fs.h）：在支持 reflink 的文件系统上做 CoW 复制，不支持则回退普通复制。
/// 数值本身与架构无关；ioctl 的 request 参数在 gnu/musl、x86_64/aarch64 上类型不一致
///（`c_ulong` vs `c_int`），调用处用 `as _` 适配。
const FICLONE: u64 = 0x4004_9409;

// ---------------------------------------------------------------- 索引结构

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredLayer {
    /// 压缩后 blob 的 `sha256:...`
    pub digest: String,
    /// 未压缩 tar 的 `sha256:...`
    pub diff_id: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageRecord {
    /// config blob 的 sha256 hex（去前缀），即 image id
    pub id: String,
    pub created: u64,
    pub size: u64,
    pub manifest_digest: Option<String>,
    pub config_digest: String,
    pub diff_ids: Vec<String>,
    pub layers: Vec<StoredLayer>,
    pub platform: String,
}

/// 本地文件/目录导入的指纹：同一路径 + 大小 + mtime 未变时直接命中缓存，
/// 连 tar 解包都省掉（重复 `run ./image.tar` 也是毫秒级）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFingerprint {
    pub path: String,
    pub size: u64,
    pub mtime_ns: u128,
    pub image_id: String,
    /// 源里自带的 RepoTags / OCI ref.name，指纹命中时无需解包也能补 tag。
    #[serde(default)]
    pub repo_tags: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Index {
    #[serde(default)]
    pub version: u32,
    /// image id -> 镜像记录
    #[serde(default)]
    pub images: BTreeMap<String, ImageRecord>,
    /// 规范化引用 -> image id
    #[serde(default)]
    pub tags: BTreeMap<String, String>,
    /// 导入指纹 key -> 指纹
    #[serde(default)]
    pub sources: BTreeMap<String, SourceFingerprint>,
}

/// resolve 的结果：spec 需要的 Image 视图 + 缓存需要的元数据。
pub struct Resolved {
    pub image: Image,
    pub record: ImageRecord,
    /// diff_ids 的 chainID 前缀链（纯 hex，可直接做快照目录名）
    pub chain_ids: Vec<String>,
}

pub struct Store {
    root: PathBuf,
    state_root: PathBuf,
}

impl Store {
    pub fn new(state_root: &Path) -> Self {
        Self {
            root: state_root.join("images"),
            state_root: state_root.to_path_buf(),
        }
    }

    fn blobs(&self) -> PathBuf {
        self.root.join("blobs")
    }

    fn cache(&self) -> PathBuf {
        self.root.join("cache")
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("images.json")
    }

    fn load_index(&self) -> Result<Index> {
        let p = self.index_path();
        if !p.is_file() {
            return Ok(Index::default());
        }
        let data = fs::read(&p).with_context(|| format!("读取 {} 失败", p.display()))?;
        serde_json::from_slice(&data).with_context(|| format!("解析 {} 失败", p.display()))
    }

    fn save_index(&self, idx: &Index) -> Result<()> {
        fs::create_dir_all(&self.root)?;
        let tmp = self.root.join("images.json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(idx)?)?;
        fs::rename(&tmp, self.index_path())
            .with_context(|| format!("写入 {} 失败", self.index_path().display()))?;
        Ok(())
    }

    /// 检查一条镜像记录依赖的 blob 是否都还在（缓存可能被手工删过）。
    fn blobs_complete(&self, rec: &ImageRecord) -> bool {
        let mut digests = vec![rec.config_digest.clone()];
        if let Some(m) = &rec.manifest_digest {
            digests.push(m.clone());
        }
        digests.extend(rec.layers.iter().map(|l| l.digest.clone()));
        digests.iter().all(|d| {
            registry::blob_path(&self.blobs(), d)
                .map(|p| p.is_file())
                .unwrap_or(false)
        })
    }

    // ------------------------------------------------------------ 解析入口

    /// run 的入口：本地路径导入 / registry 引用（命中缓存则零网络）。
    pub fn resolve(
        &self,
        input: &str,
        insecure: bool,
        platform: HostArch,
        force_pull: bool,
        concurrency: usize,
    ) -> Result<Resolved> {
        let path = Path::new(input);
        let rec = if path.is_dir() || path.is_file() {
            self.import_local(path, platform)?
        } else if registry::looks_like_ref(input) {
            self.resolve_ref(input, insecure, platform, force_pull, concurrency)?
        } else {
            bail!(
                "镜像输入 {input:?} 既不是本地路径，也不像 registry 引用；\
                 请使用 docker save tar / OCI layout / <repo>:<tag>"
            );
        };
        self.to_resolved(rec, input)
    }

    fn to_resolved(&self, rec: ImageRecord, input: &str) -> Result<Resolved> {
        let config_raw = registry::read_blob_checked(&self.blobs(), &rec.config_digest)?;
        let config: ImageConfigFile =
            serde_json::from_slice(&config_raw).context("解析 image config blob 失败")?;
        let layers = rec
            .layers
            .iter()
            .map(|l| {
                Ok(LayerSource {
                    path: registry::blob_path(&self.blobs(), &l.digest)?,
                    digest: Some(l.digest.clone()),
                    diff_id: Some(l.diff_id.clone()),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if layers.len() != rec.diff_ids.len() {
            bail!(
                "镜像记录的层数 {} 与 diff_ids 数量 {} 不一致",
                layers.len(),
                rec.diff_ids.len()
            );
        }
        let chain_ids = chain_ids(&rec.diff_ids)?;
        let tag = format!("sha256:{}", &rec.id[..12.min(rec.id.len())]);
        let image = Image::new(config, layers, format!("{input} ({tag})"));
        Ok(Resolved {
            image,
            record: rec,
            chain_ids,
        })
    }

    // ------------------------------------------------------------ registry 引用

    fn resolve_ref(
        &self,
        input: &str,
        insecure: bool,
        platform: HostArch,
        force_pull: bool,
        concurrency: usize,
    ) -> Result<ImageRecord> {
        let rk = registry::canonical_ref(input, insecure)?;
        if !force_pull {
            let _g = state::lock(&self.state_root)?;
            let idx = self.load_index()?;
            if let Some(id) = idx.tags.get(&rk.key) {
                if let Some(rec) = idx.images.get(id) {
                    if self.blobs_complete(rec) {
                        println!(
                            "miko: image  = 缓存命中 {} (sha256:{})",
                            rk.display,
                            &rec.id[..12.min(rec.id.len())]
                        );
                        return Ok(rec.clone());
                    }
                    eprintln!(
                        "miko: WARN  = {} 的 blob 不完整，重新拉取",
                        rk.display
                    );
                }
            }
        }

        let pulled = registry::pull(input, insecure, platform, &self.blobs(), concurrency)?;
        let id = digest_hex(&pulled.config_digest)?.to_string();
        let rec = ImageRecord {
            id: id.clone(),
            created: state::now(),
            size: pulled.layers.iter().map(|l| l.size).sum(),
            manifest_digest: Some(pulled.manifest_digest),
            config_digest: pulled.config_digest,
            diff_ids: pulled.config.rootfs.diff_ids.clone(),
            layers: pulled
                .layers
                .iter()
                .map(|l| StoredLayer {
                    digest: l.digest.clone(),
                    diff_id: l.diff_id.clone(),
                    size: l.size,
                })
                .collect(),
            platform: format!("{}/{}", platform.os(), platform.oci_name()),
        };

        let _g = state::lock(&self.state_root)?;
        let mut idx = self.load_index()?;
        idx.version = INDEX_VERSION;
        idx.images.insert(id.clone(), rec.clone());
        idx.tags.insert(rk.key, id.clone());
        self.save_index(&idx)?;
        println!(
            "miko: image  = {} (sha256:{}) 已缓存",
            pulled.ref_key.display,
            &id[..12.min(id.len())]
        );
        Ok(rec)
    }

    // ------------------------------------------------------------ 本地镜像导入

    fn import_local(&self, path: &Path, platform: HostArch) -> Result<ImageRecord> {
        self.import_local_with(path, platform, &[], false)
    }

    /// `extra_tags`：`load --tag` 等额外追加的引用。
    /// `allow_dangling`：为 true 时没有任何 tag 也保留记录（供 `image prune` 回收），
    /// 否则补一个 `local/<文件名>:<短 id>` 伪 tag，保持 `run ./image.tar` 可管理。
    fn import_local_with(
        &self,
        path: &Path,
        platform: HostArch,
        extra_tags: &[String],
        allow_dangling: bool,
    ) -> Result<ImageRecord> {
        let canonical = path
            .canonicalize()
            .with_context(|| format!("解析镜像路径 {} 失败", path.display()))?;
        let meta = fs::metadata(&canonical)?;
        let mtime_ns = meta
            .modified()
            .unwrap_or(UNIX_EPOCH)
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let fp = format!("{}|{}|{}", canonical.display(), meta.len(), mtime_ns);
        let fallback = canonical
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("image")
            .to_string();

        {
            let _g = state::lock(&self.state_root)?;
            let mut idx = self.load_index()?;
            let hit = idx.sources.get(&fp).and_then(|s| {
                idx.images
                    .get(&s.image_id)
                    .cloned()
                    .map(|r| (r, s.repo_tags.clone()))
            });
            if let Some((rec, inherited)) = hit {
                if self.blobs_complete(&rec) {
                    println!(
                        "miko: image  = 缓存命中 {} (sha256:{})",
                        canonical.display(),
                        &rec.id[..12.min(rec.id.len())]
                    );
                    let tags =
                        collect_tags(&inherited, extra_tags, &rec.id, &fallback, allow_dangling);
                    let applied = apply_tags(&mut idx, &rec.id, &tags)?;
                    if !applied.is_empty() {
                        idx.version = INDEX_VERSION;
                        self.save_index(&idx)?;
                    }
                    return Ok(rec);
                }
            }
        }

        let (loaded, _tmp) = source::load_local(&canonical, platform)?;
        println!(
            "miko: import = {} [{}]",
            canonical.display(),
            loaded.description
        );
        if loaded.config.rootfs.diff_ids.len() != loaded.layers.len() {
            bail!(
                "本地镜像层数 {} 与 rootfs.diff_ids 数量 {} 不一致",
                loaded.layers.len(),
                loaded.config.rootfs.diff_ids.len()
            );
        }

        let mut layers = Vec::with_capacity(loaded.layers.len());
        for (i, l) in loaded.layers.iter().enumerate() {
            let raw =
                fs::read(&l.path).with_context(|| format!("读取层 {} 失败", l.path.display()))?;
            let digest = registry::store_blob(&self.blobs(), &raw)?;
            if let Some(d) = &l.digest {
                if !d.eq_ignore_ascii_case(&digest) {
                    bail!(
                        "本地镜像层 {} 声明的 digest {} 与内容不符（{}）",
                        l.path.display(),
                        d,
                        digest
                    );
                }
            }
            let diff_id = l
                .diff_id
                .clone()
                .or_else(|| loaded.config.rootfs.diff_ids.get(i).cloned())
                .context("本地镜像层缺少 diff_id")?;
            layers.push(StoredLayer {
                digest,
                diff_id,
                size: raw.len() as u64,
            });
        }
        let config_digest = registry::store_blob(&self.blobs(), &loaded.config_raw)?;
        let id = digest_hex(&config_digest)?.to_string();
        let rec = ImageRecord {
            id: id.clone(),
            created: state::now(),
            size: layers.iter().map(|l| l.size).sum(),
            manifest_digest: None,
            config_digest,
            diff_ids: loaded.config.rootfs.diff_ids.clone(),
            layers,
            platform: format!("{}/{}", platform.os(), platform.oci_name()),
        };

        let tags = collect_tags(
            &loaded.repo_tags,
            extra_tags,
            &id,
            &fallback,
            allow_dangling,
        );

        let _g = state::lock(&self.state_root)?;
        let mut idx = self.load_index()?;
        idx.version = INDEX_VERSION;
        idx.images.entry(id.clone()).or_insert_with(|| rec.clone());
        let applied = apply_tags(&mut idx, &id, &tags)?;
        idx.sources.insert(
            fp,
            SourceFingerprint {
                path: canonical.to_string_lossy().into_owned(),
                size: meta.len(),
                mtime_ns,
                image_id: id.clone(),
                repo_tags: loaded.repo_tags.clone(),
            },
        );
        self.save_index(&idx)?;
        for t in &applied {
            eprintln!(
                "miko: tag    = {t} -> sha256:{}",
                &id[..12.min(id.len())]
            );
        }
        idx.images
            .get(&id)
            .cloned()
            .context("刚写入的镜像记录不见了")
    }

    // ------------------------------------------------------------ rootfs 快照

    /// 组装 rootfs：按 chainID 找最长的已缓存前缀，命中后复制快照，
    /// 只解包剩余层；未命中则全量解包。完成后发布完整链的快照。
    pub fn materialize_rootfs(&self, resolved: &Resolved, target: &Path) -> Result<()> {
        let n = resolved.chain_ids.len();
        if n == 0 {
            bail!("镜像没有任何 diff_ids，无法组装 rootfs");
        }
        // 串行化快照发布：两个进程同时组装同一个 chain 时，后者直接复用前者的成果。
        let _g = state::lock(&self.state_root)?;

        let mut applied = 0usize;
        let mut base: Option<PathBuf> = None;
        for i in (1..=n).rev() {
            let dir = self.cache().join(&resolved.chain_ids[i - 1]);
            if dir.join("complete").is_file() && dir.join("rootfs").is_dir() {
                applied = i;
                base = Some(dir.join("rootfs"));
                break;
            }
        }

        fs::create_dir_all(target)?;
        if let Some(b) = &base {
            println!(
                "miko: rootfs = 复用快照 diff_ids[0..{applied}]/{n} → {}",
                target.display()
            );
            clone_tree(b, target)?;
        }
        if applied < n {
            let todo = &resolved.image.layers[applied..];
            println!(
                "miko: rootfs = 解包 {}/{} 层 → {}",
                todo.len(),
                n,
                target.display()
            );
            layer::apply_layers(target, todo)?;
            self.publish_snapshot(&resolved.chain_ids[n - 1], target)?;
        }
        Ok(())
    }

    fn publish_snapshot(&self, chain: &str, rootfs: &Path) -> Result<()> {
        let final_dir = self.cache().join(chain);
        if final_dir.join("complete").is_file() {
            return Ok(());
        }
        fs::create_dir_all(self.cache())?;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let tmp = self
            .cache()
            .join(format!(".tmp-{}-{nanos}", std::process::id()));
        let res = (|| -> Result<()> {
            fs::create_dir_all(&tmp)?;
            clone_tree(rootfs, &tmp.join("rootfs"))?;
            fs::write(tmp.join("complete"), "1")?;
            if !final_dir.exists() {
                if let Err(e) = fs::rename(&tmp, &final_dir) {
                    // 另一个进程抢先发布成功：静默丢弃自己这份
                    if !final_dir.join("complete").is_file() {
                        return Err(e.into());
                    }
                }
            }
            Ok(())
        })();
        if res.is_err() || tmp.exists() {
            let _ = fs::remove_dir_all(&tmp);
        }
        res
    }

    // ------------------------------------------------------------ GC

    /// 回收无人引用的 blob 与 rootfs 快照；只动 64 位 hex 名，
    /// 不碰正在下载的 `.blob-*` / 正在发布的 `.tmp-*` 临时文件。
    fn gc(&self, idx: &Index) -> Result<(usize, usize, u64)> {
        let live_blobs: BTreeSet<String> = idx
            .images
            .values()
            .flat_map(|r| {
                let mut v = vec![r.config_digest.clone()];
                if let Some(m) = &r.manifest_digest {
                    v.push(m.clone());
                }
                v.extend(r.layers.iter().map(|l| l.digest.clone()));
                v
            })
            .collect();
        let mut live_chains: BTreeSet<String> = BTreeSet::new();
        for r in idx.images.values() {
            for c in chain_ids(&r.diff_ids)? {
                live_chains.insert(c);
            }
        }

        let mut n_blobs = 0usize;
        let mut freed = 0u64;
        let sha_dir = self.blobs().join("sha256");
        if sha_dir.is_dir() {
            for e in fs::read_dir(&sha_dir)? {
                let e = e?;
                let name = e.file_name().to_string_lossy().into_owned();
                if is_hex64(&name) && !live_blobs.contains(&format!("sha256:{name}")) {
                    freed += e.metadata().map(|m| m.len()).unwrap_or(0);
                    fs::remove_file(e.path())?;
                    n_blobs += 1;
                }
            }
        }
        let mut n_snaps = 0usize;
        if self.cache().is_dir() {
            for e in fs::read_dir(self.cache())? {
                let e = e?;
                let name = e.file_name().to_string_lossy().into_owned();
                if is_hex64(&name) && !live_chains.contains(&name) {
                    freed += dir_size(&e.path());
                    fs::remove_dir_all(e.path())?;
                    n_snaps += 1;
                } else if name.starts_with(".tmp-") {
                    let _ = fs::remove_dir_all(e.path());
                }
            }
        }
        Ok((n_blobs, n_snaps, freed))
    }
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// OCI chainID：`ChainID(L0) = DiffID(L0)`，
/// `ChainID(L0..Ln) = sha256(ChainID(L0..Ln-1) + " " + DiffID(Ln))`。
/// 返回逐前缀的纯 hex，用作 rootfs 快照目录名（前缀相同 => 底层可复用）。
pub fn chain_ids(diff_ids: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(diff_ids.len());
    let mut prev: Option<String> = None;
    for d in diff_ids {
        let h = digest_hex(d).with_context(|| format!("非法 diff_id {d:?}"))?;
        let chain = match &prev {
            None => h.to_string(),
            Some(p) => sha256_hex(format!("sha256:{p} {d}").as_bytes()),
        };
        out.push(chain.clone());
        prev = Some(chain);
    }
    Ok(out)
}

// ---------------------------------------------------------------- 目录树复制

/// reflink(CoW) 优先的递归复制：保留 mode / owner / symlink / hardlink / 设备节点 / fifo。
/// FICLONE 不支持（ext4、tmpfs 等）时逐字节复制，语义不变、只是慢一点。
pub fn clone_tree(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    let mut seen: BTreeMap<(u64, u64), PathBuf> = BTreeMap::new();
    clone_dir(src, dst, &mut seen)?;
    Ok(())
}

fn clone_dir(src: &Path, dst: &Path, seen: &mut BTreeMap<(u64, u64), PathBuf>) -> Result<()> {
    for e in fs::read_dir(src).with_context(|| format!("遍历 {} 失败", src.display()))? {
        let e = e?;
        let s = e.path();
        let d = dst.join(e.file_name());
        let meta = fs::symlink_metadata(&s)?;
        let ft = meta.file_type();
        if ft.is_dir() {
            fs::create_dir_all(&d)?;
            clone_dir(&s, &d, seen)?;
        } else if ft.is_symlink() {
            let link = fs::read_link(&s)?;
            symlink(&link, &d)?;
        } else if ft.is_file() {
            let key = (meta.dev(), meta.ino());
            if let Some(first) = seen.get(&key) {
                if fs::symlink_metadata(&d).is_ok() {
                    fs::remove_file(&d)?;
                }
                fs::hard_link(first, &d)
                    .with_context(|| format!("重建硬链接 {} 失败", d.display()))?;
            } else {
                clone_file(&s, &d)?;
                seen.insert(key, d.clone());
            }
        } else {
            clone_special(&s, &d, &meta)?;
        }
        set_meta(&d, &meta)?;
    }
    let dir_meta = fs::symlink_metadata(src)?;
    set_meta(dst, &dir_meta)?;
    Ok(())
}

fn clone_file(src: &Path, dst: &Path) -> Result<()> {
    let mut sf = File::open(src).with_context(|| format!("打开 {} 失败", src.display()))?;
    let mut df = File::create(dst).with_context(|| format!("创建 {} 失败", dst.display()))?;
    // FICLONE 成功则 df 与 sf 共享 extent；失败（EOPNOTSUPP/ENOTTY/EXDEV）回退普通复制。
    // request 用 `as _`：aarch64/musl 上 ioctl 要 i32，x86_64/gnu 上常是 c_ulong。
    let rc = unsafe {
        libc::ioctl(
            df.as_raw_fd(),
            FICLONE as _,
            sf.as_raw_fd() as libc::c_ulong,
        )
    };
    if rc != 0 {
        io::copy(&mut sf, &mut df)
            .with_context(|| format!("复制 {} -> {} 失败", src.display(), dst.display()))?;
    }
    Ok(())
}

fn set_meta(dst: &Path, meta: &fs::Metadata) -> Result<()> {
    if !meta.file_type().is_symlink() {
        fs::set_permissions(dst, Permissions::from_mode(meta.mode() & 0o7777))
            .with_context(|| format!("设置 {} 权限失败", dst.display()))?;
    }
    // 非 root 运行时保留默认 owner；root 时按快照原样恢复（与 layer::apply_one 一致）。
    if unsafe { libc::geteuid() } == 0 {
        let c = CString::new(dst.as_os_str().as_bytes())?;
        let rc = unsafe { libc::lchown(c.as_ptr(), meta.uid(), meta.gid()) };
        if rc != 0 {
            bail!(
                "lchown {} 到 uid={}/gid={} 失败: {}",
                dst.display(),
                meta.uid(),
                meta.gid(),
                io::Error::last_os_error()
            );
        }
    }
    Ok(())
}

fn clone_special(_src: &Path, dst: &Path, meta: &fs::Metadata) -> Result<()> {
    let c = CString::new(dst.as_os_str().as_bytes())?;
    let mode = (meta.mode() & 0o7777) as libc::mode_t;
    let ft = meta.file_type();
    let rc = if ft.is_fifo() {
        unsafe { libc::mkfifo(c.as_ptr(), mode) }
    } else if ft.is_char_device() {
        unsafe { libc::mknod(c.as_ptr(), mode | libc::S_IFCHR, meta.rdev()) }
    } else if ft.is_block_device() {
        unsafe { libc::mknod(c.as_ptr(), mode | libc::S_IFBLK, meta.rdev()) }
    } else {
        bail!("不支持的特殊文件类型: {}", dst.display());
    };
    if rc != 0 {
        bail!(
            "重建特殊文件 {} 失败: {}",
            dst.display(),
            io::Error::last_os_error()
        );
    }
    Ok(())
}

// ---------------------------------------------------------------- 索引辅助

fn short_id(id: &str) -> &str {
    &id[..12.min(id.len())]
}

/// 合并「源镜像自带 RepoTags」与「命令行 --tag」；都没有时按 allow_dangling
/// 决定保持无 tag 记录，还是补一个 `local/<文件名>:<短 id>` 伪 tag（run 的旧行为）。
fn collect_tags(
    inherited: &[String],
    extra: &[String],
    id: &str,
    fallback: &str,
    allow_dangling: bool,
) -> Vec<String> {
    let mut v: Vec<String> = inherited.iter().chain(extra.iter()).cloned().collect();
    v.retain(|s| !s.is_empty());
    v.sort();
    v.dedup();
    if v.is_empty() && !allow_dangling {
        v.push(format!("local/{fallback}:{}", short_id(id)));
    }
    v
}

/// 规范化后写入 tag 索引，返回本次真正新增/改动的 tag key。
fn apply_tags(idx: &mut Index, id: &str, tags: &[String]) -> Result<Vec<String>> {
    let mut applied = Vec::new();
    for t in tags {
        let key = registry::canonical_ref(t, false)
            .with_context(|| format!("非法镜像引用 {t:?}"))?
            .key;
        if idx.tags.get(&key).map(String::as_str) != Some(id) {
            idx.tags.insert(key.clone(), id.to_string());
            applied.push(key);
        }
    }
    Ok(applied)
}

/// 按 tag（支持短引用后缀）或 image id / `sha256:` 前缀定位镜像。
fn find_image<'a>(idx: &'a Index, target: &str) -> Result<&'a ImageRecord> {
    let raw = target.strip_prefix("sha256:").unwrap_or(target);
    let mut ids: Vec<&String> = idx.images.keys().filter(|id| id.starts_with(raw)).collect();
    if ids.is_empty() {
        // 短引用 `busybox` 等价于 `busybox:latest`（docker 行为）。
        let with_tag = if !target.contains(':') && !target.contains('@') {
            Some(format!("{target}:latest"))
        } else {
            None
        };
        ids = idx
            .tags
            .iter()
            .filter(|(k, _)| {
                tag_matches(k, target) || with_tag.as_deref().is_some_and(|a| tag_matches(k, a))
            })
            .map(|(_, v)| v)
            .collect();
        ids.sort();
        ids.dedup();
    }
    match ids.len() {
        0 => bail!("没有找到镜像 {target:?}（用 miko images 查看）"),
        1 => idx.images.get(ids[0]).context("索引里缺少镜像记录"),
        _ => bail!("镜像 {target:?} 匹配到多个记录，请给出更完整的 id 或 tag"),
    }
}

/// 支持 `*` / `?` 的轻量 glob（docker --filter reference 的常用子集）。
fn glob_match(pattern: &str, text: &str) -> bool {
    fn go(p: &[char], t: &[char]) -> bool {
        if p.is_empty() {
            return t.is_empty();
        }
        match p[0] {
            '*' => (0..=t.len()).any(|i| go(&p[1..], &t[i..])),
            '?' => !t.is_empty() && go(&p[1..], &t[1..]),
            c => !t.is_empty() && t[0] == c && go(&p[1..], &t[1..]),
        }
    }
    go(
        &pattern.chars().collect::<Vec<_>>(),
        &text.chars().collect::<Vec<_>>(),
    )
}

fn parse_bool(v: &str) -> Result<bool> {
    match v {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => bail!("布尔过滤值非法: {v:?}（用 true/false）"),
    }
}

fn parse_duration(s: &str) -> Result<u64> {
    let cut = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(cut);
    if num.is_empty() {
        bail!("时长 {s:?} 缺少数字");
    }
    let n: u64 = num.parse()?;
    let mult = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => bail!("时长单位 {unit:?} 不支持（用 s/m/h/d）"),
    };
    Ok(n.saturating_mul(mult))
}

/// 只解析 `YYYY-MM-DDTHH:MM:SSZ`（UTC），其余格式交给调用方报错。
fn parse_rfc3339(s: &str) -> Result<Option<u64>> {
    let b = s.as_bytes();
    if s.len() != 20
        || b.get(4) != Some(&b'-')
        || b.get(7) != Some(&b'-')
        || b.get(10) != Some(&b'T')
        || b.get(13) != Some(&b':')
        || b.get(16) != Some(&b':')
        || b.get(19) != Some(&b'Z')
    {
        return Ok(None);
    }
    let part = |a: usize, z: usize| -> Result<i32> {
        s.get(a..z)
            .context("RFC3339 片段越界")?
            .parse::<i32>()
            .context("RFC3339 片段不是数字")
    };
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_year = part(0, 4)? - 1900;
    tm.tm_mon = part(5, 7)? - 1;
    tm.tm_mday = part(8, 10)?;
    tm.tm_hour = part(11, 13)?;
    tm.tm_min = part(14, 16)?;
    tm.tm_sec = part(17, 19)?;
    let ts = unsafe { libc::timegm(&mut tm) };
    if ts < 0 {
        bail!("非法 RFC3339 时间 {s:?}");
    }
    Ok(Some(ts as u64))
}

fn rfc3339(ts: u64) -> String {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // libc::time_t 在 musl 目标上标了 deprecated（将固定为 64 位），此处仅作转换，压制告警。
    #[allow(deprecated)]
    let t = ts as libc::time_t;
    unsafe { libc::gmtime_r(&t, &mut tm) };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

#[derive(Default, Debug)]
struct ImageFilters {
    dangling: Option<bool>,
    references: Vec<String>,
    id: Option<String>,
    labels: Vec<(String, String)>,
    before: Option<u64>,
    since: Option<u64>,
    /// 绝对截止时间戳（早于它的镜像才会被选中）
    until: Option<u64>,
}

fn parse_filters(items: &[String], idx: &Index) -> Result<ImageFilters> {
    let mut f = ImageFilters::default();
    let now = state::now();
    for item in items {
        let (k, v) = item
            .split_once('=')
            .with_context(|| format!("过滤条件 {item:?} 需要 key=value"))?;
        let (k, v) = (k.trim(), v.trim());
        match k {
            "dangling" => f.dangling = Some(parse_bool(v)?),
            "reference" => f.references.push(v.to_string()),
            "id" => f.id = Some(v.trim_start_matches("sha256:").to_string()),
            "label" => {
                let (lk, lv) = v
                    .split_once('=')
                    .with_context(|| format!("label 过滤 {item:?} 需要 key=value"))?;
                f.labels.push((lk.to_string(), lv.to_string()));
            }
            "before" => f.before = Some(find_image(idx, v)?.created),
            "since" => f.since = Some(find_image(idx, v)?.created),
            "until" => {
                f.until = Some(if v.contains('T') {
                    parse_rfc3339(v)?.with_context(|| {
                        format!("非法 RFC3339 时间 {v:?}（示例 2026-11-14T09:00:00Z）")
                    })?
                } else {
                    now.saturating_sub(parse_duration(v)?)
                });
            }
            _ => bail!(
                "不支持的过滤条件 {k:?}（支持 dangling / reference / id / label / before / since / until）"
            ),
        }
    }
    Ok(f)
}

fn labels_match(config: &ImageConfigFile, want: &[(String, String)]) -> bool {
    want.iter().all(|(k, v)| {
        config
            .config
            .labels
            .get(k)
            .map(String::as_str)
            .unwrap_or("")
            == v.as_str()
    })
}

/// images 输出的一行（一个 tag 一行；dangling 镜像单独一行 `<none>:<none>`）。
struct ImageRow {
    key: String,
    id: String,
    created: u64,
    size: u64,
    layers: usize,
    digest: String,
    dangling: bool,
    config: ImageConfigFile,
}

impl ImageRow {
    fn id_display(&self, no_trunc: bool) -> String {
        if no_trunc {
            format!("sha256:{}", self.id)
        } else {
            format!("sha256:{}", short_id(&self.id))
        }
    }

    fn digest_display(&self, no_trunc: bool) -> String {
        match &self.digest {
            d if d.is_empty() => "<none>".to_string(),
            d if no_trunc => d.clone(),
            d => format!(
                "sha256:{}",
                short_id(d.strip_prefix("sha256:").unwrap_or(d))
            ),
        }
    }

    fn repository(&self) -> &str {
        self.key
            .split_once(':')
            .map(|(r, _)| r)
            .unwrap_or(&self.key)
    }

    fn tag(&self) -> &str {
        self.key
            .rsplit_once(':')
            .map(|(_, t)| t)
            .unwrap_or("<none>")
    }
}

fn build_rows(store: &Store, idx: &Index) -> Result<Vec<ImageRow>> {
    let mut rows = Vec::new();
    for (key, id) in &idx.tags {
        let Some(rec) = idx.images.get(id) else {
            continue;
        };
        rows.push(make_row(store, key.clone(), rec));
    }
    for (id, rec) in &idx.images {
        if !idx.tags.values().any(|v| v == id) {
            rows.push(make_row(store, "<none>:<none>".to_string(), rec));
        }
    }
    Ok(rows)
}

fn make_row(store: &Store, key: String, rec: &ImageRecord) -> ImageRow {
    let config = registry::read_blob_checked(&store.blobs(), &rec.config_digest)
        .ok()
        .and_then(|raw| serde_json::from_slice::<ImageConfigFile>(&raw).ok())
        .unwrap_or_default();
    ImageRow {
        dangling: key == "<none>:<none>",
        key,
        id: rec.id.clone(),
        created: rec.created,
        size: rec.size,
        layers: rec.diff_ids.len(),
        digest: rec.manifest_digest.clone().unwrap_or_default(),
        config,
    }
}

fn row_matches(r: &ImageRow, f: &ImageFilters) -> bool {
    if let Some(d) = f.dangling {
        if r.dangling != d {
            return false;
        }
    }
    if !f.references.is_empty() && !f.references.iter().any(|p| glob_match(p, &r.key)) {
        return false;
    }
    if let Some(id) = &f.id {
        if !id.is_empty() && !r.id.starts_with(id) {
            return false;
        }
    }
    if let Some(b) = f.before {
        if r.created >= b {
            return false;
        }
    }
    if let Some(s) = f.since {
        if r.created <= s {
            return false;
        }
    }
    if !f.labels.is_empty() && !labels_match(&r.config, &f.labels) {
        return false;
    }
    true
}

fn row_value(r: &ImageRow, f: &str, no_trunc: bool) -> Result<String> {
    Ok(match f {
        "ID" => r.id_display(no_trunc),
        "Repository" => r.repository().to_string(),
        "Tag" => r.tag().to_string(),
        "Digest" => r.digest_display(no_trunc),
        "CreatedSince" => ago(r.created),
        "CreatedAt" => rfc3339(r.created),
        "Size" | "VirtualSize" | "UniqueSize" => human_size(r.size),
        "SharedSize" => "N/A".to_string(),
        "Containers" => "0".to_string(),
        "Layers" => r.layers.to_string(),
        "Labels" => serde_json::to_string(&r.config.config.labels)?,
        "Platform" => format!(
            "{}/{}",
            r.config.os.clone().unwrap_or_else(|| "linux".into()),
            r.config
                .architecture
                .clone()
                .unwrap_or_else(|| "unknown".into())
        ),
        _ => bail!("不支持的模板字段 {{{{.{f}}}}}"),
    })
}

fn render_template(tpl: &str, r: &ImageRow, no_trunc: bool) -> Result<String> {
    let tpl = tpl.replace("\\t", "\t").replace("\\n", "\n");
    let mut out = String::new();
    let mut rest = tpl.as_str();
    while let Some(pos) = rest.find("{{") {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 2..];
        let Some(end) = after.find("}}") else {
            out.push_str(&rest[pos..]);
            return Ok(out);
        };
        let expr = after[..end].trim();
        if expr == "json ." {
            out.push_str(&serde_json::to_string(&row_json(r))?);
        } else if let Some(field) = expr.strip_prefix('.') {
            out.push_str(&row_value(r, field.trim(), no_trunc)?);
        } else {
            bail!("不支持的模板表达式 {{{{ {expr} }}}}");
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

fn row_json(r: &ImageRow) -> serde_json::Value {
    serde_json::json!({
        "ID": r.id_display(false),
        "Repository": r.repository(),
        "Tag": r.tag(),
        "Digest": r.digest_display(false),
        "CreatedSince": ago(r.created),
        "CreatedAt": rfc3339(r.created),
        "Size": human_size(r.size),
        "VirtualSize": human_size(r.size),
        "SharedSize": "N/A",
        "UniqueSize": human_size(r.size),
        "Containers": 0,
        "Layers": r.layers,
    })
}

/// inspect 用的完整镜像元数据（对齐 docker inspect 的常用字段）。
fn image_json(store: &Store, idx: &Index, rec: &ImageRecord) -> Result<serde_json::Value> {
    let raw = registry::read_blob_checked(&store.blobs(), &rec.config_digest)?;
    let cfg: ImageConfigFile =
        serde_json::from_slice(&raw).context("解析 image config blob 失败")?;
    let tags: Vec<&String> = idx
        .tags
        .iter()
        .filter(|(_, v)| v.as_str() == rec.id.as_str())
        .map(|(k, _)| k)
        .collect();
    let repo_digests: Vec<&String> = tags.iter().filter(|t| t.contains('@')).copied().collect();
    let layers: Vec<serde_json::Value> = rec
        .layers
        .iter()
        .enumerate()
        .map(|(i, l)| {
            serde_json::json!({
                "Digest": l.digest,
                "DiffID": rec.diff_ids.get(i).cloned().unwrap_or_default(),
                "Size": l.size,
            })
        })
        .collect();
    Ok(serde_json::json!({
        "Id": format!("sha256:{}", rec.id),
        "RepoTags": tags,
        "RepoDigests": repo_digests,
        "Created": rfc3339(rec.created),
        "Size": rec.size,
        "VirtualSize": rec.size,
        "Architecture": cfg.architecture,
        "Os": cfg.os,
        "Platform": rec.platform,
        "ManifestDigest": rec.manifest_digest,
        "Config": {
            "Env": cfg.config.env,
            "Cmd": cfg.config.cmd,
            "Entrypoint": cfg.config.entrypoint,
            "WorkingDir": cfg.config.working_dir,
            "User": cfg.config.user,
            "StopSignal": cfg.config.stop_signal,
            "Labels": cfg.config.labels,
        },
        "RootFS": { "Type": "layers", "Layers": rec.diff_ids },
        "Layers": layers,
    }))
}

fn dir_size(path: &Path) -> u64 {
    let Ok(meta) = fs::metadata(path) else {
        return 0;
    };
    if meta.is_file() {
        return meta.len();
    }
    let mut total = 0u64;
    if let Ok(rd) = fs::read_dir(path) {
        for e in rd.flatten() {
            total += dir_size(&e.path());
        }
    }
    total
}

// ---------------------------------------------------------------- 命令入口

fn ago(ts: u64) -> String {
    let s = state::now().saturating_sub(ts);
    if s < 60 {
        format!("{s}s ago")
    } else if s < 3600 {
        format!("{}m ago", s / 60)
    } else if s < 86400 {
        format!("{}h ago", s / 3600)
    } else {
        format!("{}d ago", s / 86400)
    }
}

fn human_size(n: u64) -> String {
    const GIB: f64 = (1 << 30) as f64;
    const MIB: f64 = (1 << 20) as f64;
    const KIB: f64 = (1 << 10) as f64;
    let v = n as f64;
    if v >= GIB {
        format!("{:.1} GiB", v / GIB)
    } else if v >= MIB {
        format!("{:.1} MiB", v / MIB)
    } else if v >= KIB {
        format!("{:.1} KiB", v / KIB)
    } else {
        format!("{n} B")
    }
}

#[derive(Debug, Default)]
pub struct ImagesOpts {
    pub quiet: bool,
    pub digests: bool,
    pub no_trunc: bool,
    pub filters: Vec<String>,
    pub format: Option<String>,
}

pub fn images_cmd(state_root: &Path, opts: &ImagesOpts) -> Result<i32> {
    let store = Store::new(state_root);
    let _g = state::lock(state_root)?;
    let idx = store.load_index()?;
    print!("{}", render_images(&store, &idx, opts)?);
    Ok(0)
}

fn render_images(store: &Store, idx: &Index, opts: &ImagesOpts) -> Result<String> {
    let f = parse_filters(&opts.filters, idx)?;
    let mut rows = build_rows(store, idx)?;
    rows.retain(|r| row_matches(r, &f));
    rows.sort_by(|a, b| a.key.cmp(&b.key));

    let mut out = String::new();
    if opts.quiet {
        for r in &rows {
            out.push_str(&r.id_display(opts.no_trunc));
            out.push('\n');
        }
        return Ok(out);
    }
    if let Some(tpl) = &opts.format {
        for r in &rows {
            out.push_str(&render_template(tpl, r, opts.no_trunc)?);
            out.push('\n');
        }
        return Ok(out);
    }

    let mut cols: Vec<&str> = vec!["REPOSITORY:TAG", "IMAGE ID", "CREATED", "LAYERS", "SIZE"];
    if opts.digests {
        cols.insert(1, "DIGEST");
    }
    let mut table: Vec<Vec<String>> = vec![cols.iter().map(|s| s.to_string()).collect()];
    for r in &rows {
        let mut row = vec![
            r.key.clone(),
            r.id_display(opts.no_trunc),
            ago(r.created),
            r.layers.to_string(),
            human_size(r.size),
        ];
        if opts.digests {
            row.insert(1, r.digest_display(opts.no_trunc));
        }
        table.push(row);
    }
    let n = cols.len();
    let mut widths = vec![0usize; n];
    for line in &table {
        for i in 0..n {
            widths[i] = widths[i].max(line[i].chars().count());
        }
    }
    for line in &table {
        for i in 0..n {
            if i > 0 {
                out.push(' ');
            }
            out.push_str(&line[i]);
            if i + 1 < n {
                for _ in 0..widths[i].saturating_sub(line[i].chars().count()) {
                    out.push(' ');
                }
            }
        }
        out.push('\n');
    }
    if rows.is_empty() {
        out.push_str("(无本地镜像：miko pull <ref> 或 load -i <tar> 导入)\n");
    }
    Ok(out)
}

pub fn tag_cmd(state_root: &Path, source: &str, target: &str) -> Result<i32> {
    let store = Store::new(state_root);
    let _g = state::lock(state_root)?;
    let mut idx = store.load_index()?;
    let id = find_image(&idx, source)?.id.clone();
    let applied = apply_tags(&mut idx, &id, &[target.to_string()])?;
    idx.version = INDEX_VERSION;
    store.save_index(&idx)?;
    for t in &applied {
        println!("miko: tag = {t} -> sha256:{}", short_id(&id));
    }
    Ok(0)
}

pub fn inspect_cmd(state_root: &Path, targets: &[String]) -> Result<i32> {
    let store = Store::new(state_root);
    let _g = state::lock(state_root)?;
    let idx = store.load_index()?;
    let mut arr = Vec::new();
    for t in targets {
        let rec = find_image(&idx, t)?;
        arr.push(image_json(&store, &idx, rec)?);
    }
    println!("{}", serde_json::to_string_pretty(&arr)?);
    Ok(0)
}

pub fn image_prune_cmd(
    state_root: &Path,
    all: bool,
    force: bool,
    filters: &[String],
) -> Result<i32> {
    let store = Store::new(state_root);
    let _g = state::lock(state_root)?;
    let mut idx = store.load_index()?;
    let f = parse_filters(filters, &idx)?;

    // 容器 state.json 里的 image 输入串按 tag / id 前缀反查，尽量排除在用镜像。
    // 注意：容器 bundle 里的 rootfs 是复制出来的，删镜像不会破坏已运行容器。
    let mut used: BTreeSet<String> = BTreeSet::new();
    for c in state::list(state_root).unwrap_or_default() {
        let raw = c.image.as_str();
        if let Some((_, id)) = idx
            .tags
            .iter()
            .find(|(k, _)| k.as_str() == raw || tag_matches(k, raw))
        {
            used.insert(id.clone());
        } else if raw.len() >= 4 {
            let r = raw.strip_prefix("sha256:").unwrap_or(raw);
            if let Some(id) = idx.images.keys().find(|id| id.starts_with(r)) {
                used.insert(id.clone());
            }
        }
    }

    let mut victims: Vec<String> = Vec::new();
    for (id, rec) in &idx.images {
        let dangling = !idx.tags.values().any(|v| v == id);
        if !all && !dangling {
            continue;
        }
        if used.contains(id) {
            continue;
        }
        if let Some(cut) = f.until {
            if rec.created >= cut {
                continue;
            }
        }
        if !f.labels.is_empty() {
            let cfg = registry::read_blob_checked(&store.blobs(), &rec.config_digest)
                .ok()
                .and_then(|raw| serde_json::from_slice::<ImageConfigFile>(&raw).ok())
                .unwrap_or_default();
            if !labels_match(&cfg, &f.labels) {
                continue;
            }
        }
        victims.push(id.clone());
    }

    if victims.is_empty() {
        println!("Total reclaimed space: 0 B");
        return Ok(0);
    }
    if !force {
        for id in &victims {
            println!("待删除 sha256:{}", short_id(id));
        }
        println!("以上为预览，未删除任何镜像；确认删除请加 -f / --force");
        return Ok(0);
    }

    let mut declared = 0u64;
    for id in &victims {
        let keys: Vec<String> = idx
            .tags
            .iter()
            .filter(|(_, v)| v.as_str() == id.as_str())
            .map(|(k, _)| k.clone())
            .collect();
        for k in keys {
            idx.tags.remove(&k);
            println!("Untagged: {k}");
        }
        if let Some(rec) = idx.images.remove(id) {
            declared += rec.size;
            println!("Deleted: sha256:{}", short_id(id));
        }
    }
    idx.version = INDEX_VERSION;
    idx.sources
        .retain(|_, s| idx.images.contains_key(&s.image_id));
    store.save_index(&idx)?;
    let (n_blobs, n_snaps, freed) = store.gc(&idx)?;
    eprintln!(
        "miko: 删除 {} 个镜像（声明大小 {}）",
        victims.len(),
        human_size(declared)
    );
    println!(
        "miko: GC = 回收 {n_blobs} 个 blob、{n_snaps} 个快照、{}",
        human_size(freed)
    );
    println!("Total reclaimed space: {}", human_size(freed));
    Ok(0)
}

pub fn save_cmd(state_root: &Path, targets: &[String], output: Option<&Path>) -> Result<i32> {
    let store = Store::new(state_root);
    let _g = state::lock(state_root)?;
    let idx = store.load_index()?;
    let mut picked: Vec<ImageRecord> = Vec::new();
    for t in targets {
        let rec = find_image(&idx, t)?.clone();
        if !picked.iter().any(|r| r.id == rec.id) {
            picked.push(rec);
        }
    }
    let data = build_save_tar(&store, &idx, &picked)?;
    match output {
        Some(p) => {
            fs::write(p, &data).with_context(|| format!("写入 {} 失败", p.display()))?;
            eprintln!(
                "miko: save = {} ({} 字节 / {} 个镜像)",
                p.display(),
                data.len(),
                picked.len()
            );
        }
        None => {
            // 二进制写 stdout：所有提示必须走 stderr，不能污染 tar 流。
            io::stdout().write_all(&data)?;
            io::stdout().flush()?;
        }
    }
    Ok(0)
}

/// 生成 docker save 兼容 tar：manifest.json + <config>.json + <diffid>/layer.tar。
/// 层统一解压成未压缩 tar（docker load 的期望格式），导出前用 diff_id 复核。
fn build_save_tar(store: &Store, idx: &Index, picked: &[ImageRecord]) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    {
        let mut b = tar::Builder::new(&mut buf);
        let mut written: BTreeSet<String> = BTreeSet::new();
        let mut manifest: Vec<serde_json::Value> = Vec::new();
        for rec in picked {
            let config_raw = registry::read_blob_checked(&store.blobs(), &rec.config_digest)?;
            let config_name = format!("{}.json", digest_hex(&rec.config_digest)?);
            append_bytes(&mut b, &config_name, &config_raw)?;

            let mut layer_paths = Vec::new();
            for (i, l) in rec.layers.iter().enumerate() {
                let compressed = registry::read_blob_checked(&store.blobs(), &l.digest)?;
                let plain = decompress_blob(&compressed)?;
                let want = rec.diff_ids.get(i).with_context(|| {
                    format!(
                        "镜像 sha256:{} 缺少第 {} 个 diff_id",
                        short_id(&rec.id),
                        i + 1
                    )
                })?;
                let got = sha256_hex(&plain);
                if got != digest_hex(want)? {
                    bail!(
                        "层 {} 解压后 diff_id 不符（期望 {}, 实际 {}）",
                        l.digest,
                        digest_hex(want)?,
                        got
                    );
                }
                let path = format!("{}/layer.tar", digest_hex(&l.diff_id)?);
                if written.insert(path.clone()) {
                    append_bytes(&mut b, &path, &plain)?;
                }
                layer_paths.push(path);
            }
            let tags: Vec<&String> = idx
                .tags
                .iter()
                .filter(|(_, v)| v.as_str() == rec.id.as_str())
                .map(|(k, _)| k)
                .collect();
            manifest.push(serde_json::json!({
                "Config": config_name,
                "RepoTags": tags,
                "Layers": layer_paths,
            }));
        }
        let mf = serde_json::to_vec(&manifest)?;
        append_bytes(&mut b, "manifest.json", &mf)?;
        b.finish()?;
    }
    Ok(buf)
}

fn decompress_blob(raw: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    if raw.starts_with(&[0x1f, 0x8b]) {
        flate2::read::GzDecoder::new(raw)
            .read_to_end(&mut out)
            .context("解压 gzip 层失败")?;
    } else if raw.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        zstd::stream::read::Decoder::new(Cursor::new(raw))
            .context("打开 zstd 层失败")?
            .read_to_end(&mut out)
            .context("解压 zstd 层失败")?;
    } else {
        out.extend_from_slice(raw);
    }
    Ok(out)
}

fn append_bytes<W: Write>(b: &mut tar::Builder<W>, name: &str, data: &[u8]) -> Result<()> {
    let mut h = tar::Header::new_gnu();
    h.set_uid(0);
    h.set_gid(0);
    h.set_mtime(0);
    h.set_size(data.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    b.append_data(&mut h, name, data)?;
    Ok(())
}

pub fn load_cmd(state_root: &Path, input: Option<&Path>, tags: &[String]) -> Result<i32> {
    let store = Store::new(state_root);
    let native = arch::host()?;
    let (path, _tmp): (PathBuf, Option<tempfile::TempDir>) = match input {
        Some(p) if p != Path::new("-") => (p.to_path_buf(), None),
        _ => {
            let tmp = tempfile::Builder::new()
                .prefix("miko-load-")
                .tempdir()
                .context("创建临时目录失败")?;
            let p = tmp.path().join("input.tar");
            let mut f = File::create(&p)?;
            io::copy(&mut io::stdin(), &mut f).context("读取 stdin 失败")?;
            (p, Some(tmp))
        }
    };
    let rec = store.import_local_with(&path, native, tags, true)?;
    println!(
        "miko: load  = sha256:{} ({} 层 / {})",
        short_id(&rec.id),
        rec.layers.len(),
        human_size(rec.size)
    );
    Ok(0)
}

pub fn pull_cmd(
    state_root: &Path,
    input: &str,
    insecure: bool,
    platform: Option<&str>,
    concurrency: usize,
) -> Result<i32> {
    let p = match platform {
        Some(s) => arch::parse_platform(s)?,
        None => arch::host()?,
    };
    let store = Store::new(state_root);
    let _ = store.resolve_ref(input, insecure, p, true, concurrency)?;
    Ok(0)
}

fn tag_matches(key: &str, target: &str) -> bool {
    if key == target {
        return true;
    }
    key.strip_suffix(target)
        .is_some_and(|prefix| prefix.is_empty() || prefix.ends_with('/'))
}

pub fn rmi_cmd(state_root: &Path, targets: &[String], force: bool) -> Result<i32> {
    let store = Store::new(state_root);
    let _g = state::lock(state_root)?;
    let mut idx = store.load_index()?;

    for t in targets {
        let keys: Vec<String> = idx
            .tags
            .keys()
            .filter(|k| tag_matches(k, t))
            .cloned()
            .collect();
        if !keys.is_empty() {
            for k in keys {
                if let Some(id) = idx.tags.remove(&k) {
                    println!("Untagged: {k}");
                    if !idx.tags.values().any(|v| v == &id) {
                        idx.images.remove(&id);
                        println!("Deleted: sha256:{}", &id[..12.min(id.len())]);
                    }
                }
            }
            continue;
        }

        let ids: Vec<String> = idx
            .images
            .keys()
            .filter(|id| id.starts_with(t))
            .cloned()
            .collect();
        if ids.is_empty() {
            bail!("没有找到镜像 {t:?}（用 miko images 查看）");
        }
        for id in ids {
            let tags: Vec<String> = idx
                .tags
                .iter()
                .filter(|(_, v)| *v == &id)
                .map(|(k, _)| k.clone())
                .collect();
            if tags.len() > 1 && !force {
                bail!(
                    "镜像 sha256:{} 被多个 tag 引用（{}），用 -f 强制删除或先 rmi <tag>",
                    &id[..12.min(id.len())],
                    tags.join(", ")
                );
            }
            for k in &tags {
                idx.tags.remove(k);
                println!("Untagged: {k}");
            }
            idx.images.remove(&id);
            println!("Deleted: sha256:{}", &id[..12.min(id.len())]);
        }
    }

    idx.version = INDEX_VERSION;
    idx.sources
        .retain(|_, s| idx.images.contains_key(&s.image_id));
    store.save_index(&idx)?;
    let (blobs, snaps, freed) = store.gc(&idx)?;
    println!(
        "miko: GC    = 回收 {blobs} 个 blob、{snaps} 个 rootfs 快照、{}",
        human_size(freed)
    );
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_ids_are_stable_and_prefix_linked() {
        let a = vec!["sha256:aaa".to_string(), "sha256:bbb".to_string()];
        let ids = chain_ids(&a).unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0], "aaa");
        assert_eq!(ids[1], sha256_hex("sha256:aaa sha256:bbb".as_bytes()));
        // 前缀链：前两层相同 => 第三个镜像能复用第二个 chain 快照
        let b = vec![
            "sha256:aaa".to_string(),
            "sha256:bbb".to_string(),
            "sha256:ccc".to_string(),
        ];
        let ids_b = chain_ids(&b).unwrap();
        assert_eq!(ids_b[0], ids[0]);
        assert_eq!(ids_b[1], ids[1]);
        assert!(chain_ids(&["not-a-digest".to_string()]).is_err());
    }

    #[test]
    fn index_json_roundtrip_and_defaults() {
        let idx: Index = serde_json::from_str(r#"{"version":1}"#).unwrap();
        assert!(idx.images.is_empty() && idx.tags.is_empty() && idx.sources.is_empty());
        let mut idx = Index::default();
        idx.tags
            .insert("docker.io/library/busybox:latest".into(), "ab".repeat(32));
        let raw = serde_json::to_vec(&idx).unwrap();
        let back: Index = serde_json::from_slice(&raw).unwrap();
        assert_eq!(back.tags.len(), 1);
        assert_eq!(back.version, 0);
    }

    #[test]
    fn tag_matching_handles_short_and_full_refs() {
        assert!(tag_matches(
            "docker.io/library/busybox:latest",
            "busybox:latest"
        ));
        assert!(tag_matches("localhost:5000/foo:v1", "foo:v1"));
        assert!(!tag_matches("docker.io/library/busybox:latest", "busybox"));
        assert!(!tag_matches(
            "docker.io/library/busybox:latest",
            "other:latest"
        ));
    }

    #[test]
    fn clone_tree_preserves_files_links_and_modes() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        fs::create_dir_all(src.join("dir")).unwrap();
        fs::write(src.join("dir/a.txt"), b"hello").unwrap();
        fs::write(src.join("dir/b.txt"), b"world").unwrap();
        fs::hard_link(src.join("dir/a.txt"), src.join("dir/hard.txt")).unwrap();
        std::os::unix::fs::symlink("a.txt", src.join("dir/link")).unwrap();
        fs::set_permissions(src.join("dir/a.txt"), Permissions::from_mode(0o600)).unwrap();

        clone_tree(&src, &dst).unwrap();
        assert_eq!(fs::read(dst.join("dir/a.txt")).unwrap(), b"hello");
        assert_eq!(fs::read(dst.join("dir/b.txt")).unwrap(), b"world");
        assert_eq!(
            fs::read_link(dst.join("dir/link")).unwrap(),
            PathBuf::from("a.txt")
        );
        let a = fs::metadata(dst.join("dir/a.txt")).unwrap();
        let h = fs::metadata(dst.join("dir/hard.txt")).unwrap();
        assert_eq!(a.ino(), h.ino(), "硬链接关系应被保留");
        assert_eq!(a.mode() & 0o7777, 0o600);
    }

    /// 构造最小 OCI layout：None => 1 层；Some(x) => 共享第 1 层 + 新第 2 层。
    fn make_layout(dir: &Path, second_layer: Option<&[u8]>) -> Result<()> {
        let blobs_root = dir.join("blobs");
        let blobs = blobs_root.join("sha256");
        fs::create_dir_all(&blobs)?;

        let mut layer_bytes = Vec::new();
        {
            let mut b = tar::Builder::new(&mut layer_bytes);
            let mut h = tar::Header::new_gnu();
            h.set_uid(0);
            h.set_gid(0);
            h.set_mtime(0);
            h.set_size(5);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "hello.txt", &b"hello"[..])?;
            b.finish()?;
        }
        let second: &[u8] = second_layer.unwrap_or(&layer_bytes);
        let all: Vec<&[u8]> = if second_layer.is_some() {
            vec![layer_bytes.as_slice(), second]
        } else {
            vec![layer_bytes.as_slice()]
        };
        let mut diff_ids = Vec::new();
        let mut digests = Vec::new();
        for &data in &all {
            let d = registry::store_blob(&blobs_root, data)?;
            digests.push(d);
            diff_ids.push(format!("sha256:{}", sha256_hex(data)));
        }

        let cfg = ImageConfigFile {
            architecture: Some(arch::host()?.oci_name().to_string()),
            os: Some("linux".into()),
            config: super::super::ImageRuntimeConfig {
                cmd: Some(vec!["/bin/sh".into()]),
                ..Default::default()
            },
            rootfs: super::super::RootFs {
                typ: "layers".into(),
                diff_ids: diff_ids.clone(),
            },
            history: vec![],
        };
        let config_raw = serde_json::to_vec(&cfg)?;
        let config_digest = registry::store_blob(&blobs_root, &config_raw)?;

        let native = arch::host()?;
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "config": {"mediaType":"application/vnd.oci.image.config.v1+json",
                       "digest": config_digest, "size": config_raw.len()},
            "layers": digests.iter().map(|d| serde_json::json!({
                "mediaType":"application/vnd.oci.image.layer.v1.tar",
                "digest": d, "size": 1024
            })).collect::<Vec<_>>()
        });
        let manifest_raw = serde_json::to_vec(&manifest)?;
        let manifest_digest = registry::store_blob(&blobs_root, &manifest_raw)?;

        let index = serde_json::json!({
            "schemaVersion": 2,
            "manifests": [{
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": manifest_digest,
                "size": manifest_raw.len(),
                "platform": {"architecture": native.oci_name(), "os": "linux"}
            }]
        });
        fs::write(dir.join("index.json"), serde_json::to_vec(&index)?)?;
        fs::write(dir.join("oci-layout"), r#"{"imageLayoutVersion":"1.0.0"}"#)?;
        Ok(())
    }

    fn build_second_layer() -> Vec<u8> {
        let mut out = Vec::new();
        let mut b = tar::Builder::new(&mut out);
        let mut h = tar::Header::new_gnu();
        h.set_uid(0);
        h.set_gid(0);
        h.set_mtime(0);
        h.set_size(6);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, "second.txt", &b"world!"[..]).unwrap();
        b.finish().unwrap();
        drop(b);
        out
    }

    #[test]
    fn local_import_and_rootfs_snapshot_reuse() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let state_root = tmp.path().join("state");
        let layout = tmp.path().join("layout");
        make_layout(&layout, None)?;
        let store = Store::new(&state_root);
        let native = arch::host()?;

        // 第一次：导入 + 全量解包 + 发布快照
        let rec = store.import_local(&layout, native)?;
        let resolved = store.to_resolved(rec, "layout")?;
        assert_eq!(resolved.chain_ids.len(), 1);
        let rootfs1 = tmp.path().join("rootfs1");
        store.materialize_rootfs(&resolved, &rootfs1)?;
        assert_eq!(fs::read(rootfs1.join("hello.txt"))?, b"hello");
        let snap = store.cache().join(&resolved.chain_ids[0]);
        assert!(snap.join("complete").is_file());

        // 第二次：把仓库里的 layer blob 全改成垃圾，仍然成功 => 完整快照命中，
        // 既没有重新解包、也没有重新校验（否则 digest 校验必然失败）
        for l in &resolved.record.layers {
            let p = registry::blob_path(&store.blobs(), &l.digest)?;
            fs::write(p, b"garbage")?;
        }
        let rec2 = store.import_local(&layout, native)?;
        assert_eq!(rec2.id, resolved.record.id);
        let resolved2 = store.to_resolved(rec2, "layout")?;
        let rootfs2 = tmp.path().join("rootfs2");
        store.materialize_rootfs(&resolved2, &rootfs2)?;
        assert_eq!(fs::read(rootfs2.join("hello.txt"))?, b"hello");
        Ok(())
    }

    #[test]
    fn shared_diff_id_prefix_reuses_partial_snapshot() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let state_root = tmp.path().join("state");
        let store = Store::new(&state_root);
        let native = arch::host()?;
        let layout_a = tmp.path().join("a");
        make_layout(&layout_a, None)?;
        let rec_a = store.import_local(&layout_a, native)?;
        let ra = store.to_resolved(rec_a, "a")?;
        store.materialize_rootfs(&ra, &tmp.path().join("r1"))?;

        // 镜像 B 共享第 1 层，第 2 层不同；B 的 chain_ids[0] == A 的完整链快照
        let layout_b = tmp.path().join("b");
        make_layout(&layout_b, Some(&build_second_layer()))?;
        let rec_b = store.import_local(&layout_b, native)?;
        let rb = store.to_resolved(rec_b, "b")?;
        assert_eq!(rb.chain_ids.len(), 2);
        assert_eq!(rb.chain_ids[0], ra.chain_ids[0]);
        // 把 B 的第 1 层 blob 改成垃圾：若没有复用前缀快照而重新解包，digest 校验会失败
        fs::write(
            registry::blob_path(&store.blobs(), &rb.record.layers[0].digest)?,
            b"garbage",
        )?;
        let root = tmp.path().join("r2");
        store.materialize_rootfs(&rb, &root)?;
        assert_eq!(fs::read(root.join("hello.txt"))?, b"hello");
        assert_eq!(fs::read(root.join("second.txt"))?, b"world!");
        Ok(())
    }

    #[test]
    fn gc_only_removes_unreferenced_hex_blobs() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let state_root = tmp.path().join("state");
        let store = Store::new(&state_root);
        let blobs = store.blobs();
        let live = registry::store_blob(&blobs, b"live")?;
        let dead = registry::store_blob(&blobs, b"dead")?;
        fs::write(blobs.join("sha256").join(".blob-tmp"), b"in-progress")?;
        let mut idx = Index::default();
        idx.images.insert(
            "id".into(),
            ImageRecord {
                id: "id".into(),
                created: state::now(),
                size: 4,
                manifest_digest: None,
                config_digest: live.clone(),
                diff_ids: vec![],
                layers: vec![],
                platform: "linux/amd64".into(),
            },
        );
        let (n_blobs, _, freed) = store.gc(&idx)?;
        assert_eq!(n_blobs, 1);
        assert_eq!(freed, 4);
        assert!(fs::metadata(registry::blob_path(&blobs, &dead)?).is_err());
        assert!(registry::blob_path(&blobs, &live)?.is_file());
        assert!(blobs.join("sha256").join(".blob-tmp").is_file());
        Ok(())
    }

    /// 给刚导入的镜像补一个规范化 tag，返回记录。
    fn seed_image(store: &Store, layout: &Path, tag: &str) -> Result<ImageRecord> {
        let rec = store.import_local(layout, arch::host()?)?;
        let _g = state::lock(&store.state_root)?;
        let mut idx = store.load_index()?;
        apply_tags(&mut idx, &rec.id, &[tag.to_string()])?;
        store.save_index(&idx)?;
        Ok(rec)
    }

    fn insert_dangling(store: &Store, config_digest: &str) -> Result<String> {
        let id = "d".repeat(64);
        let _g = state::lock(&store.state_root)?;
        let mut idx = store.load_index()?;
        idx.images.insert(
            id.clone(),
            ImageRecord {
                id: id.clone(),
                created: state::now(),
                size: 10,
                manifest_digest: None,
                config_digest: config_digest.to_string(),
                diff_ids: vec![],
                layers: vec![],
                platform: "linux/amd64".into(),
            },
        );
        store.save_index(&idx)?;
        Ok(id)
    }

    #[test]
    fn images_flags_filters_and_format() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let state_root = tmp.path().join("state");
        let layout = tmp.path().join("layout");
        make_layout(&layout, None)?;
        let store = Store::new(&state_root);
        let rec = seed_image(&store, &layout, "busybox:latest")?;
        let dangling_id = insert_dangling(&store, &rec.config_digest)?;
        let idx = store.load_index()?;

        let table = render_images(&store, &idx, &ImagesOpts::default())?;
        assert!(table.contains("docker.io/library/busybox:latest"));
        assert!(table.contains("<none>:<none>"));

        let quiet = render_images(
            &store,
            &idx,
            &ImagesOpts {
                quiet: true,
                ..Default::default()
            },
        )?;
        assert!(quiet.contains(&format!("sha256:{}", short_id(&rec.id))));
        assert!(!quiet.contains("REPOSITORY"));

        let notrunc = render_images(
            &store,
            &idx,
            &ImagesOpts {
                no_trunc: true,
                ..Default::default()
            },
        )?;
        assert!(notrunc.contains(&format!("sha256:{}", rec.id)));

        let digests = render_images(
            &store,
            &idx,
            &ImagesOpts {
                digests: true,
                ..Default::default()
            },
        )?;
        assert!(digests.lines().next().unwrap().contains("DIGEST"));

        let tmpl = render_images(
            &store,
            &idx,
            &ImagesOpts {
                format: Some("{{.Repository}}|{{.Tag}}|{{.ID}}".into()),
                ..Default::default()
            },
        )?;
        assert!(tmpl.contains("docker.io/library/busybox|latest|sha256:"));

        let json = render_images(
            &store,
            &idx,
            &ImagesOpts {
                format: Some("{{json .}}".into()),
                ..Default::default()
            },
        )?;
        assert!(json.contains("\"ID\""));

        let dangling_only = render_images(
            &store,
            &idx,
            &ImagesOpts {
                filters: vec!["dangling=true".into()],
                ..Default::default()
            },
        )?;
        assert!(dangling_only.contains("<none>:<none>"));
        assert!(!dangling_only.contains("docker.io/library/busybox:latest"));

        let by_ref = render_images(
            &store,
            &idx,
            &ImagesOpts {
                filters: vec!["reference=*busybox*".into()],
                ..Default::default()
            },
        )?;
        assert!(by_ref.contains("busybox:latest"));
        assert!(!by_ref.contains("<none>:<none>"));

        let bad = render_images(
            &store,
            &idx,
            &ImagesOpts {
                filters: vec!["nope=1".into()],
                ..Default::default()
            },
        );
        assert!(bad.is_err());
        assert!(idx.images.contains_key(&dangling_id));
        Ok(())
    }

    #[test]
    fn tag_and_inspect_expose_metadata() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let state_root = tmp.path().join("state");
        let layout = tmp.path().join("layout");
        make_layout(&layout, None)?;
        let store = Store::new(&state_root);
        let rec = seed_image(&store, &layout, "busybox:latest")?;

        tag_cmd(&state_root, "busybox", "myreg.local/foo:v1")?;
        let idx = store.load_index()?;
        assert_eq!(
            idx.tags.get("myreg.local/foo:v1").map(String::as_str),
            Some(rec.id.as_str())
        );

        let v = image_json(&store, &idx, &rec)?;
        assert_eq!(v["Id"], format!("sha256:{}", rec.id));
        assert_eq!(v["Config"]["Cmd"][0], "/bin/sh");
        assert_eq!(v["RootFS"]["Layers"][0], rec.diff_ids[0]);
        assert_eq!(v["Layers"][0]["Digest"], rec.layers[0].digest);
        assert!(v["RepoTags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t == "myreg.local/foo:v1"));
        Ok(())
    }

    #[test]
    fn image_prune_removes_dangling_then_all() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let state_root = tmp.path().join("state");
        let layout = tmp.path().join("layout");
        make_layout(&layout, None)?;
        let store = Store::new(&state_root);
        let rec = seed_image(&store, &layout, "busybox:latest")?;
        let dangling_id = insert_dangling(&store, &rec.config_digest)?;

        image_prune_cmd(&state_root, false, true, &[])?;
        let idx = store.load_index()?;
        assert!(!idx.images.contains_key(&dangling_id));
        assert!(idx.images.contains_key(&rec.id));

        image_prune_cmd(&state_root, true, true, &[])?;
        assert!(store.load_index()?.images.is_empty());
        Ok(())
    }

    #[test]
    fn save_then_load_preserves_tags_and_rootfs() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let src_root = tmp.path().join("src");
        let dst_root = tmp.path().join("dst");
        let layout = tmp.path().join("layout");
        let out = tmp.path().join("saved.tar");
        make_layout(&layout, None)?;
        let src = Store::new(&src_root);
        let rec = seed_image(&src, &layout, "busybox:latest")?;

        save_cmd(&src_root, &["busybox".to_string()], Some(&out))?;
        let mut ar = tar::Archive::new(File::open(&out)?);
        let names: Vec<String> = ar
            .entries()?
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().any(|n| n == "manifest.json"));
        assert!(names.iter().any(|n| n.ends_with("/layer.tar")));
        assert!(names
            .iter()
            .any(|n| n.ends_with(".json") && n != "manifest.json"));

        // 新的空 state：tar 内 RepoTags 恢复 + --tag 追加
        load_cmd(&dst_root, Some(&out), &["restored:v2".to_string()])?;
        let dst = Store::new(&dst_root);
        let idx = dst.load_index()?;
        assert!(
            idx.images.contains_key(&rec.id),
            "config digest 不变 => image id 不变"
        );
        assert!(idx.tags.contains_key("docker.io/library/busybox:latest"));
        assert!(idx.tags.contains_key("docker.io/library/restored:v2"));

        let rec2 = idx.images.get(&rec.id).unwrap().clone();
        let resolved = dst.to_resolved(rec2, "restored")?;
        let rootfs = tmp.path().join("rootfs");
        dst.materialize_rootfs(&resolved, &rootfs)?;
        assert_eq!(fs::read(rootfs.join("hello.txt"))?, b"hello");
        Ok(())
    }

    /// 构造一个 RepoTags 为空的 docker save tar。
    fn make_untagged_save_tar(path: &Path) -> Result<()> {
        let mut layer = Vec::new();
        {
            let mut b = tar::Builder::new(&mut layer);
            let mut h = tar::Header::new_gnu();
            h.set_uid(0);
            h.set_gid(0);
            h.set_mtime(0);
            h.set_size(5);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "hello.txt", &b"hello"[..])?;
            b.finish()?;
        }
        let diff_hex = sha256_hex(&layer);
        let cfg = ImageConfigFile {
            architecture: Some(arch::host()?.oci_name().to_string()),
            os: Some("linux".into()),
            config: super::super::ImageRuntimeConfig {
                ..Default::default()
            },
            rootfs: super::super::RootFs {
                typ: "layers".into(),
                diff_ids: vec![format!("sha256:{diff_hex}")],
            },
            history: vec![],
        };
        let config_raw = serde_json::to_vec(&cfg)?;
        let config_name = format!("{}.json", sha256_hex(&config_raw));
        let mf = serde_json::json!([{
            "Config": config_name,
            "RepoTags": [],
            "Layers": [format!("{diff_hex}/layer.tar")]
        }]);
        let mut ar = tar::Builder::new(File::create(path)?);
        append_bytes(&mut ar, &config_name, &config_raw)?;
        append_bytes(&mut ar, &format!("{diff_hex}/layer.tar"), &layer)?;
        append_bytes(&mut ar, "manifest.json", &serde_json::to_vec(&mf)?)?;
        ar.finish()?;
        Ok(())
    }

    #[test]
    fn load_without_tags_stays_dangling_until_pruned() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let state_root = tmp.path().join("state");
        let tar_path = tmp.path().join("untagged.tar");
        make_untagged_save_tar(&tar_path)?;
        load_cmd(&state_root, Some(&tar_path), &[])?;
        let store = Store::new(&state_root);
        let idx = store.load_index()?;
        assert_eq!(idx.images.len(), 1);
        assert!(
            idx.tags.is_empty(),
            "没有 RepoTags 也没有 --tag => dangling"
        );

        image_prune_cmd(&state_root, false, true, &[])?;
        assert!(store.load_index()?.images.is_empty());
        Ok(())
    }

    #[test]
    fn glob_duration_and_rfc3339_helpers() -> Result<()> {
        assert!(glob_match("*busybox*", "docker.io/library/busybox:latest"));
        assert!(glob_match(
            "docker.io/*:latest",
            "docker.io/library/busybox:latest"
        ));
        assert!(!glob_match("alpine*", "docker.io/library/busybox:latest"));
        assert_eq!(parse_duration("10m")?, 600);
        assert_eq!(parse_duration("24h")?, 86_400);
        assert_eq!(parse_duration("7d")?, 604_800);
        assert!(parse_duration("abc").is_err());
        let ts = parse_rfc3339("2026-11-14T09:00:00Z")?.unwrap();
        assert_eq!(rfc3339(ts), "2026-11-14T09:00:00Z");
        assert!(parse_rfc3339("not-a-date").is_ok_and(|v| v.is_none()));
        Ok(())
    }
}
