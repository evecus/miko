//! 纯用户态层合并：把各层 tar 依次解到同一个 rootfs 目录。
//!
//! 对齐 moby `graphdriver/vfs` 的思路（不依赖 overlayfs / 不调用任何外部运行时）。
//! whiteout 按 OCI image-spec 的 AUFS 格式处理：`.wh.<name>` 删除、`.wh..wh..opq` 清空目录。

use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::{self, File, Permissions};
use std::io::{self, Cursor, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use tar::{Archive, Entry, EntryType, Header};

use super::{digest_hex, hex, sha256_hex, LayerSource};
use crate::spec::Mapping;

pub fn apply_layers(target: &Path, layers: &[LayerSource]) -> Result<()> {
    fs::create_dir_all(target)?;
    for (i, layer) in layers.iter().enumerate() {
        apply_one(target, layer)
            .with_context(|| format!("应用第 {} 层 {} 失败", i + 1, layer.path.display()))?;
    }
    Ok(())
}

/// 边读边算 sha256，用于校验 diff_id（未压缩 tar 的摘要）
struct HashReader<R> {
    inner: R,
    hasher: Sha256,
}

impl<R> HashReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }
}

impl<R: Read> Read for HashReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

impl<R> HashReader<R> {
    fn into_digest(self) -> String {
        hex(&self.hasher.finalize())
    }
}

fn read_head<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        let k = r.read(&mut buf[n..])?;
        if k == 0 {
            break;
        }
        n += k;
    }
    Ok(n)
}

fn apply_one(target: &Path, layer: &LayerSource) -> Result<()> {
    // 压缩后 blob 摘要（OCI layout 提供）
    if let Some(d) = &layer.digest {
        let raw = fs::read(&layer.path)
            .with_context(|| format!("读取层 {} 失败", layer.path.display()))?;
        let got = sha256_hex(&raw);
        if got != digest_hex(d)? {
            bail!("层摘要校验失败: 期望 {}, 实际 {}", digest_hex(d)?, got);
        }
    }

    let mut f =
        File::open(&layer.path).with_context(|| format!("打开层 {} 失败", layer.path.display()))?;
    let mut head = [0u8; 512];
    let n = read_head(&mut f, &mut head)?;
    let prefix = head[..n].to_vec();

    // 魔数判定压缩方式：gzip / zstd / 裸 tar
    let base: Box<dyn Read> = Box::new(Cursor::new(prefix.clone()).chain(f));
    let reader: Box<dyn Read> = if prefix.starts_with(&[0x1f, 0x8b]) {
        Box::new(GzDecoder::new(base))
    } else if prefix.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        // OCI image-spec: application/vnd.oci.image.layer.v1.tar+zstd
        Box::new(
            zstd::stream::read::Decoder::new(base)
                .with_context(|| format!("打开 zstd 层 {} 失败", layer.path.display()))?,
        )
    } else {
        base
    };

    let mut hashed = HashReader::new(reader);
    {
        let mut ar = Archive::new(&mut hashed);
        for entry in ar.entries()? {
            let mut entry = entry?;
            apply_entry(target, &mut entry)?;
        }
    }
    // tar 结束块之后通常还有零填充（GNU tar 会补齐到 10240 字节），
    // diff_id 覆盖的是整个未压缩流，必须读完再取摘要。
    io::copy(&mut hashed, &mut io::sink())?;
    let got = hashed.into_digest();
    if let Some(d) = &layer.diff_id {
        if got != digest_hex(d)? {
            bail!(
                "diff_id 校验失败（层 {}）：期望 {}, 实际 {}",
                layer.path.display(),
                digest_hex(d)?,
                got
            );
        }
    }
    Ok(())
}

/// userns 非平凡映射时把 rootfs 的 uid/gid 按映射偏移 chown。
/// 例：映射 `0:100000:1` 意味着容器内 uid 0 == 宿主 uid 100000，
/// 层里 owner=0 的文件必须改成宿主 100000，容器进程才写得进去。
/// 恒等映射（默认 0:0:1）直接跳过，不做无用遍历。
pub fn remap_owners(root: &Path, uid_maps: &[Mapping], gid_maps: &[Mapping]) -> Result<()> {
    let trivial = |m: &[Mapping]| -> bool {
        m.len() == 1 && m[0].container_id == m[0].host_id && m[0].size == 1
    };
    if trivial(uid_maps) && trivial(gid_maps) {
        return Ok(());
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in fs::read_dir(&dir).with_context(|| format!("遍历 {} 失败", dir.display()))? {
            let e = e?;
            let p = e.path();
            let meta = fs::symlink_metadata(&p)?;
            let uid = remap(meta.uid(), uid_maps);
            let gid = remap(meta.gid(), gid_maps);
            let c = cstring(&p)?;
            let rc = unsafe { libc::lchown(c.as_ptr(), uid, gid) };
            if rc != 0 {
                bail!(
                    "chown {} 到 uid={uid}/gid={gid} 失败: {}（目标 id 可能超出宿主 user namespace 的 uid_map/gid_map 范围）",
                    p.display(),
                    io::Error::last_os_error()
                );
            }
            if meta.is_dir() {
                stack.push(p);
            }
        }
    }
    Ok(())
}

fn remap(id: u32, maps: &[Mapping]) -> u32 {
    for m in maps {
        if id >= m.container_id && id < m.container_id.saturating_add(m.size) {
            return m.host_id.saturating_add(id - m.container_id);
        }
    }
    id
}

fn apply_entry<R: Read>(root: &Path, entry: &mut Entry<'_, R>) -> Result<()> {
    let raw_path = entry.path()?.into_owned();
    let header = entry.header().clone();
    let rel = clean_path(&raw_path)?;
    if rel.as_os_str().is_empty() {
        return Ok(());
    }

    let name = rel
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    let parent_rel = rel.parent().unwrap_or_else(|| Path::new(""));

    // OCI whiteout（AUFS 格式）
    if name == ".wh..wh..opq" {
        return clear_dir(&root.join(parent_rel));
    }
    if let Some(victim) = name.strip_prefix(".wh.") {
        if victim.is_empty() {
            bail!("非法 whiteout 条目: {}", raw_path.display());
        }
        return remove_any(&root.join(parent_rel).join(victim));
    }

    // tar 元数据条目直接跳过
    match header.entry_type() {
        EntryType::XGlobalHeader
        | EntryType::XHeader
        | EntryType::GNULongName
        | EntryType::GNULongLink => return Ok(()),
        _ => {}
    }

    ensure_parent(root, &rel)?;
    let dest = root.join(&rel);

    match header.entry_type() {
        EntryType::Directory => {
            if let Ok(m) = fs::symlink_metadata(&dest) {
                if !m.is_dir() {
                    fs::remove_file(&dest)?;
                }
            }
            fs::create_dir_all(&dest)?;
            set_mode(&dest, &header)?;
            set_owner(&dest, &header)?;
        }
        EntryType::Regular => {
            prepare(&dest)?;
            let mut out = File::create(&dest)?;
            io::copy(&mut *entry, &mut out)?;
            drop(out);
            set_mode(&dest, &header)?;
            set_owner(&dest, &header)?;
        }
        EntryType::Symlink => {
            prepare(&dest)?;
            let link = header
                .link_name()?
                .with_context(|| format!("symlink {} 缺少目标", rel.display()))?;
            let link = link
                .to_str()
                .with_context(|| format!("symlink {} 目标不是 UTF-8", rel.display()))?;
            symlink(link, &dest)?;
            set_owner(&dest, &header)?;
        }
        EntryType::Link => {
            prepare(&dest)?;
            let link = header
                .link_name()?
                .with_context(|| format!("hardlink {} 缺少目标", rel.display()))?;
            let link_rel = clean_path(&link)?;
            let src = root.join(link_rel);
            if !src.exists() {
                bail!(
                    "hardlink {} 的目标 {} 尚未出现",
                    rel.display(),
                    src.display()
                );
            }
            fs::hard_link(&src, &dest)
                .with_context(|| format!("创建 hardlink {} 失败", rel.display()))?;
        }
        EntryType::Char | EntryType::Block => {
            prepare(&dest)?;
            let is_char = header.entry_type() == EntryType::Char;
            make_device(&dest, &header, is_char)?;
            set_owner(&dest, &header)?;
        }
        EntryType::Fifo => {
            prepare(&dest)?;
            let c = cstring(&dest)?;
            let rc = unsafe { libc::mkfifo(c.as_ptr(), (header.mode()? & 0o7777) as libc::mode_t) };
            check_rc(rc, &format!("mkfifo {}", dest.display()))?;
            set_owner(&dest, &header)?;
        }
        other => {
            bail!(
                "层 {} 含不支持的 tar 条目类型 {:?}（不静默跳过）",
                rel.display(),
                other.as_byte()
            );
        }
    }
    Ok(())
}

/// 词法校验：拒绝绝对路径与 `..`，去掉 `./` 前缀。
fn clean_path(p: &Path) -> Result<PathBuf> {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Normal(x) => out.push(x),
            Component::CurDir => {}
            Component::RootDir => bail!("层内出现绝对路径: {}", p.display()),
            Component::ParentDir => bail!("层内出现 '..' 路径: {}", p.display()),
            Component::Prefix(_) => bail!("层内出现非法路径前缀: {}", p.display()),
        }
    }
    Ok(out)
}

/// 保证父目录存在，并确认其解析后仍在 rootfs 内（防符号链接逃逸）
fn ensure_parent(root: &Path, rel: &Path) -> Result<()> {
    let parent = rel.parent().unwrap_or_else(|| Path::new(""));
    let full = root.join(parent);
    fs::create_dir_all(&full)?;
    let canon = full.canonicalize()?;
    let root_canon = root.canonicalize()?;
    if !canon.starts_with(&root_canon) {
        bail!("层内路径经符号链接逃逸出 rootfs: {}", rel.display());
    }
    Ok(())
}

fn prepare(dest: &Path) -> Result<()> {
    match fs::symlink_metadata(dest) {
        Ok(m) => {
            if m.is_dir() {
                fs::remove_dir_all(dest)?;
            } else {
                fs::remove_file(dest)?;
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

fn remove_any(p: &Path) -> Result<()> {
    match fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => fs::remove_dir_all(p)?,
        Ok(_) => fs::remove_file(p)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

fn clear_dir(dir: &Path) -> Result<()> {
    if !dir.is_dir() {
        fs::create_dir_all(dir)?;
        return Ok(());
    }
    for e in fs::read_dir(dir)? {
        let e = e?;
        remove_any(&e.path())?;
    }
    Ok(())
}

fn set_mode(dest: &Path, header: &Header) -> Result<()> {
    let mode = header.mode()? & 0o7777;
    fs::set_permissions(dest, Permissions::from_mode(mode))?;
    Ok(())
}

fn set_owner(dest: &Path, header: &Header) -> Result<()> {
    let uid = header.uid()? as libc::uid_t;
    let gid = header.gid()? as libc::gid_t;
    let c = cstring(dest)?;
    let rc = unsafe { libc::lchown(c.as_ptr(), uid, gid) };
    check_rc(rc, &format!("lchown {}", dest.display()))?;
    Ok(())
}

fn make_device(dest: &Path, header: &Header, is_char: bool) -> Result<()> {
    let major = header.device_major()?.unwrap_or(0);
    let minor = header.device_minor()?.unwrap_or(0);
    let kind = if is_char {
        libc::S_IFCHR
    } else {
        libc::S_IFBLK
    };
    let mode = (header.mode()? & 0o7777) | kind;
    let c = cstring(dest)?;
    let dev = libc::makedev(major, minor);
    let rc = unsafe { libc::mknod(c.as_ptr(), mode as libc::mode_t, dev) };
    check_rc(rc, &format!("mknod {}", dest.display()))?;
    Ok(())
}

fn cstring(p: &Path) -> Result<CString> {
    Ok(CString::new(p.as_os_str().as_bytes())?)
}

fn check_rc(rc: i32, what: &str) -> Result<()> {
    if rc != 0 {
        bail!("{what} 失败: {}", io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_sanitizing_blocks_escape() {
        assert_eq!(
            clean_path(Path::new("./usr/bin")).unwrap(),
            PathBuf::from("usr/bin")
        );
        assert_eq!(clean_path(Path::new("a//b")).unwrap(), PathBuf::from("a/b"));
        assert!(clean_path(Path::new("/etc/passwd")).is_err());
        assert!(clean_path(Path::new("a/../b")).is_err());
        assert!(clean_path(Path::new("../etc")).is_err());
    }

    #[test]
    fn id_remap_uses_mapping_ranges() {
        let maps = vec![
            Mapping {
                container_id: 0,
                host_id: 100000,
                size: 2,
            },
            Mapping {
                container_id: 1000,
                host_id: 200000,
                size: 1,
            },
        ];
        assert_eq!(remap(0, &maps), 100000);
        assert_eq!(remap(1, &maps), 100001);
        assert_eq!(remap(2, &maps), 2); // 未映射的 id 原样保留
        assert_eq!(remap(1000, &maps), 200000);
    }
}
