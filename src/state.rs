//! 容器状态持久化：状态目录即数据库，无常驻 daemon、无 socket。
//!
//! <state_root>/containers/<id>/{state.json, config.json, log, stop}
//! <state_root>/bundles/<id>/{rootfs/, config.json}
//! <state_root>/{state.lock, networks.json}   ← 网络对象与 IPAM 分配
//! 所有写入都走 tmp + rename，避免 supervisor 与 ps 并发读到半截文件。
//!
//! 并发控制分两层：
//! - 跨进程：`state.lock` 上的 flock(LOCK_EX)，包住所有 read-modify-write；
//! - 同进程：thread_local 深度计数，让锁可重入（`remove` 内会再进 IPAM）。
//!
//! state 的写操作集中在单一线程（supervisor / CLI 主线程），转发器与日志
//! tee 线程不碰状态文件。

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::spec::PortSpec;

pub const DEFAULT_ROOT: &str = "/var/lib/miko";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ContainerState {
    pub id: String,
    pub image: String,
    pub command: Vec<String>,
    /// created / running / exited / stopped
    pub status: String,
    /// 容器 init 进程（宿主 PID 命名空间中的 pid）
    pub pid: i32,
    /// -d 模式下的 supervisor pid
    pub supervisor_pid: Option<i32>,
    pub created_at: u64,
    pub started_at: Option<u64>,
    pub finished_at: Option<u64>,
    pub exit_code: Option<i32>,
    pub restarts: u32,
    pub restart_policy: String,
    pub detached: bool,
    pub bundle: PathBuf,
    pub net_mode: String,
    pub ports: Vec<PortSpec>,
    pub keep: bool,
    /// 镜像声明的 StopSignal（缺省 TERM）；kill 未显式给 -s 时用它
    #[serde(default = "default_stop_signal")]
    pub stop_signal: String,
    /// 初始接入的网络（ps 展示用；全部 endpoint 以 networks.json 为准）
    #[serde(default)]
    pub network_id: Option<String>,
    #[serde(default)]
    pub network_name: Option<String>,
    #[serde(default)]
    pub endpoint_id: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
    /// 该容器所有 endpoint 的宿主侧设备名，供 rm / system prune 兜底清理
    #[serde(default)]
    pub host_ifaces: Vec<String>,
}

fn default_stop_signal() -> String {
    "TERM".to_string()
}

/// 把镜像 config 的 StopSignal 归一化成 parse_signal 能吃的名字。
pub fn normalize_stop_signal(s: &str) -> String {
    let t = s.trim();
    if t.is_empty() {
        return default_stop_signal();
    }
    let upper = t.to_ascii_uppercase();
    upper.strip_prefix("SIG").unwrap_or(&upper).to_string()
}

pub fn root(state_dir: Option<&Path>) -> PathBuf {
    state_dir
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_ROOT))
}

pub fn containers_dir(root: &Path) -> PathBuf {
    root.join("containers")
}

pub fn container_dir(root: &Path, id: &str) -> PathBuf {
    containers_dir(root).join(id)
}

pub fn bundle_path(root: &Path, id: &str) -> PathBuf {
    root.join("bundles").join(id)
}

pub fn log_path(root: &Path, id: &str) -> PathBuf {
    container_dir(root, id).join("log")
}

pub fn stop_marker(root: &Path, id: &str) -> PathBuf {
    container_dir(root, id).join("stop")
}

pub fn ensure_dirs(root: &Path, id: &str) -> Result<()> {
    fs::create_dir_all(container_dir(root, id))
        .with_context(|| format!("创建状态目录 {} 失败", container_dir(root, id).display()))?;
    Ok(())
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn gen_id() -> String {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    format!("md-{t:x}-{}", std::process::id())
}

pub fn validate_id(id: &str) -> Result<()> {
    if id == "." || id == ".." {
        bail!("容器名 {id:?} 非法（'.' / '..' 会逃出状态目录）");
    }
    if id.is_empty()
        || id.len() > 64
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        bail!("容器名 {id:?} 非法（只允许 [A-Za-z0-9._-]，长度 1..64）");
    }
    Ok(())
}

pub fn load(root: &Path, id: &str) -> Result<ContainerState> {
    let p = container_dir(root, id).join("state.json");
    let data = fs::read(&p).with_context(|| format!("读取 {} 失败", p.display()))?;
    serde_json::from_slice(&data).with_context(|| format!("解析 {} 失败", p.display()))
}

pub fn save(root: &Path, s: &ContainerState) -> Result<()> {
    let dir = container_dir(root, &s.id);
    fs::create_dir_all(&dir)?;
    let final_path = dir.join("state.json");
    let tmp = dir.join("state.json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(s)?)?;
    fs::rename(&tmp, &final_path).with_context(|| format!("写入 {} 失败", final_path.display()))?;
    Ok(())
}

/// 用 `let _g = state::lock(root)?;` 包住 load -> 修改 -> save，避免并发丢更新。
/// 可重入：同一线程嵌套获取只增加深度，不会自己把自己锁死。
pub fn lock(root: &Path) -> Result<StateLock> {
    StateLock::new(root)
}

thread_local! {
    static LOCK_DEPTH: Cell<u32> = const { Cell::new(0) };
}

pub struct StateLock {
    fd: Option<i32>,
}

impl StateLock {
    fn new(root: &Path) -> Result<Self> {
        let depth = LOCK_DEPTH.with(|d| d.get());
        if depth > 0 {
            LOCK_DEPTH.with(|d| d.set(depth + 1));
            return Ok(Self { fd: None });
        }
        fs::create_dir_all(root)
            .with_context(|| format!("创建状态根目录 {} 失败", root.display()))?;
        let path = root.join("state.lock");
        let c = CString::new(path.as_os_str().as_bytes()).context("状态锁路径含 NUL 字节")?;
        let fd = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_CREAT | libc::O_RDWR | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            bail!(
                "打开 {} 失败: {}",
                path.display(),
                io::Error::last_os_error()
            );
        }
        if unsafe { libc::flock(fd, libc::LOCK_EX) } != 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            bail!("加锁 {} 失败: {err}", path.display());
        }
        LOCK_DEPTH.with(|d| d.set(1));
        Ok(Self { fd: Some(fd) })
    }
}

impl Drop for StateLock {
    fn drop(&mut self) {
        LOCK_DEPTH.with(|d| {
            let n = d.get();
            if n == 0 {
                return;
            }
            if n > 1 {
                d.set(n - 1);
                return;
            }
            if let Some(fd) = self.fd.take() {
                unsafe {
                    libc::flock(fd, libc::LOCK_UN);
                    libc::close(fd);
                }
            }
            d.set(0);
        });
    }
}

pub fn list(root: &Path) -> Result<Vec<ContainerState>> {
    let dir = containers_dir(root);
    if !dir.is_dir() {
        return Ok(vec![]);
    }
    let mut out = Vec::new();
    for e in fs::read_dir(&dir)? {
        let e = e?;
        let p = e.path().join("state.json");
        if !p.is_file() {
            continue;
        }
        match fs::read(&p).and_then(|d| {
            serde_json::from_slice::<ContainerState>(&d)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
        }) {
            Ok(s) => out.push(s),
            Err(err) => eprintln!("miko: 跳过损坏的状态文件 {}: {err}", p.display()),
        }
    }
    out.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    Ok(out)
}

/// 精确 id 优先，其次唯一前缀匹配。
pub fn resolve_id(root: &Path, input: &str) -> Result<String> {
    if input == "." || input == ".." {
        bail!("非法容器标识 {input:?}");
    }
    let all = list(root)?;
    if all.iter().any(|s| s.id == input) {
        return Ok(input.to_string());
    }
    let hits: Vec<&ContainerState> = all.iter().filter(|s| s.id.starts_with(input)).collect();
    match hits.len() {
        0 => bail!("找不到容器 {input:?}"),
        1 => Ok(hits[0].id.clone()),
        n => bail!("{input:?} 匹配到 {n} 个容器，请给出完整 id"),
    }
}

pub fn alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }
    io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

pub fn remove(root: &Path, id: &str) -> Result<()> {
    let dir = container_dir(root, id);
    if dir.is_dir() {
        fs::remove_dir_all(&dir).with_context(|| format!("删除 {} 失败", dir.display()))?;
    }
    Ok(())
}

pub fn set_stop_marker(root: &Path, id: &str) -> Result<()> {
    fs::write(stop_marker(root, id), b"1")?;
    Ok(())
}

pub fn has_stop_marker(root: &Path, id: &str) -> bool {
    stop_marker(root, id).exists()
}

pub fn clear_stop_marker(root: &Path, id: &str) {
    let _ = fs::remove_file(stop_marker(root, id));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_validation_rejects_traversal() {
        assert!(validate_id("web").is_ok());
        assert!(validate_id("my.app-1").is_ok());
        assert!(validate_id(".").is_err());
        assert!(validate_id("..").is_err());
        assert!(validate_id("../etc").is_err());
        assert!(validate_id("a/b").is_err());
        assert!(validate_id("").is_err());
        assert!(validate_id(&"x".repeat(65)).is_err());
    }

    #[test]
    fn stop_signal_normalization() {
        assert_eq!(normalize_stop_signal(""), "TERM");
        assert_eq!(normalize_stop_signal("  SIGKILL "), "KILL");
        assert_eq!(normalize_stop_signal("9"), "9");
        assert_eq!(normalize_stop_signal("sigterm"), "TERM");
    }

    #[test]
    fn state_json_is_backward_compatible() {
        // 旧版本 state.json 没有网络相关字段，全部走 serde(default)
        let old = r#"{"id":"c1","image":"busybox","command":["sh"],"status":"exited","pid":0,
            "supervisor_pid":null,"created_at":1,"started_at":null,"finished_at":null,
            "exit_code":0,"restarts":0,"restart_policy":"no","detached":false,
            "bundle":"/tmp/b","net_mode":"host","ports":[],"keep":false}"#;
        let s: ContainerState = serde_json::from_str(old).unwrap();
        assert_eq!(s.stop_signal, "TERM");
        assert!(s.network_id.is_none());
        assert!(s.ip.is_none());
        assert!(s.host_ifaces.is_empty());
    }
}
