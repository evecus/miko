//! cgroup v2 资源隔离。只有显式给了 --memory/--cpus/--pids 才启用；
//! 启用失败直接报错（可用 --no-cgroup 显式关闭），不做静默降级。

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::spec::Limits;

pub struct Cgroup {
    pub path: PathBuf,
}

pub fn create(id: &str, limits: &Limits) -> Result<Option<Cgroup>> {
    if limits.is_empty() {
        return Ok(None);
    }
    let root = Path::new("/sys/fs/cgroup");
    if !root.join("cgroup.controllers").is_file() {
        bail!("cgroup v2 未挂载于 /sys/fs/cgroup（无法启用资源限额，可加 --no-cgroup 跳过）");
    }
    let controllers = fs::read_to_string(root.join("cgroup.controllers"))?;
    let has = |name: &str| controllers.split_whitespace().any(|c| c == name);

    let mut need = Vec::new();
    if limits.memory.is_some() && has("memory") {
        need.push("memory");
    }
    if limits.cpus.is_some() && has("cpu") {
        need.push("cpu");
    }
    if limits.pids.is_some() && has("pids") {
        need.push("pids");
    }

    let control = root.join("cgroup.subtree_control");
    let current = fs::read_to_string(&control).unwrap_or_default();
    for name in &need {
        if !current.split_whitespace().any(|c| c == *name) {
            fs::write(&control, format!("+{name}")).with_context(|| {
                format!("启用 cgroup 控制器 {name} 失败（可加 --no-cgroup 跳过资源限额）")
            })?;
        }
    }

    let path = root.join(format!("miko-{id}"));
    fs::create_dir(&path).with_context(|| format!("创建 {} 失败", path.display()))?;

    if let Some(m) = limits.memory {
        fs::write(path.join("memory.max"), m.to_string()).context("写 memory.max 失败")?;
    }
    if let Some(c) = limits.cpus {
        let quota = (c * 100_000.0) as u64;
        fs::write(path.join("cpu.max"), format!("{quota} 100000")).context("写 cpu.max 失败")?;
    }
    if let Some(p) = limits.pids {
        fs::write(path.join("pids.max"), p.to_string()).context("写 pids.max 失败")?;
    }
    Ok(Some(Cgroup { path }))
}

impl Cgroup {
    pub fn attach(&self, pid: i32) -> Result<()> {
        fs::write(self.path.join("cgroup.procs"), pid.to_string())
            .with_context(|| format!("把 pid {pid} 写入 cgroup.procs 失败"))
    }

    pub fn cleanup(&self) {
        if let Err(e) = fs::remove_dir(&self.path) {
            eprintln!("miko: 清理 {} 失败: {e}", self.path.display());
        }
    }
}
