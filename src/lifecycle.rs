//! ps / kill / stop / rm / logs：直接读写状态目录，不经过 daemon。

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use crate::network;
use crate::state::{self, ContainerState};

pub fn ps(root: &Path, all: bool) -> Result<i32> {
    let states = state::list(root)?;
    let mut rows: Vec<(String, String, String, String, String, String)> = Vec::new();
    for s in &states {
        let effective = effective_status(s);
        if !all && effective != "running" {
            continue;
        }
        let pid_col = if effective == "running" {
            s.pid.to_string()
        } else {
            "-".into()
        };
        rows.push((
            short(&s.id, 20),
            short(&s.image, 28),
            short(&s.command.join(" "), 30),
            effective,
            pid_col,
            format!(
                "{}{}",
                s.restarts,
                if s.ports.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", ports_label(s))
                }
            ),
        ));
    }
    println!(
        "{:<20} {:<28} {:<30} {:<10} {:<8} RESTARTS/PORTS",
        "CONTAINER ID", "IMAGE", "COMMAND", "STATUS", "PID"
    );
    for (a, b, c, d, e, f) in &rows {
        println!("{a:<20} {b:<28} {c:<30} {d:<10} {e:<8} {f}");
    }
    if rows.is_empty() {
        println!(
            "(无容器{}）",
            if all {
                ""
            } else {
                "，用 -a 查看已停止的"
            }
        );
    }
    Ok(0)
}

fn ports_label(s: &ContainerState) -> String {
    s.ports
        .iter()
        .map(|p| format!("{}:{}->{}", p.host_ip, p.host_port, p.container_port))
        .collect::<Vec<_>>()
        .join(",")
}

fn effective_status(s: &ContainerState) -> String {
    if s.status == "running" {
        let up = state::alive(s.pid) || s.supervisor_pid.is_some_and(state::alive);
        if up {
            return "running".into();
        }
        return "exited".into();
    }
    s.status.clone()
}

pub fn kill(root: &Path, id_input: &str, signal: Option<&str>) -> Result<i32> {
    // 整段持锁：stop marker 与状态更新必须原子，不能和 supervisor 的重启循环竞争
    let _g = state::lock(root)?;
    let id = state::resolve_id(root, id_input)?;
    let mut s = state::load(root, &id)?;
    // 未显式 -s 时按镜像 config 的 StopSignal（缺省 TERM）
    let sig_name = signal.unwrap_or(&s.stop_signal);
    let sig = parse_signal(sig_name)
        .with_context(|| format!("容器 {id} 的 StopSignal {:?} 非法", s.stop_signal))?;

    // 手动停止必须留标记，否则 always/unless-stopped 会被 supervisor 立刻拉起
    state::set_stop_marker(root, &id)?;

    let mut sent = false;
    if state::alive(s.pid) {
        let rc = unsafe { libc::kill(s.pid, sig) };
        if rc != 0 {
            bail!(
                "向容器 init {} 发送信号 {sig_name} 失败: {}",
                s.pid,
                std::io::Error::last_os_error()
            );
        }
        sent = true;
    }
    if let Some(sp) = s.supervisor_pid {
        if state::alive(sp) {
            // supervisor 收到 TERM 后停止重启循环并退出
            let rc = unsafe { libc::kill(sp, libc::SIGTERM) };
            if rc != 0 {
                bail!(
                    "向 supervisor {sp} 发送 SIGTERM 失败: {}",
                    std::io::Error::last_os_error()
                );
            }
            sent = true;
        }
    }

    s.status = "stopped".into();
    s.finished_at = Some(state::now());
    state::save(root, &s)?;
    if sent {
        println!("{id}");
    } else {
        println!("miko: 容器 {id} 已不在运行，仅记录停止状态");
    }
    Ok(0)
}

/// 对齐 `docker stop`：先发 StopSignal（默认 TERM），等待最多 `timeout` 秒，
/// 仍未退出再 SIGKILL。同时给 supervisor 发 TERM 阻止重启策略拉起。
pub fn stop(root: &Path, ids: &[String], timeout_secs: u64) -> Result<i32> {
    for input in ids {
        stop_one(root, input, timeout_secs)?;
    }
    Ok(0)
}

/// 对齐 `docker start`：启动已停止的容器（复用原有 bundle / 网络 endpoint）。
pub fn start(root: &Path, ids: &[String]) -> Result<i32> {
    for input in ids {
        start_one(root, input)?;
    }
    Ok(0)
}

/// 对齐 `docker restart`：对每个容器先 stop 再 start。
pub fn restart(root: &Path, ids: &[String], timeout_secs: u64) -> Result<i32> {
    for input in ids {
        stop_one(root, input, timeout_secs)?;
        start_one(root, input)?;
    }
    Ok(0)
}

fn start_one(root: &Path, id_input: &str) -> Result<()> {
    let (id, prepared) = {
        let _g = state::lock(root)?;
        let id = state::resolve_id(root, id_input)?;
        let s = state::load(root, &id)?;

        if effective_status(&s) == "running" {
            bail!("容器 {id} 已在运行");
        }
        if s.supervisor_pid.is_some_and(state::alive) {
            bail!(
                "容器 {id} 的 supervisor 仍在运行（pid={}）",
                s.supervisor_pid.unwrap()
            );
        }

        // 清 stop marker，否则 supervisor 一启动就会立刻退出
        state::clear_stop_marker(root, &id);

        let prepared = crate::container::prepare_from_state(root, &s)?;
        (id, prepared)
    };

    let code = crate::supervisor::spawn_supervisor(prepared)?;
    if code != 0 {
        bail!("启动容器 {id} 失败（supervisor 退出码 {code}）");
    }
    Ok(())
}

fn stop_one(root: &Path, id_input: &str, timeout_secs: u64) -> Result<()> {
    let (id, pid, supervisor_pid, sig_name, sig) = {
        let _g = state::lock(root)?;
        let id = state::resolve_id(root, id_input)?;
        let s = state::load(root, &id)?;
        let sig_name = s.stop_signal.clone();
        let sig = parse_signal(&sig_name)
            .with_context(|| format!("容器 {id} 的 StopSignal {sig_name:?} 非法"))?;

        // 先打 stop marker，避免 always / unless-stopped 在等待期间被拉起
        state::set_stop_marker(root, &id)?;

        if !state::alive(s.pid) && !s.supervisor_pid.is_some_and(state::alive) {
            let mut s = s;
            s.status = "stopped".into();
            if s.finished_at.is_none() {
                s.finished_at = Some(state::now());
            }
            state::save(root, &s)?;
            println!("miko: 容器 {id} 已不在运行，仅记录停止状态");
            return Ok(());
        }

        (id, s.pid, s.supervisor_pid, sig_name, sig)
    };

    // 发优雅停止信号（不持锁，避免长时间卡住其它命令）
    if state::alive(pid) {
        let rc = unsafe { libc::kill(pid, sig) };
        if rc != 0 {
            bail!(
                "向容器 init {pid} 发送信号 {sig_name} 失败: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    if let Some(sp) = supervisor_pid {
        if state::alive(sp) {
            let _ = unsafe { libc::kill(sp, libc::SIGTERM) };
        }
    }

    // 等待退出
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    while Instant::now() < deadline {
        if !state::alive(pid) {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    // 超时仍存活 → SIGKILL
    if state::alive(pid) {
        let rc = unsafe { libc::kill(pid, libc::SIGKILL) };
        if rc != 0 && state::alive(pid) {
            bail!(
                "向容器 init {pid} 发送 SIGKILL 失败: {}",
                std::io::Error::last_os_error()
            );
        }
        // 再等一小会儿确认消失
        for _ in 0..20 {
            if !state::alive(pid) {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
    // supervisor 若还在，也强杀
    if let Some(sp) = supervisor_pid {
        if state::alive(sp) {
            let _ = unsafe { libc::kill(sp, libc::SIGKILL) };
        }
    }

    let _g = state::lock(root)?;
    let mut s = state::load(root, &id)?;
    s.status = "stopped".into();
    s.finished_at = Some(state::now());
    // pid 仍可能短暂存在于 state，effective_status 会用 alive() 判断
    state::save(root, &s)?;
    println!("{id}");
    Ok(())
}

pub fn rm(root: &Path, ids: &[String], force: bool) -> Result<i32> {
    for input in ids {
        let id = state::resolve_id(root, input)?;
        if force {
            // 忽略「已不在运行」这类非致命结果；kill 自己会取锁
            let _ = kill(root, &id, None);
        }
        let s = {
            let _g = state::lock(root)?;
            let s = state::load(root, &id)?;
            if effective_status(&s) == "running" {
                bail!("容器 {id} 正在运行，请先 miko stop/kill {id} 或使用 -f");
            }
            s
        };

        // 清理 bundle（--keep 的 bundle 仍归容器所有，rm 一并删除）
        if s.bundle.is_dir() {
            fs::remove_dir_all(&s.bundle)
                .with_context(|| format!("删除 bundle {} 失败", s.bundle.display()))?;
        }
        // 兜底清理内核侧残留：崩溃 / SIGKILL 后可能没走到 ParentNet::cleanup
        cleanup_container_resources(root, &s);
        network::release_container_endpoints(root, &id)?;
        state::remove(root, &id)?;
        println!("{id}");
    }
    Ok(0)
}

/// 清理一个容器可能遗留的内核资源。所有操作都是「不存在即成功」的幂等语义，
/// 因此 rm / system prune 可以无条件调用，不需要知道当时用的哪个防火墙后端。
fn cleanup_container_resources(root: &Path, s: &ContainerState) {
    let cg = Path::new("/sys/fs/cgroup").join(format!("miko-{}", s.id));
    if cg.is_dir() && fs::remove_dir(&cg).is_err() {
        eprintln!("miko: 清理 cgroup {} 失败", cg.display());
    }
    // 网络级 NAT / bridge 由 network rm / prune 管理，单个容器退出不撤销它们；
    // 这里只删除该容器 endpoint 留下的宿主侧设备（veth host 端 / macvlan 残留）。
    for iface in network::host_interfaces(root, &s.id) {
        if let Err(e) = crate::runtime::netlink::delete_link(&iface) {
            eprintln!("miko: 清理网络设备 {iface} 失败: {e:#}");
        }
    }
}

/// system prune：清理所有「已停止」容器残留的内核资源、孤立 bundle 与 IPAM 记录。
/// 刻意不删 state.json —— 状态和日志仍可查，避免误删用户数据。
pub fn prune(root: &Path) -> Result<i32> {
    let states = state::list(root)?;
    let mut cleaned = 0usize;
    for s in &states {
        if effective_status(s) == "running" {
            continue;
        }
        cleanup_container_resources(root, s);
        cleaned += 1;
    }

    let bundles = root.join("bundles");
    let mut orphan_bundles = 0usize;
    if bundles.is_dir() {
        for e in fs::read_dir(&bundles)? {
            let p = e?.path();
            if !p.is_dir() {
                continue;
            }
            let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            // 运行中/已登记的容器都有 state.json，其 bundle 不能动
            if !state::container_dir(root, name)
                .join("state.json")
                .is_file()
                && fs::remove_dir_all(&p).is_ok()
            {
                orphan_bundles += 1;
            }
        }
    }
    let reclaimed = network::gc_orphan_endpoints(root)?;
    println!(
        "miko: 处理 {cleaned} 个已停止容器；删除孤立 bundle {orphan_bundles} 个；回收孤儿 endpoint {reclaimed} 个"
    );
    Ok(0)
}

pub fn logs(root: &Path, id_input: &str) -> Result<i32> {
    let id = state::resolve_id(root, id_input)?;
    let p = state::log_path(root, &id);
    let data = fs::read(&p).with_context(|| format!("容器 {id} 还没有日志文件 {}", p.display()))?;
    print!("{}", String::from_utf8_lossy(&data));
    Ok(0)
}

fn parse_signal(s: &str) -> Result<i32> {
    let upper = s.trim().to_ascii_uppercase();
    let name = upper.strip_prefix("SIG").unwrap_or(&upper);
    let known = match name {
        "HUP" => 1,
        "INT" => 2,
        "QUIT" => 3,
        "KILL" => 9,
        "USR1" => 10,
        "USR2" => 12,
        "TERM" => 15,
        "CONT" => 18,
        "STOP" => 19,
        _ => s
            .trim()
            .parse::<i32>()
            .with_context(|| format!("未知信号 {s:?}"))?,
    };
    if !(1..=64).contains(&known) {
        bail!("信号编号超出范围: {known}");
    }
    Ok(known)
}

fn short(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_parsing() {
        assert_eq!(parse_signal("TERM").unwrap(), 15);
        assert_eq!(parse_signal("SIGKILL").unwrap(), 9);
        assert_eq!(parse_signal("sigint").unwrap(), 2);
        assert_eq!(parse_signal("9").unwrap(), 9);
        assert!(parse_signal("BOGUS").is_err());
        assert!(parse_signal("999").is_err());
        assert!(parse_signal("0").is_err());
    }

    #[test]
    fn short_truncates_with_ellipsis() {
        assert_eq!(short("abc", 5), "abc");
        assert_eq!(short("abcdef", 4).chars().count(), 4);
        assert!(short("abcdef", 4).ends_with('…'));
    }
}
