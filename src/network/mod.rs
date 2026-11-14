//! 网络管理入口：把 libnetwork 的 Network / Endpoint / IPAM 模型落到状态目录。
//!
//! 与「每容器独占一个 /24」的旧实现不同，网络是独立对象：先 `network create`，
//! 再 `run --net <name>` 接入；容器可以接多个网络（`network connect`），
//! 地址由每个网络的 IPAM 持久分配，重启容器时从 networks.json 重新读取全部 endpoint。

pub mod commands;
pub mod model;
pub mod store;

pub use model::{fnv1a, Attachment, DriverKind, Endpoint, Network};

use anyhow::{bail, Context, Result};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use crate::state;

/// prepare 失败时自动回滚刚分配的 endpoint（IPAM 不能泄漏地址）。
pub struct EndpointGuard {
    root: PathBuf,
    network_id: String,
    endpoint_id: String,
    armed: bool,
}

impl EndpointGuard {
    pub fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for EndpointGuard {
    fn drop(&mut self) {
        if self.armed {
            if let Err(e) = release_endpoint(&self.root, &self.network_id, &self.endpoint_id) {
                eprintln!("miko: 回滚 endpoint 失败: {e:#}");
            }
        }
    }
}

/// 从 networks.json 组装一个容器当前的全部网络附件（按接入时间排序）。
/// 第一个带网关且非 internal 的网络提供默认路由，接口名依次为 eth0 / eth1 ...
pub fn attachments_for_container(root: &Path, container_id: &str) -> Result<Vec<Attachment>> {
    let store = store::read_only(root)?;
    let mut pairs: Vec<(&Network, &Endpoint)> = store
        .networks
        .values()
        .flat_map(|n| {
            n.endpoints
                .values()
                .filter(move |e| e.container_id == container_id)
                .map(move |e| (n, e))
        })
        .collect();
    pairs.sort_by(|(na, ea), (nb, eb)| {
        ea.created_at
            .cmp(&eb.created_at)
            .then_with(|| ea.id.cmp(&eb.id))
            .then_with(|| na.id.cmp(&nb.id))
    });

    if pairs.len() > 1 && pairs.iter().any(|(n, _)| n.driver == DriverKind::Host) {
        bail!("host 网络不能与其它网络同时接入同一个容器（docker 同样限制）");
    }

    let mut out = Vec::with_capacity(pairs.len());
    let mut default_done = false;
    for (index, (net, ep)) in pairs.iter().enumerate() {
        let wants_default = !default_done && !net.internal && !ep.ip.is_empty();
        let att = Attachment::new(net, ep, index, wants_default)
            .with_context(|| format!("恢复网络 {} 的 endpoint 失败", net.name))?;
        if att.default_route {
            default_done = true;
        }
        out.push(att);
    }
    Ok(out)
}

/// run 时分配初始端点。返回附件与回滚 guard（prepare 失败时自动释放 IP）。
pub fn create_run_endpoint(
    root: &Path,
    network_ref: &str,
    container_id: &str,
    container_name: &str,
    requested_ip: Option<Ipv4Addr>,
    requested_mac: Option<String>,
    aliases: Vec<String>,
) -> Result<(Attachment, EndpointGuard)> {
    let (att, network_id, endpoint_id) = store::with_store(root, |s| {
        let id = store::find_id(s, network_ref)?;
        let net = s.networks.get_mut(&id).context("网络在分配过程中消失")?;
        let ep = model::allocate_endpoint(
            net,
            container_id,
            container_name,
            requested_ip,
            requested_mac,
            aliases,
            state::now(),
        )?;
        let att = Attachment::new(net, &ep, 0, !net.internal && !ep.ip.is_empty())?;
        Ok((att, id, ep.id))
    })?;
    Ok((
        att,
        EndpointGuard {
            root: root.to_path_buf(),
            network_id,
            endpoint_id,
            armed: true,
        },
    ))
}

/// 释放一个 endpoint（IPAM 地址立即可复用）。
pub fn release_endpoint(root: &Path, network_id: &str, endpoint_id: &str) -> Result<()> {
    store::with_store(root, |s| {
        if let Some(net) = s.networks.get_mut(network_id) {
            net.endpoints.remove(endpoint_id);
        }
        Ok(())
    })
}

/// rm 容器时释放它的所有 endpoint。
pub fn release_container_endpoints(root: &Path, container_id: &str) -> Result<usize> {
    store::with_store(root, |s| {
        let mut removed = 0;
        for net in s.networks.values_mut() {
            let before = net.endpoints.len();
            net.endpoints.retain(|_, e| e.container_id != container_id);
            removed += before - net.endpoints.len();
        }
        Ok(removed)
    })
}

/// system prune：回收指向已不存在容器的孤儿 endpoint（对齐旧 gc_ipam 的语义）。
pub fn gc_orphan_endpoints(root: &Path) -> Result<usize> {
    store::with_store(root, |s| {
        let mut removed = 0;
        for net in s.networks.values_mut() {
            let before = net.endpoints.len();
            net.endpoints.retain(|_, e| {
                state::container_dir(root, &e.container_id)
                    .join("state.json")
                    .is_file()
            });
            removed += before - net.endpoints.len();
        }
        Ok(removed)
    })
}

/// 供 lifecycle 兜底清理：某容器所有 endpoint 在宿主 netns 里可见的设备名。
pub fn host_interfaces(root: &Path, container_id: &str) -> Vec<String> {
    attachments_for_container(root, container_id)
        .unwrap_or_default()
        .into_iter()
        .filter(|a| a.needs_link())
        .map(|a| a.host_iface)
        .collect()
}

pub fn network_by_ref(root: &Path, reference: &str) -> Result<Network> {
    let store = store::read_only(root)?;
    Ok(store::get(&store, reference)?.clone())
}
