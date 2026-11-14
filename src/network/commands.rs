//! `miko network` 子命令：对齐 docker network 的可观察语义与 libnetwork 的对象模型。
//!
//! 无常驻 daemon：所有状态落在 networks.json，内核侧资源（bridge / NAT / vlan parent）
//! 在 create 时立即下发、在 rm / prune 时撤销，并由每次容器启动的 `ensure_network` 幂等重建。

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::net::Ipv4Addr;
use std::path::Path;

use super::{model, store};
use crate::cli::{NetworkConnectArgs, NetworkCreateArgs, NetworkDisconnectArgs, NetworkLsArgs};
use crate::network::{
    attachments_for_container, create_run_endpoint, release_endpoint, DriverKind, Network,
};
use crate::options::FirewallBackend;
use crate::runtime::netdrv::host_default_gateway;
use crate::{runtime, state};

// ---------------------------------------------------------------- create

pub fn create(root: &Path, args: &NetworkCreateArgs) -> Result<i32> {
    let driver = DriverKind::parse(&args.driver)?;
    if driver.is_builtin_driver() {
        bail!(
            "{} 是内置网络，不能创建；直接用 --net {}",
            driver.label(),
            driver.label()
        );
    }
    let backend = FirewallBackend::parse(&args.firewall_backend)?;
    let options = model::parse_kv(&args.opts, "-o/--opt")?;
    let labels = model::parse_kv(&args.labels, "--label")?;
    let aux = model::parse_kv(&args.aux_addresses, "--aux-address")?;
    let ip_range = args
        .ip_range
        .as_deref()
        .map(model::Ipv4Cidr::parse)
        .transpose()?;
    let gateway = args
        .gateway
        .as_deref()
        .map(|s| s.parse::<Ipv4Addr>())
        .transpose()
        .context("解析 --gateway 失败")?;

    // macvlan 必须显式给出宿主所在网段；gateway 可自动取宿主默认路由。
    let subnet = match &args.subnet {
        Some(s) => Some(model::Ipv4Cidr::parse(s)?),
        None => {
            if driver == DriverKind::Macvlan {
                bail!("macvlan 网络必须显式指定 --subnet（应与 parent 接口的物理网段一致）");
            }
            let existing = store::read_only(root)?.networks;
            Some(model::pick_subnet(&existing)?)
        }
    };
    let gateway = match gateway {
        Some(g) => Some(g),
        None if driver == DriverKind::Macvlan => Some(
            host_default_gateway()
                .context("macvlan 网络需要 --gateway（无法从宿主默认路由推断）")?,
        ),
        None => None,
    };

    let mut net = model::build_network(
        &args.name,
        driver,
        subnet,
        gateway,
        ip_range,
        aux,
        options,
        labels,
        args.internal,
        state::now(),
    )?;
    net.attachable = args.attachable;
    net.validate_options()?;

    store::with_store(root, |s| {
        model::validate_conflicts(&s.networks, &net)?;
        s.networks.insert(net.id.clone(), net.clone());
        Ok(net.id.clone())
    })?;

    // 记录已落盘，再下发内核资源；失败则回滚记录与半成品资源。
    if let Err(e) = runtime::netdrv::ensure_network(&net, backend, false) {
        let _ = runtime::netdrv::teardown_network(&net);
        let _ = store::with_store(root, |s| {
            s.networks.remove(&net.id);
            Ok(())
        });
        return Err(e).with_context(|| format!("创建网络 {} 的内核资源失败", net.name));
    }

    println!("{}", net.id);
    println!(
        "miko: network {} created driver={} subnet={} gateway={}{} firewall={}",
        net.name,
        net.driver.label(),
        net.ipam.subnet,
        net.ipam.gateway,
        if net.internal { " internal" } else { "" },
        runtime::firewall::active_label(backend),
    );
    Ok(0)
}

// ---------------------------------------------------------------- ls

pub fn ls(root: &Path, args: &NetworkLsArgs) -> Result<i32> {
    let store = store::read_only(root)?;
    let filters = parse_filters(&args.filters)?;
    let mut rows: Vec<&Network> = store
        .networks
        .values()
        .filter(|n| {
            filters.iter().all(|(k, v)| match k.as_str() {
                "driver" => n.driver.label() == v,
                "name" => glob_match(v, &n.name),
                "id" => n.id.starts_with(v),
                "scope" => v == "local",
                "label" => match v.split_once('=') {
                    Some((k, val)) => n.labels.get(k).is_some_and(|x| x == val),
                    None => n.labels.contains_key(v),
                },
                other => {
                    eprintln!("miko: 忽略未知 network ls 过滤条件 {other:?}");
                    true
                }
            })
        })
        .collect();
    rows.sort_by(|a, b| a.name.cmp(&b.name));

    if args.quiet {
        for n in &rows {
            println!("{}", n.id);
        }
        return Ok(0);
    }
    if let Some(tpl) = &args.format {
        for n in &rows {
            println!("{}", render_template(tpl, n, args.no_trunc));
        }
        return Ok(0);
    }
    println!(
        "{:<14} {:<20} {:<10} {:<7} {:<20} {:<16} ENDPOINTS",
        "NETWORK ID", "NAME", "DRIVER", "SCOPE", "SUBNET", "GATEWAY"
    );
    for n in &rows {
        println!(
            "{:<14} {:<20} {:<10} {:<7} {:<20} {:<16} {}",
            id_column(n, args.no_trunc, 12),
            truncate(&n.name, 20),
            n.driver.label(),
            "local",
            truncate(&n.ipam.subnet, 20),
            truncate(&n.ipam.gateway, 16),
            n.endpoints.len(),
        );
    }
    Ok(0)
}

fn id_column(n: &Network, no_trunc: bool, len: usize) -> String {
    if no_trunc || n.id.len() <= len {
        n.id.clone()
    } else {
        n.id.chars().take(len).collect()
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

fn render_template(tpl: &str, n: &Network, no_trunc: bool) -> String {
    let row = json!({
        "ID": n.id,
        "Name": n.name,
        "Driver": n.driver.label(),
        "Scope": "local",
        "Subnet": n.ipam.subnet,
        "Gateway": n.ipam.gateway,
        "Internal": n.internal,
        "Containers": n.endpoints.len(),
        "Labels": n.labels,
    });
    let mut out = tpl.to_string();
    for key in [
        "ID",
        "Name",
        "Driver",
        "Scope",
        "Subnet",
        "Gateway",
        "Containers",
    ] {
        let token = format!("{{{{.{key}}}}}");
        let value = match key {
            "ID" => id_column(n, no_trunc, 12),
            "Containers" => row["Containers"].to_string(),
            _ => row[key].as_str().unwrap_or("").to_string(),
        };
        out = out.replace(&token, &value);
    }
    out.replace("{{json .}}", &row.to_string())
}

// ---------------------------------------------------------------- inspect

pub fn inspect(root: &Path, references: &[String]) -> Result<i32> {
    let store = store::read_only(root)?;
    let mut out = Vec::new();
    for r in references {
        let n = store::get(&store, r)?;
        out.push(inspect_json(n));
    }
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(0)
}

fn inspect_json(n: &Network) -> Value {
    let mut config = json!({
        "Subnet": n.ipam.subnet,
        "Gateway": n.ipam.gateway,
    });
    if let Some(r) = &n.ipam.ip_range {
        config["IPRange"] = json!(r);
    }
    if !n.ipam.aux_addresses.is_empty() {
        config["AuxiliaryAddresses"] = json!(n.ipam.aux_addresses);
    }
    let mut containers = serde_json::Map::new();
    for ep in n.endpoints.values() {
        containers.insert(
            ep.container_id.clone(),
            json!({
                "Name": ep.container_name,
                "EndpointID": ep.id,
                "MacAddress": ep.mac,
                "IPv4Address": if ep.ip.is_empty() {
                    String::new()
                } else {
                    format!("{}/{}", ep.ip, n.subnet_cidr().map(|c| c.prefix()).unwrap_or(24))
                },
                "IPv6Address": "",
            }),
        );
    }
    json!({
        "Name": n.name,
        "Id": n.id,
        "Created": rfc3339(n.created_at),
        "Scope": "local",
        "Driver": n.driver.label(),
        "EnableIPv6": false,
        "IPAM": {
            "Driver": if n.ipam.driver.is_empty() { "default" } else { n.ipam.driver.as_str() },
            "Options": Value::Null,
            "Config": [config],
        },
        "Internal": n.internal,
        "Attachable": n.attachable,
        "Ingress": false,
        "ConfigFrom": { "Network": "" },
        "ConfigOnly": false,
        "Containers": containers,
        "Options": n.options,
        "Labels": n.labels,
    })
}

// ---------------------------------------------------------------- rm / prune

pub fn rm(root: &Path, references: &[String], force: bool) -> Result<i32> {
    for r in references {
        let net = {
            let store = store::read_only(root)?;
            store::get(&store, r)?.clone()
        };
        if net.builtin {
            bail!(
                "内置网络 {} 不能删除（host / none / bridge 是 miko 预置网络）",
                net.name
            );
        }
        if !net.endpoints.is_empty() && !force {
            bail!(
                "网络 {} 还有 {} 个 endpoint（容器）在使用；先 disconnect 或加 -f 强制断开",
                net.name,
                net.endpoints.len()
            );
        }
        if force {
            for ep in net.endpoints.values() {
                detach_kernel(root, &ep.container_id, &ep.id);
            }
        }
        runtime::netdrv::teardown_network(&net)
            .with_context(|| format!("删除网络 {} 的宿主资源失败", net.name))?;
        // 后端可能在中途从 iptables 换成 nftables，两个后端都兜底撤销一次。
        runtime::firewall::cleanup_orphan(&net.id, &net.ipam.subnet, &net.bridge_name());
        store::with_store(root, |s| {
            s.networks.remove(&net.id);
            Ok(())
        })?;
        println!("{}", net.name);
    }
    Ok(0)
}

pub fn prune(root: &Path, force: bool, filters: &[String]) -> Result<i32> {
    let parsed = parse_filters(filters)?;
    let until = parsed
        .iter()
        .find(|(k, _)| k == "until")
        .map(|(_, v)| parse_until(v))
        .transpose()?;
    let now = state::now();
    let store = store::read_only(root)?;
    let candidates: Vec<Network> = store
        .networks
        .values()
        .filter(|n| !n.builtin && n.endpoints.is_empty())
        .filter(|n| until.is_none_or(|secs| now.saturating_sub(n.created_at) >= secs))
        .filter(|n| {
            parsed
                .iter()
                .filter(|(k, _)| k == "label")
                .all(|(_, v)| match v.split_once('=') {
                    Some((k, val)) => n.labels.get(k).is_some_and(|x| x == val),
                    None => n.labels.contains_key(v),
                })
        })
        .cloned()
        .collect();

    if !force {
        for n in &candidates {
            println!("{} ({})", n.name, n.id);
        }
        println!(
            "miko: 预览模式：以上 {} 个网络可被删除；加 -f 实际执行",
            candidates.len()
        );
        return Ok(0);
    }
    for n in &candidates {
        runtime::netdrv::teardown_network(n)
            .with_context(|| format!("清理网络 {} 的宿主资源失败", n.name))?;
        runtime::firewall::cleanup_orphan(&n.id, &n.ipam.subnet, &n.bridge_name());
        let name = n.name.clone();
        store::with_store(root, |s| {
            s.networks.remove(&n.id);
            Ok(())
        })?;
        println!("{name}");
    }
    println!("miko: 删除 {} 个未使用的网络", candidates.len());
    Ok(0)
}

// ---------------------------------------------------------------- connect / disconnect

pub fn connect(root: &Path, args: &NetworkConnectArgs) -> Result<i32> {
    let backend = FirewallBackend::parse(&args.firewall_backend)?;
    let container_id = state::resolve_id(root, &args.container)?;
    let net = {
        let store = store::read_only(root)?;
        store::get(&store, &args.network)?.clone()
    };
    if attachments_for_container(root, &container_id)?
        .iter()
        .any(|a| a.driver == DriverKind::Host)
    {
        bail!("容器 {container_id} 使用 host 网络，不能再接入其它网络（docker 同样限制）");
    }
    match net.driver {
        DriverKind::Bridge | DriverKind::Macvlan => {}
        other => bail!(
            "不能把容器接入 {} 网络（host / none 请在 run 时用 --net 指定）",
            other.label()
        ),
    }
    let requested_ip = args
        .ip
        .as_deref()
        .map(|s| s.parse::<Ipv4Addr>())
        .transpose()
        .context("解析 --ip 失败")?;

    // 分配并持久化 endpoint（失败自动回滚）
    let (_, mut guard) = create_run_endpoint(
        root,
        &net.id,
        &container_id,
        &container_id,
        requested_ip,
        args.mac_address.clone(),
        args.aliases.clone(),
    )?;
    guard.disarm();

    let attachments = attachments_for_container(root, &container_id)?;
    let att = attachments
        .iter()
        .find(|a| a.network_id == net.id)
        .context("刚分配的 endpoint 未出现在 networks.json")?;

    if let Some(pid) = running_pid(root, &container_id) {
        match runtime::netdrv::hotplug_join(att, pid, backend, false) {
            Ok(()) => println!(
                "miko: 容器 {} 已热接入网络 {}（{}）",
                container_id, net.name, att.target_iface
            ),
            Err(e) => {
                // endpoint 已持久化，重启容器（或 supervisor 自动重启）时会自动补齐。
                let _ = runtime::netdrv::leave_host_side(att);
                eprintln!("miko: 热接入失败（{e:#}）；endpoint 已保存，容器下次启动后生效");
            }
        }
    } else {
        println!(
            "miko: 容器 {} 未运行，已记录接入网络 {}，下次启动生效",
            container_id, net.name
        );
    }
    println!("{}", net.name);
    Ok(0)
}

pub fn disconnect(root: &Path, args: &NetworkDisconnectArgs) -> Result<i32> {
    let container_id = state::resolve_id(root, &args.container)?;
    let store = store::read_only(root)?;
    let net = store::get(&store, &args.network)?;
    let endpoint_id = match net.endpoint_for_container(&container_id) {
        Some(ep) => ep.id.clone(),
        None if args.force => {
            println!("{}", net.name);
            return Ok(0);
        }
        None => bail!("容器 {} 未接入网络 {}", container_id, net.name),
    };
    let net = net.clone();
    drop(store);

    let attachments = attachments_for_container(root, &container_id)?;
    let att = attachments
        .iter()
        .find(|a| a.endpoint_id == endpoint_id)
        .cloned();
    if let (Some(pid), Some(att)) = (running_pid(root, &container_id), att.as_ref()) {
        if let Err(e) = runtime::netdrv::hotplug_leave(att, pid) {
            eprintln!("miko: 热断开失败（{e:#}）；将在容器退出后清理残留");
        }
    }
    if let Some(att) = &att {
        let _ = runtime::netdrv::leave_host_side(att);
    }
    release_endpoint(root, &net.id, &endpoint_id)?;
    if attachments.len() == 1 {
        println!(
            "miko: 容器 {} 已无任何网络，出网与端口映射均不可用",
            container_id
        );
    }
    println!("{}", net.name);
    Ok(0)
}

/// 强制删网络时，把一个 endpoint 的内核设备从运行中的容器里摘掉。
fn detach_kernel(root: &Path, container_id: &str, endpoint_id: &str) {
    let attachments = attachments_for_container(root, container_id).unwrap_or_default();
    let Some(att) = attachments.iter().find(|a| a.endpoint_id == endpoint_id) else {
        return;
    };
    if let Some(pid) = running_pid(root, container_id) {
        let _ = runtime::netdrv::hotplug_leave(att, pid);
    }
    let _ = runtime::netdrv::leave_host_side(att);
}

// ---------------------------------------------------------------- 工具

fn running_pid(root: &Path, container_id: &str) -> Option<i32> {
    let s = state::load(root, container_id).ok()?;
    if s.status == "running" && state::alive(s.pid) {
        Some(s.pid)
    } else {
        None
    }
}

fn parse_filters(items: &[String]) -> Result<Vec<(String, String)>> {
    items
        .iter()
        .map(|s| {
            let (k, v) = s
                .split_once('=')
                .with_context(|| format!("--filter 需要 KEY=VALUE，收到 {s:?}"))?;
            Ok((k.to_string(), v.to_string()))
        })
        .collect()
}

fn parse_until(v: &str) -> Result<u64> {
    let split = v.find(|c: char| !c.is_ascii_digit()).unwrap_or(v.len());
    let (num, unit) = v.split_at(split);
    let n: u64 = num
        .parse()
        .with_context(|| format!("until 数值 {num:?} 非法"))?;
    let mul = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => bail!("until 只支持 <n>[s|m|h|d]，收到 {v:?}"),
    };
    Ok(n * mul)
}

/// 支持 `*`（任意字符）与 `?`（单字符）的名字匹配。
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut mark = 0usize;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            pi += 1;
            mark = ti;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// 1970 起秒数 -> RFC3339 UTC（不引入 chrono 依赖）。
fn rfc3339(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant 的 civil_from_days（days since 1970-01-01）。
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    y += if m <= 2 { 1 } else { 0 };
    (y, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_epoch_and_known_dates() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_600_000_000), "2020-09-13T12:26:40Z");
        assert_eq!(rfc3339(1_764_000_000), "2025-11-24T16:00:00Z");
    }

    #[test]
    fn glob_matching() {
        assert!(glob_match("*alpine*", "my-alpine-net"));
        assert!(glob_match("net?", "net1"));
        assert!(!glob_match("net?", "net12"));
        assert!(glob_match("bridge", "bridge"));
        assert!(!glob_match("bridge", "host"));
    }

    #[test]
    fn until_parsing() {
        assert_eq!(parse_until("24h").unwrap(), 86400);
        assert_eq!(parse_until("7d").unwrap(), 604800);
        assert_eq!(parse_until("30").unwrap(), 30);
        assert!(parse_until("nonsense").is_err());
    }

    #[test]
    fn inspect_shape_matches_docker_fields() {
        let mut net = model::default_networks(0)
            .into_iter()
            .find(|n| n.name == "bridge")
            .unwrap();
        let ep = model::allocate_endpoint(&mut net, "c1", "c1", None, None, vec!["web".into()], 1)
            .unwrap();
        let v = inspect_json(&net);
        assert_eq!(v["Driver"], "bridge");
        assert_eq!(v["Scope"], "local");
        assert_eq!(v["IPAM"]["Config"][0]["Subnet"], "172.17.0.0/16");
        assert_eq!(v["Containers"]["c1"]["EndpointID"], ep.id);
        assert_eq!(v["Containers"]["c1"]["IPv4Address"], "172.17.0.2/16");
    }
}
