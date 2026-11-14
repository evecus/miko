//! 网络级防火墙规则：nftables 优先、iptables 降级（语义对齐 docker --firewall-backend）。
//!
//! 与旧的「每容器一张表」不同，这里按 **网络** 下发规则，对齐 libnetwork 的 bridge 驱动：
//! - 一条 `MASQUERADE` 覆盖整条子网（非 internal 且 enable_ip_masquerade=true）；
//! - `enable_icc=false` 时禁止同一 bridge 内的二层转发；
//! - 每个网络一张独立的 nft `ip` 表（表名由 network id 派生），删除网络时整表撤销，
//!   不污染宿主 ruleset；iptables 后端按 subnet / bridge 名做幂等 `-C/-A/-D --wait`。
//!
//! 端口映射本身仍是纯用户态转发器，与防火墙后端无关。

use anyhow::{bail, Context, Result};
use std::io::Write;
use std::process::{Command, Stdio};

use crate::network::fnv1a;
use crate::options::FirewallBackend;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Active {
    Nftables,
    Iptables,
}

impl Active {
    fn label(self) -> &'static str {
        match self {
            Active::Nftables => "nftables",
            Active::Iptables => "iptables",
        }
    }
}

/// 一次网络规则配置的输入（全部来自 networks.json）。
#[derive(Debug, Clone)]
pub struct FirewallConfig<'a> {
    pub network_id: &'a str,
    /// CIDR，如 172.18.0.0/16
    pub subnet: &'a str,
    /// 宿主 bridge 设备名
    pub bridge: &'a str,
    pub masquerade: bool,
    pub icc: bool,
    pub backend: FirewallBackend,
}

/// 网络专属 nft 表名（<=16 字节，只含 [A-Za-z0-9_]）。
pub fn table_name(network_id: &str) -> String {
    let h = fnv1a(network_id.as_bytes());
    format!("md{:07x}", h & 0x0fff_ffff)
}

/// 选择实际生效的后端（auto 降级、显式 nftables 不可用则 fail-fast）。
fn choose(backend: FirewallBackend) -> Result<Active> {
    let nft_ok = nft_available();
    match backend {
        FirewallBackend::Auto => {
            if nft_ok {
                Ok(Active::Nftables)
            } else {
                Ok(Active::Iptables)
            }
        }
        FirewallBackend::Nftables => {
            if !nft_ok {
                bail!(
                    "--firewall-backend=nftables 但 nftables 不可用\
                     （找不到 nft 或内核 nf_tables 不可写）；可改用 auto / iptables"
                );
            }
            Ok(Active::Nftables)
        }
        FirewallBackend::Iptables => Ok(Active::Iptables),
    }
}

/// 幂等下发一个网络的规则。每次重建自己的表/规则，重复调用无副作用。
pub fn ensure(cfg: &FirewallConfig<'_>) -> Result<()> {
    let chosen = choose(cfg.backend)?;
    let result = match chosen {
        Active::Nftables => nft_add(cfg),
        Active::Iptables => iptables_apply(cfg, IptOp::Add),
    };
    match result {
        Ok(()) => Ok(()),
        Err(e) if chosen == Active::Nftables && cfg.backend == FirewallBackend::Auto => {
            eprintln!("miko: nftables 规则下发失败（{e:#}），降级 iptables");
            iptables_apply(cfg, IptOp::Add)
        }
        Err(e) => Err(e),
    }
}

/// 撤销一个网络的全部规则。删除网络 / prune 时调用，失败不影响主流程。
pub fn remove(cfg: &FirewallConfig<'_>) -> Result<()> {
    let _ = nft_delete(&table_name(cfg.network_id));
    iptables_apply(cfg, IptOp::Delete)
}

/// 崩溃残留兜底：不知道当时用的哪个后端时，两边都尝试撤销，失败一律忽略。
pub fn cleanup_orphan(network_id: &str, subnet: &str, bridge: &str) {
    let _ = nft_delete(&table_name(network_id));
    let cfg = FirewallConfig {
        network_id,
        subnet,
        bridge,
        masquerade: true,
        icc: true,
        backend: FirewallBackend::Auto,
    };
    let _ = iptables_apply(&cfg, IptOp::Delete);
}

/// 返回实际生效的后端标签，供 network create 打印。
pub fn active_label(backend: FirewallBackend) -> &'static str {
    choose(backend).unwrap_or(Active::Iptables).label()
}

// ---------------------------------------------------------------- nftables

fn nft_available() -> bool {
    let version = Command::new("nft")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !matches!(version, Ok(s) if s.success()) {
        return false;
    }
    let probe = format!("mdprobe{:x}", std::process::id());
    let script = format!("add table ip {probe}\ndelete table ip {probe}\n");
    run_nft(&script).is_ok()
}

/// 给 `nft -f -` 喂脚本。stdin 必须显式 drop，否则 nft 等 EOF 会卡住。
fn run_nft(script: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("启动 nft 失败")?;
    {
        let mut stdin = child.stdin.take().context("打开 nft stdin 失败")?;
        stdin
            .write_all(script.as_bytes())
            .context("写 nft 规则脚本失败")?;
    }
    let out = child.wait_with_output().context("等待 nft 失败")?;
    if !out.status.success() {
        bail!(
            "nft 执行失败: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn nft_script(table: &str, cfg: &FirewallConfig<'_>) -> String {
    let mut s = format!(
        "add table ip {t}\n\
         add chain ip {t} postrouting {{ type nat hook postrouting priority 100 ; policy accept ; }}\n\
         add chain ip {t} forward {{ type filter hook forward priority 0 ; policy accept ; }}\n",
        t = table,
    );
    if cfg.masquerade {
        s.push_str(&format!(
            "add rule ip {t} postrouting ip saddr {s} oifname != {b} masquerade\n",
            t = table,
            s = cfg.subnet,
            b = cfg.bridge,
        ));
    }
    if !cfg.icc {
        s.push_str(&format!(
            "add rule ip {t} forward iifname {b} oifname {b} drop\n",
            t = table,
            b = cfg.bridge,
        ));
    }
    s
}

fn nft_add(cfg: &FirewallConfig<'_>) -> Result<()> {
    let table = table_name(cfg.network_id);
    // 先删同名残留表（重启 / 上次崩溃），随后整表重建，保证幂等。
    let _ = nft_delete(&table);
    run_nft(&nft_script(&table, cfg))
        .with_context(|| format!("下发 nftables 网络规则（表 {table}）失败"))
}

fn nft_delete(table: &str) -> Result<()> {
    run_nft(&format!("delete table ip {table}\n"))
}

// ---------------------------------------------------------------- iptables

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IptOp {
    Add,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rule {
    Masquerade,
    IccDrop,
}

fn iptables_apply(cfg: &FirewallConfig<'_>, op: IptOp) -> Result<()> {
    let mut errors = Vec::new();
    for rule in [Rule::Masquerade, Rule::IccDrop] {
        let enabled = match rule {
            Rule::Masquerade => cfg.masquerade,
            Rule::IccDrop => !cfg.icc,
        };
        // 删除时也把两条都尝试一遍（旧规则可能来自不同配置），不存在即忽略。
        if !enabled && op == IptOp::Add {
            continue;
        }
        if let Err(e) = iptables_rule(cfg, rule, op) {
            errors.push(format!("{e:#}"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        bail!("iptables 规则管理失败: {}", errors.join("; "))
    }
}

/// 构造一条 iptables 命令，返回参数与「动词所在下标」（供 -C 检查复用）。
fn iptables_args(cfg: &FirewallConfig<'_>, rule: Rule, verb: &str) -> (Vec<String>, usize) {
    let mut args: Vec<String> = vec!["--wait".into()];
    if rule == Rule::Masquerade {
        args.extend(["-t".into(), "nat".into()]);
    }
    let verb_pos = args.len();
    args.push(verb.into());
    match rule {
        Rule::Masquerade => args.extend([
            "POSTROUTING".into(),
            "-s".into(),
            cfg.subnet.into(),
            "!".into(),
            "-o".into(),
            cfg.bridge.into(),
            "-j".into(),
            "MASQUERADE".into(),
        ]),
        Rule::IccDrop => args.extend([
            "FORWARD".into(),
            "-i".into(),
            cfg.bridge.into(),
            "-o".into(),
            cfg.bridge.into(),
            "-j".into(),
            "DROP".into(),
        ]),
    }
    (args, verb_pos)
}

fn iptables_rule(cfg: &FirewallConfig<'_>, rule: Rule, op: IptOp) -> Result<()> {
    let verb = match op {
        IptOp::Add => "-A",
        IptOp::Delete => "-D",
    };
    let (args, verb_pos) = iptables_args(cfg, rule, verb);

    if op == IptOp::Add {
        let mut check = args.clone();
        check[verb_pos] = "-C".into();
        let exists = Command::new("iptables")
            .args(&check)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if exists {
            return Ok(());
        }
    }

    let out = Command::new("iptables")
        .args(&args)
        .output()
        .context("执行 iptables 失败（出网 NAT 需要 iptables 可用）")?;
    if !out.status.success() {
        bail!(
            "iptables {verb} 失败: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> FirewallConfig<'static> {
        FirewallConfig {
            network_id: "net42",
            subnet: "172.18.0.0/16",
            bridge: "mkbr0",
            masquerade: true,
            icc: true,
            backend: FirewallBackend::Auto,
        }
    }

    #[test]
    fn table_name_is_stable_and_valid() {
        let a = table_name("net-abc");
        assert_eq!(a, table_name("net-abc"));
        assert!(a.len() <= 16);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
        assert_ne!(table_name("net-abc"), table_name("net-abd"));
    }

    #[test]
    fn nft_script_contains_expected_rules() {
        let mut c = cfg();
        let s = nft_script("md0000042", &c);
        assert!(s.contains("ip saddr 172.18.0.0/16"));
        assert!(s.contains("masquerade"));
        assert!(!s.contains("iifname")); // icc 默认开启，不加 drop
        c.icc = false;
        c.masquerade = false;
        let s2 = nft_script("md0000042", &c);
        assert!(!s2.contains("masquerade"));
        assert!(s2.contains("iifname mkbr0 oifname mkbr0 drop"));
    }

    #[test]
    fn backend_labels() {
        assert_eq!(Active::Nftables.label(), "nftables");
        assert_eq!(Active::Iptables.label(), "iptables");
        assert_eq!(FirewallBackend::Iptables.label(), "iptables");
    }
}
