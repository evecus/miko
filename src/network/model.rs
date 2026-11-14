//! 网络对象模型：对齐 libnetwork 的 Network / Endpoint / IPAM / Driver 分层。
//!
//! 一个 `Network` 是一条可独立管理的网络（内置 bridge / host / none 或用户创建），
//! `Endpoint` 是容器接入该网络的接口记录，IPAM 负责从子网里分配地址。
//! 这里只做纯数据与校验，内核侧动作在 `runtime::netdrv`，持久化在 `store`。

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DRIVER_BRIDGE: &str = "bridge";
pub const DRIVER_MACVLAN: &str = "macvlan";
pub const DRIVER_NONE: &str = "none";
pub const DRIVER_HOST: &str = "host";

// 与 docker / libnetwork 一致的 driver option 名称（netlabel / bridge fromLabels）。
pub const OPT_BRIDGE_NAME: &str = "com.docker.network.bridge.name";
pub const OPT_ENABLE_ICC: &str = "com.docker.network.bridge.enable_icc";
pub const OPT_ENABLE_MASQUERADE: &str = "com.docker.network.bridge.enable_ip_masquerade";
pub const OPT_MTU: &str = "com.docker.network.driver.mtu";
pub const OPT_IFACE_PREFIX: &str = "com.docker.network.container_iface_prefix";
pub const OPT_PARENT: &str = "parent";
pub const OPT_MACVLAN_MODE: &str = "macvlan_mode";

pub const DEFAULT_BRIDGE_NAME: &str = "mkbr0";
pub const DEFAULT_BRIDGE_SUBNET: &str = "172.17.0.0/16";

/// 网络驱动类型。`none` / `host` 是内置单例驱动，不参与 IPAM。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DriverKind {
    /// Linux bridge + veth pair，容器间二层互通，宿主侧做 NAT 出网
    Bridge,
    /// macvlan 子接口直接挂在宿主物理接口上
    Macvlan,
    /// 独立 netns，只有 loopback
    None,
    /// 共享宿主 netns
    Host,
}

impl DriverKind {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            DRIVER_BRIDGE => Ok(DriverKind::Bridge),
            DRIVER_MACVLAN => Ok(DriverKind::Macvlan),
            DRIVER_NONE => Ok(DriverKind::None),
            DRIVER_HOST => Ok(DriverKind::Host),
            other => bail!("未知网络驱动 {other:?}（支持 bridge / macvlan / none / host）"),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            DriverKind::Bridge => DRIVER_BRIDGE,
            DriverKind::Macvlan => DRIVER_MACVLAN,
            DriverKind::None => DRIVER_NONE,
            DriverKind::Host => DRIVER_HOST,
        }
    }

    /// 是否需要为容器新建 network namespace。
    pub fn needs_netns(self) -> bool {
        self != DriverKind::Host
    }

    /// 是否参与 IPv4 地址分配。
    pub fn supports_ipam(self) -> bool {
        matches!(self, DriverKind::Bridge | DriverKind::Macvlan)
    }

    /// 是否支持 `-p/--publish`（docker 只允许 bridge 网络发布端口）。
    pub fn supports_publish(self) -> bool {
        self == DriverKind::Bridge
    }

    pub fn is_builtin_driver(self) -> bool {
        matches!(self, DriverKind::None | DriverKind::Host)
    }
}

/// macvlan 模式（取值来自 linux/if_link.h 的 MACVLAN_MODE_*）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MacvlanMode {
    Private = 1,
    Vepa = 2,
    Bridge = 4,
    Passthru = 8,
}

impl MacvlanMode {
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "" | "bridge" => Ok(MacvlanMode::Bridge),
            "private" => Ok(MacvlanMode::Private),
            "vepa" => Ok(MacvlanMode::Vepa),
            "passthru" | "passthrough" => Ok(MacvlanMode::Passthru),
            other => {
                bail!("非法 macvlan_mode {other:?}（支持 bridge / private / vepa / passthru）")
            }
        }
    }

    pub fn value(self) -> u32 {
        self as u32
    }

    pub fn label(self) -> &'static str {
        match self {
            MacvlanMode::Private => "private",
            MacvlanMode::Vepa => "vepa",
            MacvlanMode::Bridge => "bridge",
            MacvlanMode::Passthru => "passthru",
        }
    }
}

// ---------------------------------------------------------------- IPv4 CIDR

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Cidr {
    network: Ipv4Addr,
    prefix: u8,
}

impl Ipv4Cidr {
    pub fn new(network: Ipv4Addr, prefix: u8) -> Result<Self> {
        if prefix > 30 {
            bail!("CIDR 前缀 /{prefix} 过小（需要至少 /30 才能分配主机地址）");
        }
        let masked = u32::from(network) & mask(prefix);
        Ok(Self {
            network: Ipv4Addr::from(masked),
            prefix,
        })
    }

    pub fn parse(s: &str) -> Result<Self> {
        let (addr, plen) = s
            .trim()
            .split_once('/')
            .with_context(|| format!("CIDR 需要 A.B.C.D/N 格式，收到 {s:?}"))?;
        let ip: Ipv4Addr = addr
            .parse()
            .with_context(|| format!("CIDR 地址 {addr:?} 非法"))?;
        let prefix: u8 = plen
            .parse()
            .with_context(|| format!("CIDR 前缀 {plen:?} 非法"))?;
        Self::new(ip, prefix)
    }

    pub fn network(&self) -> Ipv4Addr {
        self.network
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.network) | !mask(self.prefix))
    }

    pub fn first_host(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.network) + 1)
    }

    pub fn last_host(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.broadcast()) - 1)
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & mask(self.prefix)) == u32::from(self.network)
    }

    pub fn overlaps(&self, other: &Ipv4Cidr) -> bool {
        self.contains(other.network) || other.contains(self.network)
    }

    /// 可分配的主机地址（排除网络号与广播地址），/16 最多 65534 个。
    pub fn hosts(&self) -> impl Iterator<Item = Ipv4Addr> {
        let start = u32::from(self.first_host());
        let end = u32::from(self.last_host());
        (start..=end).map(Ipv4Addr::from)
    }
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

// ---------------------------------------------------------------- 对象

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IpamConfig {
    #[serde(default)]
    pub driver: String,
    #[serde(default)]
    pub subnet: String,
    #[serde(default)]
    pub gateway: String,
    #[serde(default)]
    pub ip_range: Option<String>,
    #[serde(default)]
    pub aux_addresses: BTreeMap<String, String>,
}

impl IpamConfig {
    pub fn subnet_cidr(&self) -> Result<Ipv4Cidr> {
        Ipv4Cidr::parse(&self.subnet)
    }

    pub fn gateway_ip(&self) -> Result<Ipv4Addr> {
        self.gateway
            .parse()
            .with_context(|| format!("网关地址 {:?} 非法", self.gateway))
    }

    pub fn range_cidr(&self) -> Result<Ipv4Cidr> {
        match &self.ip_range {
            Some(s) => Ipv4Cidr::parse(s),
            None => self.subnet_cidr(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub id: String,
    pub container_id: String,
    pub container_name: String,
    /// host / none 网络为空串
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub mac: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    /// 宿主侧设备名（veth host 端 / macvlan 源接口），host / none 为空
    #[serde(default)]
    pub host_iface: String,
    /// 落到容器 netns 时的临时接口名，__init 里重命名为 ethN
    #[serde(default)]
    pub container_iface: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Network {
    pub id: String,
    pub name: String,
    pub driver: DriverKind,
    #[serde(default)]
    pub builtin: bool,
    #[serde(default)]
    pub internal: bool,
    #[serde(default)]
    pub attachable: bool,
    pub created_at: u64,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub options: BTreeMap<String, String>,
    #[serde(default)]
    pub ipam: IpamConfig,
    /// endpoint id -> endpoint
    #[serde(default)]
    pub endpoints: BTreeMap<String, Endpoint>,
}

impl Network {
    pub fn subnet_cidr(&self) -> Option<Ipv4Cidr> {
        if self.ipam.subnet.is_empty() {
            None
        } else {
            Ipv4Cidr::parse(&self.ipam.subnet).ok()
        }
    }

    /// 宿主侧 Linux bridge 名。用户可通过 -o 指定，否则由网络 id 派生（<=15 字节）。
    pub fn bridge_name(&self) -> String {
        if let Some(v) = self.options.get(OPT_BRIDGE_NAME) {
            if !v.is_empty() {
                return v.clone();
            }
        }
        if self.builtin && self.name == DRIVER_BRIDGE {
            return DEFAULT_BRIDGE_NAME.to_string();
        }
        let h = fnv1a(self.id.as_bytes()) & 0x00ff_ffff;
        format!("mkbr{h:06x}")
    }

    pub fn enable_icc(&self) -> bool {
        self.options
            .get(OPT_ENABLE_ICC)
            .map(|v| v == "true")
            .unwrap_or(true)
    }

    pub fn enable_masquerade(&self) -> bool {
        !self.internal
            && self
                .options
                .get(OPT_ENABLE_MASQUERADE)
                .map(|v| v == "true")
                .unwrap_or(true)
    }

    pub fn mtu(&self) -> Result<u16> {
        match self.options.get(OPT_MTU) {
            Some(v) => {
                let m: u32 = v
                    .parse()
                    .with_context(|| format!("{OPT_MTU} 需要整数，收到 {v:?}"))?;
                let m: u16 = m
                    .try_into()
                    .with_context(|| format!("{OPT_MTU} 超出范围: {m}"))?;
                if m < 68 {
                    bail!("{OPT_MTU} 不能小于 68");
                }
                Ok(m)
            }
            None => Ok(1500),
        }
    }

    pub fn iface_prefix(&self) -> &str {
        self.options
            .get(OPT_IFACE_PREFIX)
            .map(String::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or("eth")
    }

    pub fn macvlan_parent(&self) -> Option<&str> {
        self.options
            .get(OPT_PARENT)
            .map(String::as_str)
            .filter(|s| !s.is_empty())
    }

    pub fn macvlan_mode(&self) -> Result<MacvlanMode> {
        match self.options.get(OPT_MACVLAN_MODE) {
            Some(v) => MacvlanMode::parse(v),
            None => Ok(MacvlanMode::Bridge),
        }
    }

    pub fn endpoint_for_container(&self, container_id: &str) -> Option<&Endpoint> {
        self.endpoints
            .values()
            .find(|e| e.container_id == container_id)
    }

    /// 校验驱动选项：未知键 fail-fast，不静默忽略（与 docker 行为一致）。
    pub fn validate_options(&self) -> Result<()> {
        for key in self.options.keys() {
            let allowed = match self.driver {
                DriverKind::Bridge => matches!(
                    key.as_str(),
                    OPT_BRIDGE_NAME
                        | OPT_ENABLE_ICC
                        | OPT_ENABLE_MASQUERADE
                        | OPT_MTU
                        | OPT_IFACE_PREFIX
                ),
                DriverKind::Macvlan => {
                    matches!(
                        key.as_str(),
                        OPT_PARENT | OPT_MACVLAN_MODE | OPT_MTU | OPT_IFACE_PREFIX
                    )
                }
                _ => false,
            };
            if !allowed {
                bail!("驱动 {} 不支持网络选项 {key:?}", self.driver.label());
            }
        }
        for key in [OPT_ENABLE_ICC, OPT_ENABLE_MASQUERADE] {
            if let Some(v) = self.options.get(key) {
                if v != "true" && v != "false" {
                    bail!("{key} 只能是 true / false，收到 {v:?}");
                }
            }
        }
        if let Some(p) = self.options.get(OPT_IFACE_PREFIX) {
            if p.is_empty() || p.len() > 8 || !p.chars().all(|c| c.is_ascii_alphanumeric()) {
                bail!("{OPT_IFACE_PREFIX} 只能是 1..8 位字母数字，收到 {p:?}");
            }
        }
        self.mtu()?;
        match self.driver {
            DriverKind::Bridge => {
                let name = self.bridge_name();
                validate_ifname(&name)
                    .with_context(|| format!("{OPT_BRIDGE_NAME} {name:?} 非法"))?;
            }
            DriverKind::Macvlan => {
                if self.macvlan_parent().is_none() {
                    bail!("macvlan 网络必须指定 -o parent=<宿主接口>");
                }
                self.macvlan_mode()?;
            }
            _ => {}
        }
        Ok(())
    }
}

/// Linux IFNAMSIZ = 16（含结尾 NUL），接口名最长 15 字节。
pub fn validate_ifname(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 15 {
        bail!("网络设备名 {name:?} 长度需在 1..15 字节");
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        bail!("网络设备名 {name:?} 含非法字符");
    }
    Ok(())
}

// ---------------------------------------------------------------- IPAM

/// 生成一个短 hex id（网络 / endpoint 共用）。同进程内用计数器避免碰撞。
pub fn gen_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let h = fnv1a(format!("{t}-{}-{n}", std::process::id()).as_bytes());
    format!("{h:012x}")
}

pub fn fnv1a(data: &[u8]) -> u32 {
    let mut h: u32 = 2_166_136_261;
    for b in data {
        h ^= *b as u32;
        h = h.wrapping_mul(16_777_619);
    }
    h
}

pub fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        bail!("MAC 地址需要 02:42:ac:11:00:02 格式，收到 {s:?}");
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        if p.len() != 2 {
            bail!("MAC 地址段 {p:?} 非法");
        }
        out[i] = u8::from_str_radix(p, 16).with_context(|| format!("MAC 地址段 {p:?} 非法"))?;
    }
    Ok(out)
}

pub fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// docker 风格的容器 MAC：02:42 + IPv4 四字节。
pub fn mac_for_ip(ip: Ipv4Addr) -> [u8; 6] {
    let o = ip.octets();
    [0x02, 0x42, o[0], o[1], o[2], o[3]]
}

fn iface_names(endpoint_id: &str, driver: DriverKind) -> (String, String) {
    let h = fnv1a(endpoint_id.as_bytes()) & 0x0fff_ffff;
    let s = format!("{h:07x}");
    match driver {
        DriverKind::Bridge => (format!("mkv{s}"), format!("mkc{s}")),
        DriverKind::Macvlan => (format!("mkm{s}"), format!("mkm{s}")),
        _ => (String::new(), String::new()),
    }
}

/// 检查一个 IP 是否可分配给新 endpoint。
pub fn check_ip_available(net: &Network, ip: Ipv4Addr) -> Result<()> {
    let subnet = net.subnet_cidr().context("网络缺少 IPv4 subnet")?;
    let range = net.ipam.range_cidr()?;
    if !subnet.contains(ip) {
        bail!("地址 {ip} 不在子网 {subnet} 内");
    }
    if !range.contains(ip) {
        bail!("地址 {ip} 不在 --ip-range {range} 内");
    }
    if ip == subnet.network() || ip == subnet.broadcast() {
        bail!("地址 {ip} 是网络号或广播地址");
    }
    if ip == range.network() || ip == range.broadcast() {
        bail!("地址 {ip} 是分配范围的网络号或广播地址");
    }
    if net.ipam.gateway_ip().ok() == Some(ip) {
        bail!("地址 {ip} 已被网关占用");
    }
    if net
        .ipam
        .aux_addresses
        .values()
        .any(|v| v.parse::<Ipv4Addr>().ok() == Some(ip))
    {
        bail!("地址 {ip} 是保留的 aux-address");
    }
    if net
        .endpoints
        .values()
        .any(|e| e.ip.parse::<Ipv4Addr>().ok() == Some(ip))
    {
        bail!("地址 {ip} 已被本网络的其他容器占用");
    }
    Ok(())
}

/// 为一个容器分配 endpoint 并登记到网络。host / none 网络只登记逻辑 endpoint（无 IP）。
pub fn allocate_endpoint(
    net: &mut Network,
    container_id: &str,
    container_name: &str,
    requested_ip: Option<Ipv4Addr>,
    requested_mac: Option<String>,
    aliases: Vec<String>,
    now: u64,
) -> Result<Endpoint> {
    if net.endpoint_for_container(container_id).is_some() {
        bail!(
            "容器 {container_id} 已经接入网络 {}（一个容器在同一网络只能有一个 endpoint）",
            net.name
        );
    }

    let (ip, mac) = if net.driver.supports_ipam() {
        let ip = match requested_ip {
            Some(ip) => {
                check_ip_available(net, ip)?;
                ip
            }
            None => {
                let range = net.ipam.range_cidr()?;
                range
                    .hosts()
                    .find(|candidate| check_ip_available(net, *candidate).is_ok())
                    .context("子网地址已耗尽（或全部被 --ip-range / aux-address 排除）")?
            }
        };
        let mac = match requested_mac {
            Some(m) => {
                parse_mac(&m)?;
                m
            }
            None => format_mac(&mac_for_ip(ip)),
        };
        (ip.to_string(), mac)
    } else {
        if requested_ip.is_some() || requested_mac.is_some() {
            bail!("{} 网络不支持 --ip / --mac-address", net.driver.label());
        }
        (String::new(), String::new())
    };

    let id = gen_id();
    let (host_iface, container_iface) = iface_names(&id, net.driver);
    let ep = Endpoint {
        id: id.clone(),
        container_id: container_id.to_string(),
        container_name: container_name.to_string(),
        ip,
        mac,
        aliases,
        host_iface,
        container_iface,
        created_at: now,
    };
    net.endpoints.insert(id, ep.clone());
    Ok(ep)
}

/// 构造一个网络，并校验 IPAM / 驱动选项 / 名称合法性。
/// 参数较多但都是 `network create` 的显式字段，逐项列出比塞进一个 options 字典更清晰。
#[allow(clippy::too_many_arguments)]
pub fn build_network(
    name: &str,
    driver: DriverKind,
    subnet: Option<Ipv4Cidr>,
    gateway: Option<Ipv4Addr>,
    ip_range: Option<Ipv4Cidr>,
    aux_addresses: BTreeMap<String, String>,
    options: BTreeMap<String, String>,
    labels: BTreeMap<String, String>,
    internal: bool,
    now: u64,
) -> Result<Network> {
    validate_network_name(name)?;
    if driver.is_builtin_driver() {
        bail!(
            "{} 是内置单例网络，不能创建（直接使用 --net {}）",
            driver.label(),
            driver.label()
        );
    }

    let ipam = if driver.supports_ipam() {
        let subnet = subnet.context("该驱动需要 --subnet（或自动分配失败）")?;
        let gw = gateway.unwrap_or(subnet.first_host());
        if !subnet.contains(gw) {
            bail!("网关 {gw} 不在子网 {subnet} 内");
        }
        if gw == subnet.network() || gw == subnet.broadcast() {
            bail!("网关 {gw} 不能是网络号或广播地址");
        }
        if let Some(r) = ip_range {
            if !subnet.contains(r.network()) || !subnet.contains(r.broadcast()) {
                bail!("--ip-range {r} 必须完全落在子网 {subnet} 内");
            }
        }
        let mut checked_aux = BTreeMap::new();
        for (k, v) in aux_addresses {
            let ip: Ipv4Addr = v
                .parse()
                .with_context(|| format!("--aux-address {k}={v} 不是合法 IPv4 地址"))?;
            if !subnet.contains(ip) {
                bail!("--aux-address {k}={ip} 不在子网 {subnet} 内");
            }
            if ip == gw {
                bail!("--aux-address {k}={ip} 与网关冲突");
            }
            checked_aux.insert(k, ip.to_string());
        }
        IpamConfig {
            driver: "default".into(),
            subnet: subnet.to_string(),
            gateway: gw.to_string(),
            ip_range: ip_range.map(|r| r.to_string()),
            aux_addresses: checked_aux,
        }
    } else {
        IpamConfig::default()
    };

    let net = Network {
        id: gen_id(),
        name: name.to_string(),
        driver,
        builtin: false,
        internal,
        attachable: false,
        created_at: now,
        labels,
        options,
        ipam,
        endpoints: BTreeMap::new(),
    };
    net.validate_options()?;
    Ok(net)
}

pub fn validate_network_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("网络名 {name:?} 非法（只允许 [A-Za-z0-9._-]，长度 1..64）");
    }
    Ok(())
}

/// 检查新网络与已有网络是否冲突：重名、子网重叠、bridge 名重复、macvlan parent 重复。
pub fn validate_conflicts(existing: &BTreeMap<String, Network>, candidate: &Network) -> Result<()> {
    for n in existing.values() {
        if n.name == candidate.name {
            bail!("网络 {} 已存在", candidate.name);
        }
        if let (Some(a), Some(b)) = (candidate.subnet_cidr(), n.subnet_cidr()) {
            if a.overlaps(&b) {
                bail!("子网 {a} 与已有网络 {} 的 {b} 重叠", n.name);
            }
        }
        if n.driver == DriverKind::Bridge
            && candidate.driver == DriverKind::Bridge
            && n.bridge_name() == candidate.bridge_name()
        {
            bail!(
                "bridge 名 {} 已被网络 {} 占用",
                candidate.bridge_name(),
                n.name
            );
        }
        if n.driver == DriverKind::Macvlan
            && candidate.driver == DriverKind::Macvlan
            && n.macvlan_parent() == candidate.macvlan_parent()
        {
            bail!(
                "macvlan parent {} 已被网络 {} 占用（libnetwork 同样限制同一 parent 只能一个网络）",
                candidate.macvlan_parent().unwrap_or(""),
                n.name
            );
        }
    }
    Ok(())
}

/// 自动挑一个不与已有网络、宿主路由冲突的私网网段（对齐 docker 的 172.18.0.0/16 起递增）。
pub fn pick_subnet(existing: &BTreeMap<String, Network>) -> Result<Ipv4Cidr> {
    let mut occupied: Vec<Ipv4Cidr> = existing.values().filter_map(Network::subnet_cidr).collect();
    occupied.extend(host_routes());
    let mut candidates: Vec<Ipv4Cidr> = (18..=31u8)
        .map(|o| Ipv4Cidr::new(Ipv4Addr::new(172, o, 0, 0), 16).unwrap())
        .collect();
    for third in 2..=254u8 {
        candidates.push(Ipv4Cidr::new(Ipv4Addr::new(192, 168, third, 0), 24).unwrap());
    }
    candidates
        .into_iter()
        .find(|c| !occupied.iter().any(|o| o.overlaps(c)))
        .context("找不到可用的私网网段，请显式指定 --subnet")
}

/// 读 /proc/net/route，把宿主已有路由网段列出来，避免自动选网段撞车。
fn host_routes() -> Vec<Ipv4Cidr> {
    let Ok(text) = fs::read_to_string("/proc/net/route") else {
        return vec![];
    };
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 {
            continue;
        }
        let Ok(dst) = u32::from_str_radix(f[1], 16) else {
            continue;
        };
        let Ok(maskbits) = u32::from_str_radix(f[7], 16) else {
            continue;
        };
        let prefix = maskbits.swap_bytes().count_ones() as u8;
        // /0 是默认路由，不代表「占用了某个私网网段」；/31、/32 也不参与网段挑选。
        if prefix == 0 || prefix > 30 {
            continue;
        }
        let network = Ipv4Addr::from(dst.swap_bytes());
        if let Ok(cidr) = Ipv4Cidr::new(network, prefix) {
            out.push(cidr);
        }
    }
    out
}

/// 内置网络：bridge（默认）、host、none。
/// id 由名字确定性派生（而非随机）：即使只执行 `network ls` 这类只读命令、
/// networks.json 尚未落盘，跨进程看到的内置网络 id 也完全一致。
pub fn default_networks(now: u64) -> Vec<Network> {
    let builtin_id = |name: &str| format!("{:012x}", fnv1a(name.as_bytes()));
    let mut options = BTreeMap::new();
    options.insert(OPT_BRIDGE_NAME.to_string(), DEFAULT_BRIDGE_NAME.to_string());
    options.insert(OPT_ENABLE_ICC.to_string(), "true".to_string());
    options.insert(OPT_ENABLE_MASQUERADE.to_string(), "true".to_string());
    let bridge = Network {
        id: builtin_id(DRIVER_BRIDGE),
        name: DRIVER_BRIDGE.to_string(),
        driver: DriverKind::Bridge,
        builtin: true,
        internal: false,
        attachable: false,
        created_at: now,
        labels: BTreeMap::new(),
        options,
        ipam: IpamConfig {
            driver: "default".into(),
            subnet: DEFAULT_BRIDGE_SUBNET.to_string(),
            gateway: "172.17.0.1".to_string(),
            ip_range: None,
            aux_addresses: BTreeMap::new(),
        },
        endpoints: BTreeMap::new(),
    };
    let singleton = |name: &str, driver: DriverKind| Network {
        id: builtin_id(name),
        name: name.to_string(),
        driver,
        builtin: true,
        internal: false,
        attachable: false,
        created_at: now,
        labels: BTreeMap::new(),
        options: BTreeMap::new(),
        ipam: IpamConfig::default(),
        endpoints: BTreeMap::new(),
    };
    vec![
        bridge,
        singleton(DRIVER_HOST, DriverKind::Host),
        singleton(DRIVER_NONE, DriverKind::None),
    ]
}

/// 解析 `--opt KEY=VALUE` / `--label KEY=VALUE` / `--aux-address KEY=IP`。
pub fn parse_kv(items: &[String], flag: &str) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for item in items {
        let (k, v) = item
            .split_once('=')
            .with_context(|| format!("{flag} 需要 KEY=VALUE，收到 {item:?}"))?;
        if k.is_empty() || v.is_empty() {
            bail!("{flag} 的 key / value 不能为空，收到 {item:?}");
        }
        out.insert(k.to_string(), v.to_string());
    }
    Ok(out)
}

// ---------------------------------------------------------------- 运行时附件

/// 一次容器启动（或热插拔）所需的完整网络信息，父进程与 __init 共用。
#[derive(Debug, Clone)]
pub struct Attachment {
    pub network_id: String,
    pub network_name: String,
    pub driver: DriverKind,
    pub net: Network,
    pub endpoint_id: String,
    pub ip: Option<Ipv4Addr>,
    pub prefix: u8,
    pub gateway: Option<Ipv4Addr>,
    pub mac: Option<[u8; 6]>,
    pub mtu: u16,
    pub host_iface: String,
    pub container_iface: String,
    /// 容器内最终接口名（eth0 / eth1 ...）
    pub target_iface: String,
    pub default_route: bool,
    pub aliases: Vec<String>,
}

impl Attachment {
    pub fn new(net: &Network, ep: &Endpoint, index: usize, default_route: bool) -> Result<Self> {
        let ip = if ep.ip.is_empty() {
            None
        } else {
            Some(
                ep.ip
                    .parse::<Ipv4Addr>()
                    .with_context(|| format!("endpoint {} 的 IP {:?} 非法", ep.id, ep.ip))?,
            )
        };
        let mac = if ep.mac.is_empty() {
            None
        } else {
            Some(parse_mac(&ep.mac)?)
        };
        let gateway = if net.internal || ip.is_none() {
            None
        } else {
            net.ipam.gateway_ip().ok()
        };
        Ok(Self {
            network_id: net.id.clone(),
            network_name: net.name.clone(),
            driver: net.driver,
            net: net.clone(),
            endpoint_id: ep.id.clone(),
            ip,
            prefix: net.subnet_cidr().map(|c| c.prefix()).unwrap_or(24),
            gateway,
            mac,
            mtu: net.mtu()?,
            host_iface: ep.host_iface.clone(),
            container_iface: ep.container_iface.clone(),
            target_iface: format!("{}{index}", net.iface_prefix()),
            default_route: default_route && gateway.is_some(),
            aliases: ep.aliases.clone(),
        })
    }

    /// 该接口是否需要父进程创建内核设备（host / none 不需要）。
    pub fn needs_link(&self) -> bool {
        !self.host_iface.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_network(subnet: &str) -> Network {
        let mut options = BTreeMap::new();
        options.insert(OPT_ENABLE_ICC.to_string(), "true".to_string());
        options.insert(OPT_ENABLE_MASQUERADE.to_string(), "true".to_string());
        Network {
            id: "net000000001".into(),
            name: "test".into(),
            driver: DriverKind::Bridge,
            builtin: false,
            internal: false,
            attachable: false,
            created_at: 1,
            labels: BTreeMap::new(),
            options,
            ipam: IpamConfig {
                driver: "default".into(),
                subnet: subnet.into(),
                gateway: "10.0.0.1".into(),
                ip_range: None,
                aux_addresses: BTreeMap::new(),
            },
            endpoints: BTreeMap::new(),
        }
    }

    #[test]
    fn cidr_parse_contains_and_hosts() {
        let c = Ipv4Cidr::parse("192.168.10.128/25").unwrap();
        assert_eq!(c.to_string(), "192.168.10.128/25");
        assert_eq!(c.network().to_string(), "192.168.10.128");
        assert_eq!(c.broadcast().to_string(), "192.168.10.255");
        assert_eq!(c.first_host().to_string(), "192.168.10.129");
        assert_eq!(c.last_host().to_string(), "192.168.10.254");
        assert!(c.contains("192.168.10.200".parse().unwrap()));
        assert!(!c.contains("192.168.10.1".parse().unwrap()));
        assert!(Ipv4Cidr::parse("10.0.0.0/8")
            .unwrap()
            .overlaps(&Ipv4Cidr::parse("10.1.0.0/16").unwrap()));
        assert!(Ipv4Cidr::parse("10.0.0.0/31").is_err());
        assert!(Ipv4Cidr::parse("nonsense").is_err());
    }

    #[test]
    fn ipam_skips_gateway_and_allocates_sequentially() {
        let mut net = test_network("10.0.0.0/24");
        let a = allocate_endpoint(&mut net, "c1", "c1", None, None, vec![], 1).unwrap();
        assert_eq!(a.ip, "10.0.0.2");
        assert_eq!(a.mac, "02:42:0a:00:00:02");
        let b = allocate_endpoint(&mut net, "c2", "c2", None, None, vec![], 2).unwrap();
        assert_eq!(b.ip, "10.0.0.3");
        assert_ne!(a.host_iface, b.host_iface);
        assert!(check_ip_available(&net, "10.0.0.1".parse().unwrap()).is_err());
        assert!(check_ip_available(&net, "10.0.0.2".parse().unwrap()).is_err());
        assert!(check_ip_available(&net, "10.0.0.255".parse().unwrap()).is_err());
        assert!(check_ip_available(&net, "10.0.1.2".parse().unwrap()).is_err());
        // 显式 IP 可用，但重复分配同一个 IP 必须失败
        let c = allocate_endpoint(
            &mut net,
            "c3",
            "c3",
            Some("10.0.0.42".parse().unwrap()),
            None,
            vec![],
            3,
        )
        .unwrap();
        assert_eq!(c.ip, "10.0.0.42");
        assert!(allocate_endpoint(
            &mut net,
            "c4",
            "c4",
            Some("10.0.0.42".parse().unwrap()),
            None,
            vec![],
            4,
        )
        .is_err());
        // 释放后可复用
        net.endpoints.remove(&a.id);
        let d = allocate_endpoint(&mut net, "c5", "c5", None, None, vec![], 5).unwrap();
        assert_eq!(d.ip, "10.0.0.2");
    }

    #[test]
    fn ip_range_and_aux_address_are_respected() {
        let mut net = test_network("10.0.0.0/24");
        net.ipam.ip_range = Some("10.0.0.128/25".into());
        net.ipam
            .aux_addresses
            .insert("reserved".into(), "10.0.0.130".into());
        let a = allocate_endpoint(&mut net, "c1", "c1", None, None, vec![], 1).unwrap();
        assert_eq!(a.ip, "10.0.0.129"); // 128 是 range 网络号，130 被 aux 保留
        assert!(allocate_endpoint(
            &mut net,
            "c2",
            "c2",
            Some("10.0.0.10".parse().unwrap()),
            None,
            vec![],
            2,
        )
        .is_err()); // 不在 ip-range 内
    }

    #[test]
    fn host_and_none_have_no_ipam() {
        for driver in [DriverKind::Host, DriverKind::None] {
            let mut net = test_network("");
            net.driver = driver;
            net.ipam = IpamConfig::default();
            let ep = allocate_endpoint(&mut net, "c1", "c1", None, None, vec![], 1).unwrap();
            assert!(ep.ip.is_empty());
            assert!(ep.host_iface.is_empty());
            assert!(allocate_endpoint(
                &mut net,
                "c2",
                "c2",
                Some("1.2.3.4".parse().unwrap()),
                None,
                vec![],
                2,
            )
            .is_err());
        }
    }

    #[test]
    fn network_validation() {
        let mut net = test_network("10.0.0.0/24");
        net.validate_options().unwrap();
        net.options.insert("unknown".into(), "x".into());
        assert!(net.validate_options().is_err());
        net.options.remove("unknown");
        net.options.insert(OPT_ENABLE_ICC.into(), "yes".into());
        assert!(net.validate_options().is_err());
        net.options.insert(OPT_ENABLE_ICC.into(), "false".into());
        assert!(!net.enable_icc());

        let mut mv = test_network("192.168.1.0/24");
        mv.driver = DriverKind::Macvlan;
        mv.options.clear(); // bridge 专属选项在 macvlan 网络上必须被拒绝
        assert!(mv.validate_options().is_err()); // 缺 parent
        mv.options.insert(OPT_PARENT.into(), "eth0".into());
        mv.options.insert(OPT_MACVLAN_MODE.into(), "vepa".into());
        mv.validate_options().unwrap();
        assert_eq!(mv.macvlan_mode().unwrap(), MacvlanMode::Vepa);
        mv.options.insert(OPT_MACVLAN_MODE.into(), "bogus".into());
        assert!(mv.validate_options().is_err());
    }

    #[test]
    fn conflicts_cover_names_subnets_bridge_and_parent() {
        let mut a = test_network("172.20.0.0/16");
        a.name = "alpha".into();
        let mut existing = BTreeMap::new();
        existing.insert(a.id.clone(), a);
        let mut b = test_network("172.20.5.0/24");
        b.id = "net000000002".into(); // 不同网络 id -> 派生 bridge 名也不同
        b.name = "alpha".into();
        assert!(validate_conflicts(&existing, &b).is_err());
        b.name = "beta".into();
        assert!(validate_conflicts(&existing, &b).is_err()); // 子网重叠
        b.ipam.subnet = "172.21.0.0/16".into();
        assert!(validate_conflicts(&existing, &b).is_ok());
    }

    #[test]
    fn mac_parsing_and_generation() {
        let m = mac_for_ip("172.17.0.7".parse().unwrap());
        assert_eq!(format_mac(&m), "02:42:ac:11:00:07");
        assert_eq!(parse_mac("02:42:ac:11:00:07").unwrap(), m);
        assert!(parse_mac("zz:42:ac:11:00:07").is_err());
        assert!(parse_mac("02:42:ac:11:00").is_err());
    }

    #[test]
    fn ifnames_fit_kernel_limit() {
        for driver in [DriverKind::Bridge, DriverKind::Macvlan] {
            let (host, peer) = iface_names("ep-abcdef", driver);
            assert!(host.len() <= 15 && peer.len() <= 15);
        }
        assert!(validate_ifname("mkbr0").is_ok());
        assert!(validate_ifname("a-very-long-bridge-name").is_err());
        assert!(validate_ifname("bad name").is_err());
    }
}
