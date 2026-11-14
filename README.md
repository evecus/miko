# miko

一个**独立、轻量**的 OCI 容器运行时：不调用 `docker` / `dockerd` / `containerd` / `runc`，
只依赖 Linux 内核原语（namespace / cgroup v2 / capabilities / seccomp / netlink / veth /
bridge / macvlan）。单二进制、无常驻 daemon、无 socket，容器与网络状态全部落在状态目录里。

同时支持 **x86_64 (amd64)** 与 **aarch64 (arm64)**：registry 拉取按宿主架构选择
manifest，seccomp 过滤器在两个架构上都生效，CI 对两者都做构建验证。

## 特性

| 领域 | 能力 |
|---|---|
| 镜像 | OCI image layout / `docker save` tar / Registry Distribution v2 直拉（Bearer 鉴权、manifest list 按架构下钻、digest + diff_id 校验、gzip/zstd、whiteout） |
| 镜像缓存 | content-addressable blob 库、config + 层并发下载、tag 命中零网络、本地 tar 导入指纹、`rmi` / `image prune` 后自动 GC |
| 镜像管理 | `pull` / `images` / `rmi` / `tag` / `inspect` / `image prune` / `save` / `load` |
| rootfs | 纯用户态层合并、OCI chainID 快照（reflink 优先）、`MS_PRIVATE` + `pivot_root`、bind 卷、只读根、userns owner 重映射 |
| 隔离 | pid/mnt/uts/ipc/net/user namespace、cgroup v2、capability bounding set、seccomp BPF、AppArmor、uid/gid 映射 |
| **网络** | **bridge / macvlan / none / host 四种驱动；`network create/ls/inspect/rm/prune/connect/disconnect` 管理；每网络独立 IPAM（subnet / gateway / ip-range / aux-address / --ip / --mac-address）；容器多网络接入与运行中热插拔；`--dns` / `--add-host` / `--network-alias` 名字发现** |
| 防火墙 | 网络级 MASQUERADE / ICC 规则，**nftables 优先、iptables 降级**（对齐 docker `--firewall-backend`），支持 `--internal` 与 `enable_ip_masquerade=false` |
| 端口映射 | 纯用户态 TCP/UDP 转发器（仅 bridge 网络，不需要 DNAT 权限） |
| 生命周期 | 前台 run / `-d` 双 fork supervisor / 重启策略 / ps、kill、rm、logs、**exec（含 -it）**、`system prune` |
| 状态 | `<state_root>` 下的 `state.json` + `networks.json` + flock，无 daemon |

## 编译

依赖 Rust 1.75+。TLS 使用 **rustls + 内联根证书**，不链接系统 OpenSSL。

```bash
# x86_64
cargo build --release

# aarch64（需要交叉工具链）
rustup target add aarch64-unknown-linux-gnu
sudo apt install gcc-aarch64-linux-gnu
CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
  cargo build --release --target aarch64-unknown-linux-gnu
```

产物是单个 `miko` 二进制，拷到 Armbian 等板子上即可（建议 root 运行）。

## 内核要求

```
CONFIG_NAMESPACES=y        CONFIG_USER_NS=y
CONFIG_PID_NS / MNT_NS / NET_NS / UTS_NS / IPC_NS
CONFIG_CGROUPS=y           (cgroup v2 挂载于 /sys/fs/cgroup)
CONFIG_VETH=y              CONFIG_BRIDGE=y          # bridge 驱动
CONFIG_MACVLAN=y           CONFIG_VLAN_8021Q=y     # macvlan 驱动（含 -o parent=eth0.10）
CONFIG_NETFILTER / NF_NAT / NFT_NAT / NF_TABLES   # 出网 NAT
CONFIG_SECCOMP=y           CONFIG_SECCOMP_FILTER=y
```

板端确认：

```bash
zcat /proc/config.gz | grep -E 'CONFIG_(NAMESPACES|USER_NS|CGROUP|VETH|BRIDGE|MACVLAN|SECCOMP|NF_TABLES|NFT_NAT)='
mount | grep cgroup; cat /sys/fs/cgroup/cgroup.controllers
```

---

# 网络

网络模型对齐 Docker / [libnetwork](https://github.com/moby/libnetwork)：
**Network 是独立对象，容器通过 Endpoint 接入，地址由每个网络的 IPAM 持久分配**。
没有 daemon，因此网络对象、endpoint、分配记录都存在 `<state_root>/networks.json`，
内核侧资源（bridge 设备、NAT 规则、vlan parent）由 `network create` 下发，并在
**每次容器启动时幂等重建**（libnetwork 是 daemon 启动时 restore networks）。

## 四种驱动

| 驱动 | netns | 内核设备 | 容器地址 | 出网 | 端口映射 | 典型用途 |
|---|---|---|---|---|---|---|
| `bridge`（默认） | 新建 | Linux bridge + veth pair | 网络子网自动分配 | MASQUERADE（`--internal` 关闭） | ✅ `-p` | 默认、容器互通、端口发布 |
| `macvlan` | 新建 | parent 上的 macvlan 子接口 | 物理网段内分配 | 直接走物理网络（无宿主 NAT） | ❌ | 容器像独立物理机、需要 LAN 可达 |
| `none` | 新建 | 无（仅 lo） | 无 | ❌ | ❌ | 完全离线 |
| `host` | 不新建（共享宿主） | 无 | 宿主网络栈 | ✅ | ❌ | 最高网络性能 |

预置网络：`bridge`（`mkbr0` / `172.17.0.0/16` / gw `172.17.0.1`）、`host`、`none`，
三者**不可删除**。`macvlan` 需要显式 `network create -d macvlan`。

## 管理命令

| 命令 | 说明 |
|---|---|
| `network create [OPT] NAME` | 创建 bridge / macvlan 网络，输出网络 id |
| `network ls [-q] [--filter] [--format] [--no-trunc]` | 列出网络；filter 支持 `driver=` / `name=<glob>` / `id=` / `label=k=v` |
| `network inspect NETWORK...` | JSON 详情（Name / Id / Driver / IPAM / Containers / Options / Labels，对齐 `docker network inspect`） |
| `network rm [-f] NETWORK...` | 删除网络；有 endpoint 时需 `-f` 强制断开 |
| `network prune [-f] [--filter]` | 删除所有未被使用的网络；无 `-f` 只预览；filter 支持 `label=` / `until=24h` |
| `network connect [OPT] NETWORK CONTAINER` | 把容器接入网络（**运行中热插拔**，失败则记录状态、下次启动生效） |
| `network disconnect [-f] NETWORK CONTAINER` | 断开并释放 IPAM 地址 |

`network create` 选项：

| 参数 | 说明 |
|---|---|
| `-d, --driver bridge\|macvlan` | 驱动，默认 bridge（host / none 是内置网络，不能创建） |
| `--subnet CIDR` | IPv4 子网；bridge 缺省自动从 `172.18.0.0/16` 起挑选未冲突网段，macvlan 必须显式指定 |
| `--gateway IP` | 网关；bridge 缺省取子网首地址，macvlan 缺省取宿主默认网关 |
| `--ip-range CIDR` | 限定可分配地址范围（必须落在 subnet 内） |
| `--aux-address NAME=IP` | 保留地址，IPAM 不分配（可重复） |
| `-o, --opt KEY=VALUE` | 驱动选项，见下表（未知键 fail-fast） |
| `--label KEY=VALUE` | 标签（可重复） |
| `--internal` | 禁止出网：不下发 MASQUERADE、容器不设默认路由 |
| `--attachable` | 标记可手工 connect |
| `--firewall-backend auto\|nftables\|iptables` | 该网络规则下发后端 |

驱动选项（`-o`）：

| 选项 | 驱动 | 默认 | 说明 |
|---|---|---|---|
| `com.docker.network.bridge.name` | bridge | `mkbr0` / 派生名 | 宿主 Linux bridge 设备名（≤15 字节） |
| `com.docker.network.bridge.enable_icc` | bridge | `true` | `false` 时禁止同一 bridge 内容器互通 |
| `com.docker.network.bridge.enable_ip_masquerade` | bridge | `true` | `false` 时不下发出网 NAT 规则 |
| `com.docker.network.driver.mtu` | 两者 | 1500 | 接口 MTU |
| `com.docker.network.container_iface_prefix` | 两者 | `eth` | 容器内接口名前缀（eth0 / eth1 ...） |
| `parent` | macvlan | 必填 | 宿主父接口；`eth0.10` 形式会自动创建 VLAN 子接口 |
| `macvlan_mode` | macvlan | `bridge` | `bridge` / `private` / `vepa` / `passthru` |

`run` 网络参数：

| 参数 | 说明 |
|---|---|
| `--net/--network NAME` | 接入的网络名 / id，默认 `bridge`（`veth` 仍作为 bridge 的兼容别名） |
| `--ip IP` / `--mac-address MAC` | 静态地址 / MAC，由所属网络 IPAM 校验冲突 |
| `--network-alias ALIAS` | 网络别名，写入同网络其它容器的 `/etc/hosts` |
| `-p HOST:CONTAINER[/tcp\|udp]` | 端口发布，**仅 bridge 网络** |
| `--dns IP` / `--dns-search DOMAIN` / `--dns-opt OPT` | 生成容器 `/etc/resolv.conf` |
| `--add-host HOST:IP` | 追加 `/etc/hosts` 记录 |
| `--nat` | 强制为 bridge 网络开启 MASQUERADE |
| `--firewall-backend ...` | 启动时重建网络规则所用后端 |

## 快速开始

```bash
# 默认 bridge 网络：容器拿到 172.17.0.x，可出网，可发布端口
miko run -d --name web --restart always -p 8080:80 nginx:alpine
miko ps -a

# 自定义 bridge：指定网段、地址范围、MTU，关闭容器互通
miko network create --subnet 10.20.0.0/16 --gateway 10.20.0.1 \
  --ip-range 10.20.5.0/24 \
  -o com.docker.network.bridge.name=mkbr-app \
  -o com.docker.network.driver.mtu=1400 \
  -o com.docker.network.bridge.enable_icc=false \
  --label env=prod appnet
miko network ls
miko network inspect appnet

# 静态 IP + DNS + 名字发现
miko run -d --name api --net appnet --ip 10.20.5.10 \
  --network-alias api.local --dns 1.1.1.1 --add-host db:10.20.5.20 \
  busybox:latest -- sleep infinity
miko run --net appnet busybox:latest -- sh -c 'cat /etc/hosts; ping -c1 api.local'

# host / none
miko run --net host busybox:latest -- ip addr      # 宿主网络栈
miko run --net none busybox:latest -- ip addr      # 只有 lo

# macvlan：容器直接出现在物理 LAN（parent 必须与 --subnet 同网段）
miko network create -d macvlan --subnet 192.168.1.0/24 --gateway 192.168.1.1 \
  -o parent=eth0 -o macvlan_mode=bridge lan
miko run --net lan --ip 192.168.1.210 busybox:latest -- ip addr
# VLAN 子接口：parent=eth0.10 会自动创建 eth0.10

# 多网络 + 运行中热插拔
miko network connect appnet web
miko network inspect appnet | jq '.[0].Containers'
miko network disconnect appnet web

# 清理
miko network prune -f
miko network rm appnet
miko kill web && miko rm web
miko system prune
```

## 各驱动的实现细节

### bridge

```
宿主 netns                                   容器 netns
┌────────────── mkbr0 (10.20.0.1/16) ────────┐        ┌──────────────────┐
│  mkvXXXX (veth host, master=mkbr0, up)  ◄───┼──veth──┼─► eth0           │
└────────────────────────────────────────────┘        │  10.20.5.2/16    │
   POSTROUTING: -s 10.20.0.0/16 ! -o mkbr0 MASQUERADE  │  default via gw │
   FORWARD:    -i mkbr0 -o mkbr0 DROP (icc=false)       └──────────────────┘
```

- 创建网络时：建 bridge → 配网关地址 → up → `ip_forward=1` → 下发 NAT/ICC 规则。
- 每次容器启动：`ensure_network` 幂等重建（机器重启后内核资源会自动恢复）。
- 每个 endpoint 一个 veth pair，宿主端 `IFLA_MASTER` 挂到 bridge，容器端通过
  `IFLA_NET_NS_FD` 直接落进新 netns，再由 `__init` 重命名为 `ethN` 并配 IP / 默认路由。
- 容器之间二层互通；出网走 MASQUERADE；`-p` 由宿主用户态转发器连到容器 IP。
- `--internal` 不下发 MASQUERADE，也不给容器设默认路由；`enable_icc=false` 隔离二层转发。

### macvlan

- 网络选项必须给 `parent`；`parent=eth0.10` 会自动创建 802.1Q 子接口并 up。
- 每个 endpoint 在 parent 上创建一个 macvlan 子接口（`MACVLAN_MODE_*`），
  创建时直接移入容器 netns，配 IP 与默认路由（网关通常就是物理网关）。
- `bridge`（默认）模式容器间可互通；`private` / `vepa` / `passthru` 按内核语义。
- **macvlan 的宿主与容器之间默认不互通**（内核限制），也没有宿主 NAT 与 `-p`；
  如需宿主访问容器，请在另一台物理机或用 macvlan 宿主子接口。

### none / host

- `none`：新建 netns，只把 `lo` 置 up；不创建任何设备、不分配 IP。
- `host`：不创建 netns（`clone` 不带 `CLONE_NEWNET`），共享宿主网络栈；
  `/etc/resolv.conf`、`/etc/hosts` 仍生成在容器自己的 rootfs 副本里，**不 bind 宿主文件**。
- 两者都不参与 IPAM，`--ip` / `-p` / `--nat` 都会 fail-fast。

## IPAM

每个网络一条 IPv4 子网，分配记录随网络对象持久化在 `networks.json`：

```
subnet    10.20.0.0/16
gateway   10.20.0.1           ← 不分配
aux       reserved=10.20.0.9  ← 不分配
ip-range  10.20.5.0/24        ← 只在此范围内分配，10.20.5.0 / .255 排除
容器 IP   10.20.5.1 → 10.20.5.2 ...（顺序复用已释放地址）
MAC       02:42:<IPv4 四字节>（可 --mac-address 覆盖）
```

静态 `--ip` 会校验：在 subnet 与 ip-range 内、不是网络号/广播/网关/aux、未被占用。
`rm` 容器、`network disconnect`、`system prune`（孤儿回收）都会释放地址。

## DNS 与名字发现

四种驱动都在 `pivot_root` 之前生成容器自己的 `/etc/resolv.conf` 与 `/etc/hosts`
（镜像里若是符号链接会先移除，避免写到宿主）。

- `--dns` 覆盖宿主 nameserver，`--dns-search` / `--dns-opt` 生成 `search` / `options` 行。
- `/etc/hosts` 含 localhost、容器 hostname / id / `--network-alias`、`--add-host`，
  以及**同一网络内其它容器的名字、短 id 与别名 → IP**（对齐 libnetwork 的 `etchosts`，
  不引入内嵌 DNS 服务）。`network connect` 之后新启动的容器会自动看到新增邻居。

## 防火墙后端

规则是**网络级**的（不是每容器一张表）：

1. 探测 nftables 是否真可用（`nft` 可执行 + 能创建/删除 nf_tables 表）；
2. `auto`：可用 → nftables，不可用或下发失败 → 降级 iptables；
3. 显式 `nftables` 但不可用 → 直接报错。

nftables 后端为每个网络建一张独立 `ip` 表（表名由 network id 派生），包含
`postrouting`（MASQUERADE）与 `forward`（ICC drop）两条 chain；iptables 后端用
`-C/-A/-D --wait` 幂等管理。删除网络时整表 / 整组规则撤销，不污染宿主 ruleset。
`ip_forward=1` 只设置不恢复（与 docker 一致，避免破坏宿主其它网络）。

## 多网络与热插拔

容器可接入多个网络：第一个带网关且非 `internal` 的网络提供默认路由，
接口依次为 `eth0`、`eth1`...。`network connect` 对运行中的容器会打开
`/proc/<pid>/ns/net`，在宿主 netns 建好设备后临时 `setns` 进容器 netns 配 IP/路由，
再切回宿主 netns（guard 保证异常也恢复）。热插拔失败不会丢失配置：endpoint 已写入
`networks.json`，容器重启（含 supervisor 自动重启）时由 `start_once` 与 `__init`
重新读取并补齐。

限制：`host` 网络不能与其它网络共存；`macvlan` 同一 parent 只允许一条网络
（与 libnetwork 一致）；`network connect` 不接受 host / none 网络。

## 状态目录

```
<state_root>                 # 默认 /var/lib/miko，--state-dir 覆盖
├── networks.json            # 网络对象 / endpoint / IPAM 分配（核心）
├── state.lock               # flock，包住 state.json 与 networks.json 的 read-modify-write
├── containers/<id>/{state.json, log, stop}
├── bundles/<id>/{rootfs/, config.json}      # config.json 只存 state_root + container_id
└── images/...
```

`system prune` 清理崩溃残留（cgroup / 网络设备 / 孤立 bundle / 孤儿 endpoint），
**不动网络级 NAT 规则与 bridge**（它们由 `network rm` / `network prune` 管理），
也不删 `state.json` 与日志。

---

## 架构

```
run
 ├─ image::store        tag/导入指纹命中 → 本地 blob；未命中 → pull / 本地导入
 ├─ store::materialize  diff_ids chainID 快照复用（reflink）→ bundle/rootfs
 ├─ network::create_run_endpoint   --net 解析 → networks.json 分配 endpoint / IP（失败自动回滚）
 ├─ spec::build         image config → OCI config.json（唯一配置来源，含 state_root / container_id）
 ├─ state               state.json（flock 串行化）
 └─ container::start_once
     ├─ network::attachments_for_container  每次启动读 networks.json 的全部 endpoint
     ├─ cgroup v2       限额 + attach
     ├─ clone           NEWNS/NEWPID/NEWUTS/NEWIPC（+NEWNET 非 host / +NEWUSER）
     │   └─ re-exec `__init`（PID 1）
     │       ├─ 网络：netdrv::configure_container_side（ethN / IP / MAC / MTU / 默认路由 / lo）
     │       ├─ /etc/resolv.conf / /etc/hosts（DNS、别名、同网络邻居）
     │       ├─ rootfs：挂载 → pivot_root → 只读根
     │       ├─ 安全：hostname、rlimits、capabilities、降权
     │       └─ fork 用户进程 → seccomp/AppArmor → execve
     ├─ 父进程：netdrv::ensure_network（bridge / NAT / ICC / parent 幂等重建）
     │          netdrv::join_host_side（veth / macvlan + IFLA_NET_NS_FD）
     │          用户态端口转发器、日志 tee
     └─ wait → 清理（cgroup / endpoint 宿主侧设备 / bundle）
```

`-d` 时由双 fork + setsid 的 supervisor 接管，复用同一份 `Prepared` 反复
`start_once` 实现重启策略；`ps/kill/rm/logs` 与 `network *` 直接读写状态目录，
不经过任何 daemon。

## 已知限制

- 层合并是复制式（vfs），未使用 overlayfs；磁盘占用高于 overlayfs。
- 不支持 IPv6、overlay / ipvlan 驱动、swarm scope、内嵌 DNS 服务（名字发现走 `/etc/hosts`）。
- `network connect` 的热插拔需要 root + 能 `setns` 到容器 netns；`host` 网络无法多网络共存。
- macvlan 的宿主 ↔ 容器默认不通（内核限制），且不支持 `-p` 端口发布。
- 端口映射是纯用户态转发器，性能低于内核 DNAT。
- seccomp 是「默认允许 + 显式拒绝危险 syscall」的保守子集，不是白名单式 deny-all。
- 支持 `exec`（`-it` / `-u` / `-w` / `-e` / `-d` / `--privileged`，路径对齐 runc setns）；
  没有健康检查、镜像构建；OCI runtime-spec 只实现子集，`config.json` 含 `miko` 自有扩展字段。
- 镜像管理仍是子集：无 `docker login` 凭据（仅匿名 Bearer token）、`build` /
  `commit` / `push` / `import`、`history`；`images --format` 与 `--filter` 只实现常用字段。

## 开发

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release --target aarch64-unknown-linux-gnu
```
