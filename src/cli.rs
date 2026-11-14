use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// 顶层参数（对所有子命令生效）
#[derive(Parser, Debug)]
#[command(
    name = "miko",
    version = "0.1.0",
    about = "独立 OCI 容器运行时：不调用 docker / dockerd / containerd / runc"
)]
pub struct Cli {
    /// 容器状态目录（默认 /var/lib/miko）
    #[arg(long, global = true, value_name = "DIR")]
    pub state_dir: Option<PathBuf>,

    /// 拉取镜像时的并发下载数（默认 4）
    #[arg(long, global = true, value_name = "N", default_value_t = 4)]
    pub concurrency: usize,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// 从 OCI layout / docker save tar / registry 引用运行一个容器（自动使用本地镜像缓存）
    Run(Box<RunArgs>),

    /// 拉取镜像到本地缓存（内容寻址，层并发下载）
    Pull(PullArgs),

    /// 列出本地缓存的镜像
    Images(ImagesArgs),

    /// 删除本地镜像（并回收无人引用的 blob 与 rootfs 快照）
    Rmi(RmiArgs),

    /// 给已有镜像加一个 tag
    Tag(TagArgs),

    /// 查看镜像的完整元数据（JSON）
    Inspect(InspectArgs),

    /// 把本地镜像导出为 docker save 兼容 tar
    Save(SaveArgs),

    /// 从 docker save tar / OCI layout 导入镜像（可指定 tag）
    Load(LoadArgs),

    /// 镜像子命令（prune）
    Image(ImageArgs),

    /// 管理网络（create / ls / inspect / rm / prune / connect / disconnect）
    Network(NetworkArgs),

    /// 列出容器
    Ps(PsArgs),

    /// 向容器发送信号
    Kill(KillArgs),

    /// 优雅停止容器（先 StopSignal，超时后 SIGKILL；对齐 docker stop）
    Stop(StopArgs),

    /// 删除已停止的容器
    Rm(RmArgs),

    /// 查看容器日志
    Logs(LogsArgs),

    /// 在运行中的容器里执行新进程（对齐 docker exec / runc exec）
    Exec(ExecArgs),

    /// 清理崩溃残留的内核资源
    System(SystemArgs),

    /// 内部入口：在新建的 namespace 里作为容器 PID 1 运行
    #[command(name = "__init", hide = true)]
    Init(InitArgs),
}

#[derive(clap::Args, Debug, Clone)]
#[command(about = "从镜像运行容器")]
pub struct RunArgs {
    /// OCI image layout 目录 / docker save tar / registry 引用（如 busybox:latest）
    pub image: String,

    /// 容器名（缺省为自动生成的短 id）
    #[arg(long)]
    pub name: Option<String>,

    /// 容器内主机名（缺省取容器 id）
    #[arg(long)]
    pub hostname: Option<String>,

    /// 内存上限：256m / 1g / 1073741824（显式给出才创建 cgroup）
    #[arg(long)]
    pub memory: Option<String>,

    /// CPU 核数上限，如 1.5（显式给出才创建 cgroup）
    #[arg(long)]
    pub cpus: Option<f64>,

    /// 进程数上限（显式给出才创建 cgroup）
    #[arg(long)]
    pub pids: Option<u32>,

    /// 即使给了资源限额也不创建 cgroup
    #[arg(long)]
    pub no_cgroup: bool,

    /// 追加或覆盖环境变量 KEY=VALUE
    #[arg(short = 'e', long = "env")]
    pub envs: Vec<String>,

    /// 覆盖工作目录
    #[arg(short = 'w', long = "workdir")]
    pub workdir: Option<String>,

    /// 覆盖用户：uid[:gid] 或用户名（用户名查 rootfs 内的 /etc/passwd）
    #[arg(short = 'u', long = "user")]
    pub user: Option<String>,

    /// 不裁剪 capability bounding set（缺省按 docker 默认 14 项裁剪）
    #[arg(long)]
    pub no_cap_drop: bool,

    /// 只读根文件系统
    #[arg(long)]
    pub readonly_rootfs: bool,

    /// bundle 目录：rootfs 与 config.json 的落盘位置
    #[arg(long)]
    pub bundle_dir: Option<PathBuf>,

    /// 退出后保留 bundle（缺省清理）
    #[arg(long)]
    pub keep: bool,

    /// registry 使用 http（默认 https）
    #[arg(long)]
    pub insecure_registry: bool,

    /// 忽略本地缓存，强制重新向 registry 核对 tag（blob 命中内容寻址后仍会跳过下载）
    #[arg(long)]
    pub pull: bool,

    /// 目标平台 linux/amd64 | linux/arm64（缺省按宿主架构；用于 registry manifest 选择，不做跨架构模拟）
    #[arg(long, value_name = "OS/ARCH")]
    pub platform: Option<String>,

    /// 防火墙后端：auto（nftables 可用则优先，否则降级 iptables，默认） / nftables / iptables
    #[arg(long, value_name = "BACKEND", default_value = "auto")]
    pub firewall_backend: String,

    // ------------------------------------------------------------ 生命周期
    /// 后台运行（脱离终端，由 supervisor 接管）
    #[arg(short = 'd', long)]
    pub detach: bool,

    /// 重启策略：no / on-failure[:N] / always / unless-stopped
    #[arg(long, default_value = "no")]
    pub restart: String,

    // ------------------------------------------------------------ 存储与网络
    /// 绑定挂载 HOST:CONTAINER[:ro]（可重复）
    #[arg(short = 'v', long = "volume")]
    pub volumes: Vec<String>,

    /// 端口映射 [HOST_IP:]HOST_PORT:CONTAINER_PORT[/tcp]（可重复，仅 bridge 网络）
    #[arg(short = 'p', long = "publish")]
    pub publish: Vec<String>,

    /// 接入的网络：bridge（默认） / host / none / macvlan 网络名 / 用户网络名 / 网络 id
    #[arg(
        long,
        alias = "network",
        default_value = "bridge",
        value_name = "NETWORK"
    )]
    pub net: String,

    /// bridge 网络强制开启 MASQUERADE 出网（覆盖网络的 enable_ip_masquerade=false）
    #[arg(long)]
    pub nat: bool,

    /// 指定容器 IPv4 地址（必须在网络 subnet / ip-range 内）
    #[arg(long, value_name = "IP")]
    pub ip: Option<String>,

    /// 指定容器网卡 MAC 地址
    #[arg(long = "mac-address", value_name = "MAC")]
    pub mac_address: Option<String>,

    /// 网络别名，写入同网络其它容器的 /etc/hosts（可重复）
    #[arg(long = "network-alias", value_name = "ALIAS")]
    pub network_alias: Vec<String>,

    /// 容器 DNS 服务器（可重复；默认取宿主 /etc/resolv.conf）
    #[arg(long = "dns", value_name = "IP")]
    pub dns: Vec<String>,

    /// DNS 搜索域（可重复）
    #[arg(long = "dns-search", value_name = "DOMAIN")]
    pub dns_search: Vec<String>,

    /// /etc/resolv.conf 的 options 行（可重复）
    #[arg(long = "dns-opt", value_name = "OPT")]
    pub dns_opt: Vec<String>,

    /// 追加 /etc/hosts 记录 HOST:IP（可重复）
    #[arg(long = "add-host", value_name = "HOST:IP")]
    pub add_host: Vec<String>,

    // ------------------------------------------------------------ 安全
    /// 启用 user namespace
    #[arg(long)]
    pub userns: bool,

    /// userns 根切换：pivot（标准，真实内核）/ chroot（嵌套 userns 兼容，打印告警）
    #[arg(long, default_value = "pivot", value_name = "MODE")]
    pub userns_root: String,

    /// uid 映射 container:host:size（默认 0:0:1，仅 --userns 时有效）
    #[arg(long, value_name = "C:H:S")]
    pub uid_map: Option<String>,

    /// gid 映射 container:host:size（默认 0:0:1，仅 --userns 时有效）
    #[arg(long, value_name = "C:H:S")]
    pub gid_map: Option<String>,

    /// 安全选项：seccomp=default|unconfined、apparmor=<profile>|unconfined
    #[arg(long = "security-opt", value_name = "KEY=VALUE")]
    pub security_opt: Vec<String>,

    /// 覆盖镜像 CMD（放在 `--` 之后）
    #[arg(last = true)]
    pub command: Vec<String>,
}

#[derive(clap::Args, Debug)]
pub struct PullArgs {
    /// registry 引用，如 busybox:latest / ghcr.io/org/app:v1
    pub image: String,

    /// registry 使用 http（默认 https）
    #[arg(long)]
    pub insecure_registry: bool,

    /// 目标平台 linux/amd64 | linux/arm64（缺省按宿主架构）
    #[arg(long, value_name = "OS/ARCH")]
    pub platform: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct ImagesArgs {
    /// 只输出 image id
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// 显示 manifest digest 列
    #[arg(long)]
    pub digests: bool,

    /// 不截断 image id / digest
    #[arg(long)]
    pub no_trunc: bool,

    /// 过滤条件（可重复）：dangling=true|false、reference=<glob>、
    /// before=<ref|id>、since=<ref|id>、label=<key>=<value>、id=<prefix>
    #[arg(long = "filter", value_name = "KEY=VALUE")]
    pub filters: Vec<String>,

    /// 自定义输出模板，如 '{{.Repository}}:{{.Tag}} {{.ID}}'；
    /// 支持 {{json .}} 输出整行 JSON
    #[arg(long, value_name = "TEMPLATE")]
    pub format: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct RmiArgs {
    /// 镜像引用或 image id 前缀（可多个）
    #[arg(required = true)]
    pub images: Vec<String>,

    /// 镜像被多个 tag 引用时强制删除
    #[arg(short = 'f', long)]
    pub force: bool,
}

#[derive(clap::Args, Debug)]
pub struct TagArgs {
    /// 已有镜像：tag 引用或 image id 前缀
    pub source: String,

    /// 目标 tag，如 myreg.local/busybox:stable
    pub target: String,
}

#[derive(clap::Args, Debug)]
pub struct InspectArgs {
    /// 镜像引用或 image id 前缀（可多个）
    #[arg(required = true)]
    pub images: Vec<String>,
}

#[derive(clap::Args, Debug)]
pub struct SaveArgs {
    /// 要导出的镜像引用或 image id 前缀（可多个，共享层只写一份）
    #[arg(required = true)]
    pub images: Vec<String>,

    /// 输出 tar 文件；省略则写 stdout（日志走 stderr）
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    pub output: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub struct LoadArgs {
    /// 输入 tar / OCI layout 目录；省略或 '-' 表示从 stdin 读
    #[arg(short = 'i', long = "input", value_name = "FILE")]
    pub input: Option<PathBuf>,

    /// 额外给导入的镜像打 tag（可重复）；不指定则沿用 tar 内的 RepoTags，
    /// 两者都没有时镜像保持无 tag（dangling，可用 image prune 回收）
    #[arg(long = "tag", value_name = "REF")]
    pub tags: Vec<String>,
}

#[derive(clap::Args, Debug)]
pub struct ImageArgs {
    #[command(subcommand)]
    pub command: ImageCommand,
}

#[derive(clap::Subcommand, Debug)]
pub enum ImageCommand {
    /// 删除无 tag 镜像（默认）或全部未被容器使用的镜像（-a），并执行 GC
    Prune(PruneArgs),
}

#[derive(clap::Args, Debug)]
pub struct PruneArgs {
    /// 删除所有未被容器使用的镜像，而不只是 dangling
    #[arg(short = 'a', long)]
    pub all: bool,

    /// 跳过确认直接删除（非交互环境下必须给）
    #[arg(short = 'f', long)]
    pub force: bool,

    /// 过滤条件（可重复）：until=<duration|RFC3339>、label=<key>=<value>
    #[arg(long = "filter", value_name = "KEY=VALUE")]
    pub filters: Vec<String>,
}

#[derive(clap::Args, Debug)]
pub struct PsArgs {
    /// 显示已停止的容器
    #[arg(short = 'a', long)]
    pub all: bool,
}

#[derive(clap::Args, Debug)]
pub struct KillArgs {
    /// 容器 id 或名称
    pub id: String,

    /// 信号名或编号（缺省用镜像 StopSignal，镜像未声明则 TERM）
    #[arg(short = 's', long = "signal")]
    pub signal: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct StopArgs {
    /// 容器 id 或名称（可多个）
    #[arg(required = true)]
    pub ids: Vec<String>,

    /// 等待优雅退出的秒数，超时后 SIGKILL（默认 10，对齐 docker stop）
    #[arg(short = 't', long = "time", default_value_t = 10)]
    pub time: u64,
}

#[derive(clap::Args, Debug)]
pub struct RmArgs {
    /// 容器 id 或名称（可多个）
    #[arg(required = true)]
    pub ids: Vec<String>,

    /// 先 kill 再删除
    #[arg(short = 'f', long)]
    pub force: bool,
}

#[derive(clap::Args, Debug)]
pub struct LogsArgs {
    /// 容器 id 或名称
    pub id: String,
}

#[derive(clap::Args, Debug)]
#[command(about = "在运行中的容器里执行命令（setns 进入全部 namespace）")]
pub struct ExecArgs {
    /// 容器 id 或名称
    pub container: String,

    /// 保持 STDIN 打开
    #[arg(short = 'i', long)]
    pub interactive: bool,

    /// 分配伪终端
    #[arg(short = 't', long)]
    pub tty: bool,

    /// 后台运行（打印宿主 pid 后立即返回）
    #[arg(short = 'd', long)]
    pub detach: bool,

    /// 容器内用户 uid[:gid] 或用户名（查容器 /etc/passwd）
    #[arg(short = 'u', long = "user", value_name = "USER")]
    pub user: Option<String>,

    /// 工作目录（容器内路径）
    #[arg(short = 'w', long = "workdir", value_name = "DIR")]
    pub workdir: Option<String>,

    /// 环境变量 KEY=VALUE（可重复；覆盖容器默认）
    #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
    pub envs: Vec<String>,

    /// 以特权模式执行（尽力提升 capability）
    #[arg(long)]
    pub privileged: bool,

    /// 要执行的命令及其参数（放在容器名之后）
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

#[derive(clap::Args, Debug)]
pub struct SystemArgs {
    #[command(subcommand)]
    pub command: SystemCommand,
}

#[derive(clap::Subcommand, Debug)]
pub enum SystemCommand {
    /// 清理已停止容器残留的 cgroup / 网络设备 / 孤立 bundle / 孤儿 endpoint
    Prune,
}

// ---------------------------------------------------------------- 网络管理

#[derive(clap::Args, Debug)]
pub struct NetworkArgs {
    #[command(subcommand)]
    pub command: NetworkCommand,
}

#[derive(clap::Subcommand, Debug)]
pub enum NetworkCommand {
    /// 创建一条网络（bridge / macvlan）
    Create(NetworkCreateArgs),
    /// 列出网络
    Ls(NetworkLsArgs),
    /// 查看网络详情（JSON，字段对齐 docker network inspect）
    Inspect(NetworkInspectArgs),
    /// 删除网络（内置网络不可删）
    Rm(NetworkRmArgs),
    /// 删除所有未被使用的网络
    Prune(NetworkPruneArgs),
    /// 把容器接入网络（运行中容器热插拔）
    Connect(NetworkConnectArgs),
    /// 把容器从网络断开
    Disconnect(NetworkDisconnectArgs),
}

#[derive(clap::Args, Debug)]
pub struct NetworkCreateArgs {
    /// 网络名
    pub name: String,

    /// 驱动：bridge（默认） / macvlan
    #[arg(short = 'd', long, default_value = "bridge", value_name = "DRIVER")]
    pub driver: String,

    /// IPv4 子网 CIDR（bridge 缺省自动从 172.18.0.0/16 起挑选；macvlan 必须显式指定）
    #[arg(long, value_name = "CIDR")]
    pub subnet: Option<String>,

    /// 网关 IPv4（缺省取子网第一个可用地址；macvlan 缺省取宿主默认网关）
    #[arg(long, value_name = "IP")]
    pub gateway: Option<String>,

    /// 只允许从这个子范围分配容器 IP
    #[arg(long = "ip-range", value_name = "CIDR")]
    pub ip_range: Option<String>,

    /// 保留地址 NAME=IP（可重复），IPAM 不会分配它
    #[arg(long = "aux-address", value_name = "NAME=IP")]
    pub aux_addresses: Vec<String>,

    /// 驱动选项 KEY=VALUE（可重复）：
    /// bridge: com.docker.network.bridge.name / .enable_icc / .enable_ip_masquerade /
    /// com.docker.network.driver.mtu / com.docker.network.container_iface_prefix；
    /// macvlan: parent / macvlan_mode
    #[arg(short = 'o', long = "opt", value_name = "KEY=VALUE")]
    pub opts: Vec<String>,

    /// 标签 KEY=VALUE（可重复）
    #[arg(long = "label", value_name = "KEY=VALUE")]
    pub labels: Vec<String>,

    /// 禁止容器出网（不下发 MASQUERADE，也不设默认路由）
    #[arg(long)]
    pub internal: bool,

    /// 允许手工 connect（记录标记，本地网络默认即可连接）
    #[arg(long)]
    pub attachable: bool,

    /// 该网络 NAT / ICC 规则的后端：auto / nftables / iptables
    #[arg(long, default_value = "auto", value_name = "BACKEND")]
    pub firewall_backend: String,
}

#[derive(clap::Args, Debug)]
pub struct NetworkLsArgs {
    /// 只输出网络 id
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// 过滤条件（可重复）：driver=、name=<glob>、id=<prefix>、label=k=v
    #[arg(long = "filter", value_name = "KEY=VALUE")]
    pub filters: Vec<String>,

    /// 自定义输出模板，支持 {{.ID}} {{.Name}} {{.Driver}} {{.Scope}}
    /// {{.Subnet}} {{.Gateway}} {{.Containers}} {{json .}}
    #[arg(long, value_name = "TEMPLATE")]
    pub format: Option<String>,

    /// 不截断网络 id
    #[arg(long)]
    pub no_trunc: bool,
}

#[derive(clap::Args, Debug)]
pub struct NetworkInspectArgs {
    /// 网络名或 id（可多个）
    #[arg(required = true)]
    pub networks: Vec<String>,
}

#[derive(clap::Args, Debug)]
pub struct NetworkRmArgs {
    /// 网络名或 id（可多个）
    #[arg(required = true)]
    pub networks: Vec<String>,

    /// 强制断开仍在使用的 endpoint
    #[arg(short = 'f', long)]
    pub force: bool,
}

#[derive(clap::Args, Debug)]
pub struct NetworkPruneArgs {
    /// 跳过确认直接删除（非交互环境下必须给）
    #[arg(short = 'f', long)]
    pub force: bool,

    /// 过滤条件（可重复）：label=k=v、until=24h / 7d
    #[arg(long = "filter", value_name = "KEY=VALUE")]
    pub filters: Vec<String>,
}

#[derive(clap::Args, Debug)]
pub struct NetworkConnectArgs {
    /// 网络名或 id
    pub network: String,

    /// 容器 id 或名称
    pub container: String,

    /// 指定 IPv4 地址
    #[arg(long, value_name = "IP")]
    pub ip: Option<String>,

    /// 指定 MAC 地址
    #[arg(long = "mac-address", value_name = "MAC")]
    pub mac_address: Option<String>,

    /// 网络别名（可重复）
    #[arg(long = "alias", value_name = "ALIAS")]
    pub aliases: Vec<String>,

    /// 热接入时下发网络规则使用的后端
    #[arg(long, default_value = "auto", value_name = "BACKEND")]
    pub firewall_backend: String,
}

#[derive(clap::Args, Debug)]
pub struct NetworkDisconnectArgs {
    /// 网络名或 id
    pub network: String,

    /// 容器 id 或名称
    pub container: String,

    /// 容器未接入该网络时不报错
    #[arg(short = 'f', long)]
    pub force: bool,
}

#[derive(clap::Args, Debug)]
pub struct InitArgs {
    /// bundle 目录（宿主绝对路径）
    #[arg(long)]
    pub bundle: PathBuf,

    /// 与父进程同步的 pipe 读端 fd
    #[arg(long)]
    pub sync_fd: i32,

    /// userns 模式：标准文件系统已由父进程预挂，__init 跳过挂载直接 pivot
    #[arg(long)]
    pub pre_mounted: bool,
}
