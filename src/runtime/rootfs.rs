//! 挂载与根切换：MS_PRIVATE -> 在 rootfs 内挂标准文件系统 -> MS_REC bind -> pivot_root。
//!
//! `mount_all` 被两处复用：
//! - 常规路径：__init 在自己的 mount ns 里挂载，退出时随 ns 一起销毁；
//! - userns 路径：由父进程（初始 userns 权限）预挂，返回挂载点列表供事后清理。
//!   原因是受限内核/嵌套容器下，子 userns 内挂 procfs/sysfs 会 EPERM。

use anyhow::{Context, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::unistd::{chdir, chroot, pivot_root};
use std::fs::{self, File};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use crate::spec::OciSpec;

const PIVOT_DIR: &str = ".miko_pivot";

pub fn setup(bundle: &Path, spec: &OciSpec, pre_mounted: bool) -> Result<()> {
    let rootfs = bundle.join(&spec.root.path);

    if !pre_mounted {
        // 1. 切断与宿主挂载树的传播
        mount(
            None::<&Path>,
            Path::new("/"),
            None::<&Path>,
            MsFlags::MS_REC | MsFlags::MS_PRIVATE,
            None::<&Path>,
        )
        .context("mount --make-rprivate / 失败")?;
        // 2. 标准文件系统 / volume / 设备 / rootfs bind
        mount_all(&rootfs, spec, true)?;
    }

    if pre_mounted {
        // 嵌套 userns 内核：子 userns 内既不能挂 procfs，也不能对含继承挂载的 rootfs
        // 做 pivot_root（实测 EINVAL）。此处父进程已预挂好，只做 chroot。
        if !spec.miko.userns_chroot {
            anyhow::bail!("内部不一致：pre_mounted 但未标记 userns_chroot");
        }
        if spec.root.readonly {
            anyhow::bail!("--readonly-rootfs 在 --userns-root chroot 下不支持（chroot 后 remount / 会影响宿主）");
        }
        chroot(&rootfs).context(
            "chroot 失败：非恒等 uid/gid 映射会失去 initial userns 的 CAP_SYS_CHROOT。\
             嵌套 userns 兼容模式只支持 0:0:1；其他映射请用 --userns-root pivot（需非嵌套内核）",
        )?;
        chdir(Path::new("/"))?;
        setup_dev_symlinks()?;
        return Ok(());
    }

    // 3. pivot_root(".", ".miko_pivot")：先 chdir 进 rootfs，用相对路径最稳
    let pivot_dir = rootfs.join(PIVOT_DIR);
    if pivot_dir.exists() {
        fs::remove_dir_all(&pivot_dir)?;
    }
    fs::create_dir(&pivot_dir)?;
    chdir(&rootfs)?;
    pivot_root(Path::new("."), Path::new(PIVOT_DIR)).context("pivot_root 失败")?;
    chdir(Path::new("/"))?;

    // 4. 卸载旧根
    let old = Path::new("/").join(PIVOT_DIR);
    umount2(&old, MntFlags::MNT_DETACH).context("卸载旧根失败")?;
    fs::remove_dir(&old).ok();

    // 5. 补 /dev 下的常用符号链接
    setup_dev_symlinks()?;

    // 6. 只读根（放在最后，不影响已挂载的子文件系统）
    if spec.root.readonly {
        mount(
            None::<&Path>,
            Path::new("/"),
            None::<&Path>,
            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
            None::<&Path>,
        )
        .context("remount 只读根失败")?;
    }
    Ok(())
}

/// 把标准文件系统、volume、设备节点挂到 `rootfs/<dest>`（宿主可达路径），
/// 最后把 rootfs 自身做成挂载点。返回所有挂载点，供父进程预挂场景清理。
pub fn mount_all(rootfs: &Path, spec: &OciSpec, root_bind: bool) -> Result<Vec<PathBuf>> {
    let mut points: Vec<PathBuf> = Vec::new();

    // /etc/resolv.conf 与 /etc/hosts 由 runtime::network 按网络配置生成到 rootfs 副本，
    // 四种驱动都不再 bind 宿主文件（避免容器改动宿主 /etc）。
    for m in &spec.mounts {
        let dest = rootfs.join(m.destination.trim_start_matches('/'));
        if m.typ == "bind" {
            bind_volume(Path::new(&m.source), &dest, &m.options)
                .with_context(|| format!("绑定 {} -> {} 失败", m.source, m.destination))?;
        } else {
            fs::create_dir_all(&dest)
                .with_context(|| format!("创建挂载点 {} 失败", m.destination))?;
            let (flags, data) = mount_flags(&m.options);
            let data_opt = (!data.is_empty()).then_some(data.as_str());
            mount(
                Some(m.source.as_str()),
                &dest,
                Some(m.typ.as_str()),
                flags,
                data_opt,
            )
            .with_context(|| {
                let hint = if spec.miko.userns && (m.typ == "proc" || m.typ == "sysfs") {
                    "（当前内核可能处于嵌套 userns，禁止在子 userns 内挂 procfs/sysfs；可显式加 --userns-root chroot）"
                } else {
                    ""
                };
                format!("挂载 {} ({}) 失败{hint}", m.destination, m.typ)
            })?;
        }
        points.push(dest);
    }

    // 基础设备节点用 bind 而不是 mknod：部分嵌套容器/seccomp 全局拒绝 mknod，
    // bind 宿主设备文件不需要 CAP_MKNOD，rootless 也通用。
    points.extend(bind_devices(rootfs)?);

    // rootfs 自身必须是一个挂载点，pivot_root 才接受；MS_REC 带上所有子挂载。
    // chroot 兼容路径不需要它（且它会复制整棵子挂载树，导致清理时 EBUSY），故跳过。
    if root_bind {
        mount(
            Some(rootfs),
            rootfs,
            None::<&Path>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&Path>,
        )
        .with_context(|| format!("bind mount {} 失败", rootfs.display()))?;
        points.push(rootfs.to_path_buf());
    }
    Ok(points)
}

/// -v 绑定挂载：源是目录就挂到目录，源是文件就挂到文件；ro 用 remount 实现。
fn bind_volume(src: &Path, dst: &Path, options: &[String]) -> Result<()> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    if src.is_file() {
        if !dst.exists() {
            File::create(dst).with_context(|| format!("创建文件挂载点 {} 失败", dst.display()))?;
        }
    } else {
        fs::create_dir_all(dst)?;
    }
    mount(
        Some(src),
        dst,
        None::<&Path>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&Path>,
    )
    .with_context(|| format!("bind {} -> {} 失败", src.display(), dst.display()))?;
    if options.iter().any(|o| o == "ro") {
        mount(
            None::<&Path>,
            dst,
            None::<&Path>,
            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
            None::<&Path>,
        )
        .with_context(|| format!("remount 只读 {} 失败", dst.display()))?;
    }
    Ok(())
}

fn mount_flags(options: &[String]) -> (MsFlags, String) {
    let mut flags = MsFlags::empty();
    let mut data = Vec::new();
    for o in options {
        match o.as_str() {
            "ro" => flags |= MsFlags::MS_RDONLY,
            "nosuid" => flags |= MsFlags::MS_NOSUID,
            "noexec" => flags |= MsFlags::MS_NOEXEC,
            "nodev" => flags |= MsFlags::MS_NODEV,
            "strictatime" => flags |= MsFlags::MS_STRICTATIME,
            "noatime" => flags |= MsFlags::MS_NOATIME,
            "relatime" => flags |= MsFlags::MS_RELATIME,
            _ => data.push(o.clone()),
        }
    }
    (flags, data.join(","))
}

/// 从宿主 bind 基础设备文件到 rootfs/dev（必须在 pivot 之前，宿主路径才可达）。
fn bind_devices(rootfs: &Path) -> Result<Vec<PathBuf>> {
    const DEVICES: &[&str] = &["null", "zero", "full", "random", "urandom", "tty"];
    let dev_dir = rootfs.join("dev");
    fs::create_dir_all(&dev_dir)?;
    let mut points = Vec::new();
    for name in DEVICES {
        let src = Path::new("/dev").join(name);
        if !src.exists() {
            continue;
        }
        let dst = dev_dir.join(name);
        if !dst.exists() {
            File::create(&dst).with_context(|| format!("创建设备挂载点 {} 失败", dst.display()))?;
        }
        mount(
            Some(&src),
            &dst,
            None::<&Path>,
            MsFlags::MS_BIND,
            None::<&Path>,
        )
        .with_context(|| format!("bind {} -> {} 失败", src.display(), dst.display()))?;
        points.push(dst);
    }
    Ok(points)
}

fn setup_dev_symlinks() -> Result<()> {
    for (link, target) in [
        ("/dev/fd", "/proc/self/fd"),
        ("/dev/stdin", "/proc/self/fd/0"),
        ("/dev/stdout", "/proc/self/fd/1"),
        ("/dev/stderr", "/proc/self/fd/2"),
        ("/dev/ptmx", "/dev/pts/ptmx"),
    ] {
        if !Path::new(link).exists() {
            symlink(target, link).with_context(|| format!("创建符号链接 {link} 失败"))?;
        }
    }
    Ok(())
}
