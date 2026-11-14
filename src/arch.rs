//! 宿主架构抽象：OCI 平台字符串、seccomp audit arch、镜像 manifest 选择。
//!
//! 只支持 linux/amd64 与 linux/arm64（aarch64）。其他架构一律 fail-fast，
//! 不做"看起来能跑"的静默降级。
//!
//! 这里刻意不引入任何外部 crate：架构常量只有两个，写死比再拉一个依赖更可控。
//! syscall 编号仍然全部取自 `libc::SYS_*` —— libc 已经按目标架构条件编译，
//! 同一份 `denied_syscalls()` 源码在 x86_64 与 aarch64 上会自动得到正确编号。

use anyhow::{bail, Result};
use std::env::consts::ARCH;

/// ELF/AUDIT 架构标识（`linux/audit.h`）：__AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE | EM_*
pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
pub const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostArch {
    Amd64,
    Arm64,
}

impl HostArch {
    /// OCI image-spec 的 `platform.architecture` 取值。
    pub fn oci_name(self) -> &'static str {
        match self {
            HostArch::Amd64 => "amd64",
            HostArch::Arm64 => "arm64",
        }
    }

    pub fn os(self) -> &'static str {
        "linux"
    }

    pub fn audit_arch(self) -> u32 {
        match self {
            HostArch::Amd64 => AUDIT_ARCH_X86_64,
            HostArch::Arm64 => AUDIT_ARCH_AARCH64,
        }
    }

    /// 判断镜像 manifest 里的 architecture 字段是否与本架构等价。
    /// 兼容 registry 里常见的别名：`x86_64`/`amd64`、`aarch64`/`arm64`，
    /// 以及部分工具写出的 `arm64/v8` variant（这里只比较 `arm64` 前缀）。
    pub fn matches(self, value: &str) -> bool {
        let v = value.trim().to_ascii_lowercase();
        match self {
            HostArch::Amd64 => v == "amd64" || v == "x86_64",
            HostArch::Arm64 => v == "arm64" || v == "aarch64" || v.starts_with("arm64/"),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            HostArch::Amd64 => "linux/amd64",
            HostArch::Arm64 => "linux/arm64",
        }
    }
}

/// 当前进程所在架构；不支持的架构直接报错。
pub fn host() -> Result<HostArch> {
    match ARCH {
        "x86_64" => Ok(HostArch::Amd64),
        "aarch64" => Ok(HostArch::Arm64),
        other => bail!("miko 只支持 x86_64 / aarch64，当前架构 {other:?} 不受支持"),
    }
}

/// 解析 `--platform linux/amd64`（也接受简写 amd64 / arm64）。
/// 不允许指定与宿主不同的架构去"硬跑"——镜像与二进制的指令集必须一致；
/// `--platform` 的用途是覆盖 registry 的 manifest 选择（例如镜像 index 元数据有误）。
pub fn parse_platform(s: &str) -> Result<HostArch> {
    let raw = s.trim().to_ascii_lowercase();
    let arch = match raw.rsplit_once('/') {
        Some((os, a)) => {
            if os != "linux" {
                bail!("--platform 只支持 linux/<arch>，收到 {s:?}");
            }
            a
        }
        None => raw.as_str(),
    };
    let want = match arch {
        "amd64" | "x86_64" => HostArch::Amd64,
        "arm64" | "aarch64" => HostArch::Arm64,
        other => bail!("--platform 只支持 amd64 / arm64，收到 {other:?}"),
    };
    let native = host()?;
    if want != native {
        bail!(
            "--platform {} 与宿主架构 {} 不一致；miko 不做跨架构模拟（无 qemu/binfmt）",
            want.label(),
            native.label()
        );
    }
    Ok(want)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arch_aliases() {
        assert!(HostArch::Amd64.matches("amd64"));
        assert!(HostArch::Amd64.matches("x86_64"));
        assert!(!HostArch::Amd64.matches("arm64"));
        assert!(HostArch::Arm64.matches("arm64"));
        assert!(HostArch::Arm64.matches("aarch64"));
        assert!(HostArch::Arm64.matches("ARM64/v8"));
        assert!(!HostArch::Arm64.matches("amd64"));
    }

    #[test]
    fn platform_parsing() {
        let native = host().unwrap();
        let (long, short, other) = if native == HostArch::Amd64 {
            ("linux/amd64", "amd64", "linux/arm64")
        } else {
            ("linux/arm64", "arm64", "linux/amd64")
        };
        assert_eq!(parse_platform(long).unwrap(), native);
        assert_eq!(parse_platform(short).unwrap(), native);
        assert!(parse_platform("windows/amd64").is_err());
        assert!(parse_platform("linux/riscv64").is_err());
        // 与宿主不一致时必须拒绝（不做 qemu/binfmt 跨架构模拟）
        assert!(parse_platform(other).is_err());
    }

    #[test]
    fn audit_arch_values() {
        assert_eq!(HostArch::Amd64.audit_arch(), 0xc000_003e);
        assert_eq!(HostArch::Arm64.audit_arch(), 0xc000_00b7);
    }
}
