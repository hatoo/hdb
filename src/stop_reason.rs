#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    SysCall(i64),
    Other(nix::sys::wait::WaitStatus),
}

impl std::fmt::Display for StopReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StopReason::SysCall(num) => {
                write!(
                    f,
                    "{}",
                    syscall_numbers::native::sys_call_name(*num).unwrap_or("unknown syscall")
                )
            }
            StopReason::Other(status) => write!(f, "{:?}", status),
        }
    }
}
