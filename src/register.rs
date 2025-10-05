pub enum RegisterType {
    Gpr,
    SubGpr,
    Fpr,
    Dr,
}

pub enum RegisterFormat {
    Uint,
    DoubleFloat,
    LongDouble,
    Vector,
}

pub struct RegisterInfo {
    pub name: &'static str,
    pub reg_type: RegisterType,
    pub format: RegisterFormat,
    pub offset: usize,
    pub size: usize,
}

pub struct Registers {
    pub user: libc::user,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterValue {
    Uint(u64),
}

#[cfg(target_arch = "x86_64")]
pub const REGISTERS: &[RegisterInfo] = &[RegisterInfo {
    name: "rax",
    reg_type: RegisterType::Gpr,
    format: RegisterFormat::Uint,
    offset: std::mem::offset_of!(libc::user, regs.rax),
    size: 8,
}];

impl Registers {
    pub fn read_by_name(&self, name: &str) -> Option<RegisterValue> {
        let reg = REGISTERS.iter().find(|r| r.name == name)?;
        let ptr = (&self.user.regs as *const _ as *const u8).wrapping_add(reg.offset);
        let value = match reg.size {
            8 => RegisterValue::Uint(unsafe { *(ptr as *const u64) }),
            _ => return None,
        };

        Some(value)
    }
}
