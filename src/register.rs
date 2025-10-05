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

#[derive(Debug)]
pub struct Registers {
    pub user: libc::user,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterValue {
    U64(u64),
    U8(u8),
    U128(u128),
}

#[cfg(target_arch = "x86_64")]
pub const REGISTERS: &[RegisterInfo] = &[
    RegisterInfo {
        name: "rax",
        reg_type: RegisterType::Gpr,
        format: RegisterFormat::Uint,
        offset: std::mem::offset_of!(libc::user, regs.rax),
        size: 8,
    },
    RegisterInfo {
        name: "r13",
        reg_type: RegisterType::Gpr,
        format: RegisterFormat::Uint,
        offset: std::mem::offset_of!(libc::user, regs.r13),
        size: 8,
    },
    RegisterInfo {
        name: "r13b",
        reg_type: RegisterType::SubGpr,
        format: RegisterFormat::Uint,
        offset: std::mem::offset_of!(libc::user, regs.r13),
        size: 1,
    },
    RegisterInfo {
        name: "xmm0",
        reg_type: RegisterType::Fpr,
        format: RegisterFormat::Vector,
        offset: std::mem::offset_of!(libc::user, i387.st_space).wrapping_add(0 * 16),
        size: 8,
    },
    RegisterInfo {
        name: "st0",
        reg_type: RegisterType::Fpr,
        format: RegisterFormat::LongDouble,
        offset: std::mem::offset_of!(libc::user, i387.st_space).wrapping_add(0 * 16),
        size: 16,
    },
];

impl Registers {
    pub fn read_by_name(&self, name: &str) -> Option<RegisterValue> {
        let reg = REGISTERS.iter().find(|r| r.name == name)?;
        let ptr = (&self.user.regs as *const _ as *const u8).wrapping_add(reg.offset);
        let value = match reg.size {
            8 => RegisterValue::U64(unsafe { *(ptr as *const u64) }),
            1 => RegisterValue::U8(unsafe { *(ptr as *const u8) }),
            16 => {
                let mut bytes = [0u8; 16];
                unsafe {
                    std::ptr::copy_nonoverlapping(ptr, bytes.as_mut_ptr(), 16);
                }

                RegisterValue::U128(u128::from_le_bytes(bytes))
            }
            _ => return None,
        };

        Some(value)
    }
}
