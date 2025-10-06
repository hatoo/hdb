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

#[non_exhaustive]
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

impl RegisterValue {
    pub fn as_usize(&self) -> usize {
        match self {
            RegisterValue::U64(v) => *v as usize,
            RegisterValue::U8(v) => *v as usize,
            RegisterValue::U128(v) => *v as usize,
        }
    }
}
#[cfg(target_arch = "x86_64")]
pub const PC: RegisterInfo = RegisterInfo {
    name: "rip",
    reg_type: RegisterType::Gpr,
    format: RegisterFormat::Uint,
    offset: std::mem::offset_of!(libc::user, regs.rip),
    size: 8,
};

#[cfg(target_arch = "x86_64")]
pub const REGISTERS: &[RegisterInfo] = &[
    RegisterInfo {
        name: "rip",
        reg_type: RegisterType::Gpr,
        format: RegisterFormat::Uint,
        offset: std::mem::offset_of!(libc::user, regs.rip),
        size: 8,
    },
    RegisterInfo {
        name: "rax",
        reg_type: RegisterType::Gpr,
        format: RegisterFormat::Uint,
        offset: std::mem::offset_of!(libc::user, regs.rax),
        size: 8,
    },
    RegisterInfo {
        name: "rsi",
        reg_type: RegisterType::Gpr,
        format: RegisterFormat::Uint,
        offset: std::mem::offset_of!(libc::user, regs.rsi),
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

impl RegisterValue {
    pub fn to_le_bytes(&self) -> Vec<u8> {
        match self {
            RegisterValue::U64(v) => v.to_le_bytes().to_vec(),
            RegisterValue::U8(v) => vec![*v],
            RegisterValue::U128(v) => v.to_le_bytes().to_vec(),
        }
    }
}

impl Registers {
    pub fn read(&self, reg: &RegisterInfo) -> RegisterValue {
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
            _ => unreachable!(),
        };

        value
    }

    pub fn write(&mut self, reg: &RegisterInfo, value: RegisterValue) {
        let mut bytes = value.to_le_bytes();
        if reg.size > bytes.len() {
            bytes.resize(reg.size, 0);
        }
        let ptr = (&mut self.user as *mut _ as *mut u8).wrapping_add(reg.offset);
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, reg.size);
        }
    }
}
