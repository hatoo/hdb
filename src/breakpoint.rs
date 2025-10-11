use std::collections::BTreeMap;

use crate::{process::Process, register::DrIndex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, clap::ValueEnum)]
pub enum WatchMode {
    Execute,
    Write,
    #[clap(alias = "rw")]
    ReadWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Software or Hardware breakpoint/watchpoint
pub enum StopPoint {
    SoftwareBreak {
        addr: usize,
        orig_byte: Option<u8>,
    },
    Hardware {
        addr: usize,
        dr_index: Option<DrIndex>,
        size: usize,
        mode: WatchMode,
    },
    SysCallCatch {
        // None for all syscalls
        syscall: Option<i64>,
        enabled: bool,
    },
}

impl std::fmt::Display for StopPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StopPoint::SoftwareBreak { addr, .. } => {
                write!(f, "SW 0x{addr:x}")
            }
            StopPoint::Hardware {
                addr, size, mode, ..
            } => {
                let mode_str = match mode {
                    WatchMode::Execute => "Execute",
                    WatchMode::Write => "Write",
                    WatchMode::ReadWrite => "Read/Write",
                };
                write!(f, "HW 0x{addr:x}, size: {size}, mode: {mode_str}")
            }
            StopPoint::SysCallCatch { syscall, enabled } => {
                if let Some(syscall) = syscall {
                    write!(f, "Catch syscall {}", syscall)
                } else {
                    write!(f, "Catch all syscalls")
                }
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
impl StopPoint {
    pub fn new_software_break(addr: usize) -> Result<Self, std::io::Error> {
        Ok(Self::SoftwareBreak {
            addr,
            orig_byte: None,
        })
    }

    pub fn new_hardware(addr: usize, mode: WatchMode, size: usize) -> Result<Self, std::io::Error> {
        if size != 1 && size != 2 && size != 4 && size != 8 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "size must be 1, 2, 4, or 8",
            ));
        }

        if mode == WatchMode::Execute && size != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "size must be 1 for execute watchpoint",
            ));
        }

        if addr & (size - 1) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "addr must be aligned to size",
            ));
        }

        Ok(Self::Hardware {
            addr,
            dr_index: None,
            size,
            mode,
        })
    }

    pub fn is_hardware(&self) -> bool {
        matches!(self, StopPoint::Hardware { .. })
    }

    pub fn addr(&self) -> Option<usize> {
        match self {
            StopPoint::SoftwareBreak { addr, .. } => Some(*addr),
            StopPoint::Hardware { addr, .. } => Some(*addr),
            StopPoint::SysCallCatch { .. } => None,
        }
    }

    pub fn enabled(&self) -> bool {
        match self {
            StopPoint::SoftwareBreak { orig_byte, .. } => orig_byte.is_some(),
            StopPoint::Hardware { dr_index, .. } => dr_index.is_some(),
            StopPoint::SysCallCatch { enabled, .. } => *enabled,
        }
    }

    pub fn enable(
        &mut self,
        process: &mut Process,
        new_dr_index: Option<DrIndex>,
    ) -> Result<(), std::io::Error> {
        match self {
            StopPoint::SoftwareBreak { addr, orig_byte } => {
                assert!(orig_byte.is_none());

                let aligned_addr = *addr & !0x7;
                let offset = *addr - aligned_addr;
                assert!(offset < 8);

                let orig_data = process.read(aligned_addr)?.cast_unsigned();
                let int3_data = (orig_data & !(0xff << (offset * 8))) | (0xcc << (offset * 8));
                *orig_byte = Some(((orig_data & (0xff << (offset * 8))) >> (offset * 8)) as u8);
                process.write(aligned_addr, int3_data.cast_signed())?;
                Ok(())
            }
            StopPoint::Hardware {
                addr,
                dr_index,
                size,
                mode,
            } => {
                use crate::register::{DR, RegisterValue};

                let new_dr = new_dr_index.ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::Other, "no available debug register")
                })?;
                *dr_index = Some(new_dr);

                let mut regs = process.read_registers()?;
                let dr7 = regs.read(&DR[7]).as_usize();
                regs.write(&DR[*new_dr], RegisterValue::U64(*addr as _));

                let clear_mask = 0b11 << (*new_dr * 2) | (0b1111 << (16 + *new_dr * 4));
                let rw_bits = match mode {
                    WatchMode::Execute => 0b00,
                    WatchMode::Write => 0b01,
                    WatchMode::ReadWrite => 0b11,
                };
                let size_bits = match size {
                    1 => 0b00,
                    2 => 0b01,
                    4 => 0b11,
                    8 => 0b10,
                    _ => unreachable!(),
                };

                let new_dr7 = (dr7 & !clear_mask)
                    | (0b01 << (*new_dr * 2)) // local enable
                    | (rw_bits << (16 + *new_dr * 4)) // rw bits
                    | (size_bits << (18 + *new_dr * 4)) // size bits
                    ;
                regs.write(&DR[7], RegisterValue::U64(new_dr7 as _));
                process.write_registers(&regs)?;

                Ok(())
            }
            StopPoint::SysCallCatch { enabled, .. } => {
                *enabled = true;
                Ok(())
            }
        }
    }

    pub fn disable(&mut self, process: &mut Process) -> Result<Option<DrIndex>, std::io::Error> {
        match self {
            StopPoint::SoftwareBreak { addr, orig_byte } => {
                assert!(orig_byte.is_some());
                let aligned_addr = *addr & !0x7;
                let offset = *addr - aligned_addr;
                assert!(offset < 8);

                let orig_data = process.read(aligned_addr)?.cast_unsigned();
                let restored_data = (orig_data & !(0xff << (offset * 8)))
                    | ((orig_byte.take().unwrap() as u64) << (offset * 8));
                process.write(aligned_addr, restored_data.cast_signed())?;
                Ok(None)
            }
            StopPoint::Hardware { dr_index, .. } => {
                let dr_index = dr_index.take().unwrap();
                use crate::register::{DR, RegisterValue};

                let mut regs = process.read_registers()?;

                let mut dr7 = regs.read(&DR[7]).as_usize();
                let clear_mask = 0b11 << (*dr_index * 2) | (0b1111 << (16 + *dr_index * 4));
                dr7 &= !clear_mask;
                regs.write(&DR[*dr_index], RegisterValue::U64(dr7 as _));

                process.write_registers(&regs)?;

                Ok(Some(dr_index))
            }
            StopPoint::SysCallCatch { enabled, .. } => {
                *enabled = false;
                Ok(None)
            }
        }
    }

    // For disassemble
    pub fn restore_code(&self, start_addr: usize, code: &mut [u8]) {
        if let StopPoint::SoftwareBreak { addr, orig_byte } = self {
            if *addr < start_addr || *addr >= start_addr + code.len() {
                return;
            }

            if let Some(orig_byte) = *orig_byte {
                let offset = *addr - start_addr;
                code[offset] = orig_byte;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StopPointId(pub usize);

impl std::fmt::Display for StopPointId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub struct StopPoints {
    next_id: usize,
    points: BTreeMap<StopPointId, StopPoint>,
}

impl Default for StopPoints {
    fn default() -> Self {
        Self::new()
    }
}

impl StopPoints {
    pub fn new() -> Self {
        Self {
            next_id: 0,
            points: BTreeMap::new(),
        }
    }

    pub fn add_software(&mut self, addr: usize) -> Result<StopPointId, std::io::Error> {
        if let Some((id, _)) = self.points.iter().find(|(_, bp)| bp.addr() == Some(addr)) {
            return Ok(*id);
        }

        let bp = StopPoint::new_software_break(addr)?;

        let id = StopPointId(self.next_id);
        self.points.insert(id, bp);
        self.next_id += 1;
        Ok(id)
    }

    pub fn add_hardware(&mut self, addr: usize) -> Result<StopPointId, std::io::Error> {
        if let Some((id, _)) = self.points.iter().find(|(_, bp)| bp.addr() == Some(addr)) {
            return Ok(*id);
        }

        let bp = StopPoint::new_hardware(addr, WatchMode::Execute, 1)?;

        let id = StopPointId(self.next_id);
        self.points.insert(id, bp);
        self.next_id += 1;
        Ok(id)
    }

    pub fn add_syscall_catch(
        &mut self,
        syscall: Option<i64>,
    ) -> Result<StopPointId, std::io::Error> {
        if let Some((id, _)) = self.points.iter().find(|(_, bp)| {
            if let StopPoint::SysCallCatch { syscall: s, .. } = bp {
                *s == syscall
            } else {
                false
            }
        }) {
            return Ok(*id);
        }

        let bp = StopPoint::SysCallCatch {
            syscall,
            enabled: false,
        };

        let id = StopPointId(self.next_id);
        self.points.insert(id, bp);
        self.next_id += 1;
        Ok(id)
    }

    pub fn add_watchpoint(
        &mut self,
        addr: usize,
        size: usize,
        mode: WatchMode,
    ) -> Result<StopPointId, std::io::Error> {
        if let Some((id, _)) = self.points.iter().find(|(_, bp)| bp.addr() == Some(addr)) {
            return Ok(*id);
        }

        let bp = StopPoint::new_hardware(addr, mode, size)?;

        let id = StopPointId(self.next_id);
        self.points.insert(id, bp);
        self.next_id += 1;
        Ok(id)
    }

    pub fn enable(
        &mut self,
        process: &mut Process,
        id: StopPointId,
        dr_index: Option<DrIndex>,
    ) -> Result<(), std::io::Error> {
        if let Some(bp) = self.points.get_mut(&id) {
            if !bp.enabled() {
                bp.enable(process, dr_index)?;
            }
        }
        Ok(())
    }

    pub fn remove(
        &mut self,
        process: &mut Process,
        id: StopPointId,
    ) -> Result<Option<DrIndex>, std::io::Error> {
        if let Some(mut bp) = self.points.remove(&id)
            && bp.enabled()
        {
            let dr_index = bp.disable(process)?;
            return Ok(dr_index);
        }
        Ok(None)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&StopPointId, &StopPoint)> {
        self.points.iter()
    }

    pub fn break_point_at(&mut self, addr: usize) -> Option<&mut StopPoint> {
        self.points.values_mut().find(|bp| bp.addr() == Some(addr))
    }

    pub fn restore_code(&self, start_addr: usize, code: &mut [u8]) {
        for bp in self.points.values() {
            bp.restore_code(start_addr, code);
        }
    }

    pub fn contains(&self, syscall: i64) -> bool {
        self.points.values().any(|bp| {
            if let StopPoint::SysCallCatch {
                syscall: s,
                enabled,
            } = bp
            {
                *enabled && (s.is_none() || s == &Some(syscall))
            } else {
                false
            }
        })
    }

    pub fn contains_syscall_catch(&self) -> bool {
        self.points
            .values()
            .any(|bp| matches!(bp, StopPoint::SysCallCatch { enabled: true, .. }))
    }
}
