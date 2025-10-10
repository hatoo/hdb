use std::collections::BTreeMap;

use crate::process::Process;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BreakPoint {
    Software {
        addr: usize,
        orig_byte: Option<u8>,
    },
    Hardware {
        addr: usize,
        dr_index: usize,
        enabled: bool,
    },
}

#[cfg(target_arch = "x86_64")]
impl BreakPoint {
    pub fn new_software(addr: usize) -> Result<Self, std::io::Error> {
        Ok(Self::Software {
            addr,
            orig_byte: None,
        })
    }

    pub fn new_hardware(addr: usize, dr_index: usize) -> Result<Self, std::io::Error> {
        if dr_index >= 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "dr_index must be 0..3",
            ));
        }

        Ok(Self::Hardware {
            addr,
            dr_index,
            enabled: false,
        })
    }

    pub fn addr(&self) -> usize {
        match self {
            BreakPoint::Software { addr, .. } => *addr,
            BreakPoint::Hardware { addr, .. } => *addr,
        }
    }

    pub fn enabled(&self) -> bool {
        match self {
            BreakPoint::Software { orig_byte, .. } => orig_byte.is_some(),
            BreakPoint::Hardware { enabled, .. } => *enabled,
        }
    }

    pub fn enable(&mut self, process: &mut Process) -> Result<(), std::io::Error> {
        match self {
            BreakPoint::Software { addr, orig_byte } => {
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
            BreakPoint::Hardware {
                addr,
                dr_index,
                enabled,
            } => {
                use crate::register::{DR, RegisterValue};

                assert!(!*enabled);

                let mut regs = process.read_registers()?;
                let dr7 = regs.read(&DR[7]).as_usize();
                let dr_index = *dr_index;
                regs.write(&DR[dr_index], RegisterValue::U64(*addr as _));

                let clear_mask = 0b11 << (dr_index * 2) | (0b1111 << (16 + dr_index * 4));
                let new_dr7 = (dr7 & !clear_mask)
                    | (0b01 << (dr_index * 2)) // local enable
                    | (0b00 << (16 + dr_index * 4)); // exec
                // size 1 (00)
                regs.write(&DR[7], RegisterValue::U64(new_dr7 as _));

                process.write_registers(&regs)?;
                *enabled = true;

                Ok(())
            }
        }
    }

    pub fn disable(&mut self, process: &mut Process) -> Result<(), std::io::Error> {
        match self {
            BreakPoint::Software { addr, orig_byte } => {
                assert!(orig_byte.is_some());
                let aligned_addr = *addr & !0x7;
                let offset = *addr - aligned_addr;
                assert!(offset < 8);

                let orig_data = process.read(aligned_addr)?.cast_unsigned();
                let restored_data = (orig_data & !(0xff << (offset * 8)))
                    | ((orig_byte.take().unwrap() as u64) << (offset * 8));
                process.write(aligned_addr, restored_data.cast_signed())?;
                Ok(())
            }
            BreakPoint::Hardware {
                dr_index, enabled, ..
            } => {
                use crate::register::{DR, RegisterValue};

                let mut regs = process.read_registers()?;
                assert!(*enabled);

                let mut dr7 = regs.read(&DR[7]).as_usize();
                let clear_mask = 0b11 << (*dr_index * 2) | (0b1111 << (16 + *dr_index * 4));
                dr7 &= !clear_mask;
                regs.write(&DR[*dr_index], RegisterValue::U64(dr7 as _));

                process.write_registers(&regs)?;
                *enabled = false;

                Ok(())
            }
        }
    }

    // For disassemble
    pub fn restore_code(&self, start_addr: usize, code: &mut [u8]) {
        if let BreakPoint::Software { addr, orig_byte } = self {
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
pub struct BreakPointId(pub usize);

impl std::fmt::Display for BreakPointId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub struct BreakPoints {
    next_id: usize,
    points: BTreeMap<BreakPointId, BreakPoint>,
}

impl Default for BreakPoints {
    fn default() -> Self {
        Self::new()
    }
}

impl BreakPoints {
    pub fn new() -> Self {
        Self {
            next_id: 0,
            points: BTreeMap::new(),
        }
    }

    pub fn add(
        &mut self,
        process: &mut Process,
        addr: usize,
    ) -> Result<BreakPointId, std::io::Error> {
        if let Some((id, _)) = self.points.iter().find(|(_, bp)| bp.addr() == addr) {
            return Ok(*id);
        }

        let mut bp = BreakPoint::new_software(addr)?;
        bp.enable(process)?;

        let id = BreakPointId(self.next_id);
        self.points.insert(id, bp);
        self.next_id += 1;
        Ok(id)
    }

    pub fn remove(
        &mut self,
        process: &mut Process,
        id: BreakPointId,
    ) -> Result<(), std::io::Error> {
        if let Some(mut bp) = self.points.remove(&id)
            && bp.enabled()
        {
            bp.disable(process)?;
        }
        Ok(())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&BreakPointId, &BreakPoint)> {
        self.points.iter()
    }

    pub fn break_point_at(&mut self, addr: usize) -> Option<&mut BreakPoint> {
        self.points.values_mut().find(|bp| bp.addr() == addr)
    }

    pub fn restore_code(&self, start_addr: usize, code: &mut [u8]) {
        for bp in self.points.values() {
            bp.restore_code(start_addr, code);
        }
    }
}
