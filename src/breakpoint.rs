use std::collections::BTreeMap;

use crate::process::Process;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BreakPoint {
    pub addr: usize,
    orig_byte: Option<u8>,
}

#[cfg(target_arch = "x86_64")]
impl BreakPoint {
    pub fn new(addr: usize) -> Result<Self, std::io::Error> {
        Ok(Self {
            addr,
            orig_byte: None,
        })
    }

    pub fn enabled(&self) -> bool {
        self.orig_byte.is_some()
    }

    pub fn enable(&mut self, process: &mut Process) -> Result<(), std::io::Error> {
        assert!(self.orig_byte.is_none());

        let aligned_addr = self.addr & !0x7;
        let offset = self.addr - aligned_addr;
        assert!(offset < 8);

        let orig_data = process.read(aligned_addr)?.cast_unsigned();
        let int3_data = (orig_data & !(0xff << (offset * 8))) | (0xcc << (offset * 8));
        self.orig_byte = Some(((orig_data & (0xff << (offset * 8))) >> (offset * 8)) as u8);
        process.write(aligned_addr, int3_data.cast_signed())?;
        Ok(())
    }

    pub fn disable(&mut self, process: &mut Process) -> Result<(), std::io::Error> {
        let aligned_addr = self.addr & !0x7;
        let offset = self.addr - aligned_addr;
        assert!(offset < 8);

        let orig_data = process.read(aligned_addr)?.cast_unsigned();
        let restored_data = (orig_data & !(0xff << (offset * 8)))
            | ((self.orig_byte.take().unwrap() as u64) << (offset * 8));
        process.write(aligned_addr, restored_data.cast_signed())?;
        Ok(())
    }

    // For disassemble
    pub fn restore_code(&self, start_addr: usize, code: &mut [u8]) {
        if self.addr < start_addr || self.addr >= start_addr + code.len() {
            return;
        }

        if let Some(orig_byte) = self.orig_byte {
            let offset = self.addr - start_addr;
            code[offset] = orig_byte;
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
        if let Some((id, _)) = self.points.iter().find(|(_, bp)| bp.addr == addr) {
            return Ok(*id);
        }

        let mut bp = BreakPoint::new(addr)?;
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
        self.points.values_mut().find(|bp| bp.addr == addr)
    }

    pub fn restore_code(&self, start_addr: usize, code: &mut [u8]) {
        for bp in self.points.values() {
            bp.restore_code(start_addr, code);
        }
    }
}
