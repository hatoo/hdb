use std::collections::BTreeMap;

use crate::{process::Process, register::RegisterInfo};

pub struct Debugger {
    process: crate::process::Process,
    breakpoints: BreakPoints,
}

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
        if let Some(mut bp) = self.points.remove(&id) {
            if bp.enabled() {
                bp.disable(process)?;
            }
        }
        Ok(())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&BreakPointId, &BreakPoint)> {
        self.points.iter()
    }

    pub fn break_point_at(&mut self, addr: usize) -> Option<&mut BreakPoint> {
        self.points.values_mut().find(|bp| bp.addr == addr)
    }
}

impl Debugger {
    pub fn new(process: crate::process::Process) -> Self {
        Self {
            process,
            breakpoints: BreakPoints::new(),
        }
    }

    /// Do not call syscalls with this pid for thread safety.
    /// You should use other methods of this struct.
    pub unsafe fn raw_pid(&self) -> i32 {
        unsafe { self.process.raw_pid() }
    }

    fn skip_breakpoint(&mut self) -> Result<Option<nix::sys::wait::WaitStatus>, std::io::Error> {
        let pc = self.get_pc()?;
        if self.breakpoints.break_point_at(pc - 1).is_some() {
            self.set_pc(pc - 1)?;
            let Some(breakpoint) = self.breakpoints.break_point_at(pc - 1) else {
                unreachable!()
            };
            breakpoint.disable(&mut self.process)?;
            let status = self.process.single_step()?;
            breakpoint.enable(&mut self.process)?;
            Ok(Some(status))
        } else {
            Ok(None)
        }
    }

    pub fn step(&mut self) -> Result<nix::sys::wait::WaitStatus, std::io::Error> {
        if let Some(status) = self.skip_breakpoint()? {
            return Ok(status);
        } else {
            let status = self.process.single_step()?;
            Ok(status)
        }
    }

    pub fn resume(&mut self) -> Result<nix::sys::wait::WaitStatus, std::io::Error> {
        self.skip_breakpoint()?;
        let status = self.process.resume()?;

        Ok(status)
    }

    pub fn get_pc(&mut self) -> Result<usize, std::io::Error> {
        let rip = self.read_register(&crate::register::PC)?.as_usize();
        Ok(rip)
    }

    pub fn set_pc(&mut self, pc: usize) -> Result<(), std::io::Error> {
        self.write_register(
            &crate::register::PC,
            crate::register::RegisterValue::U64(pc as u64),
        )?;
        Ok(())
    }

    pub fn read_register(
        &mut self,
        reg: &RegisterInfo,
    ) -> Result<crate::register::RegisterValue, std::io::Error> {
        let regs = self.process.read_registers()?;
        Ok(regs.read(reg))
    }

    pub fn write_register(
        &mut self,
        reg: &RegisterInfo,
        value: crate::register::RegisterValue,
    ) -> Result<(), std::io::Error> {
        let mut regs = self.process.read_registers()?;
        regs.write(reg, value);
        self.process.write_registers(&regs)?;

        Ok(())
    }

    pub fn read_memory(&mut self, addr: usize, size: usize) -> Result<Vec<u8>, std::io::Error> {
        self.process.read_at(addr, size)
    }

    pub fn write_memory(&mut self, addr: usize, data: &[u8]) -> Result<usize, std::io::Error> {
        self.process.write_at(addr, data)
    }

    pub fn breakpoints(&self) -> impl Iterator<Item = (&BreakPointId, &BreakPoint)> {
        self.breakpoints.iter()
    }

    pub fn add_breakpoint(&mut self, addr: usize) -> Result<BreakPointId, std::io::Error> {
        let id = self.breakpoints.add(&mut self.process, addr)?;
        Ok(id)
    }

    pub fn remove_breakpoint(&mut self, id: BreakPointId) -> Result<(), std::io::Error> {
        self.breakpoints.remove(&mut self.process, id)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::panic;
    use nix::sys::wait::WaitStatus;
    use std::{
        io::Read,
        os::{fd::AsRawFd, unix::process::CommandExt},
        process::Command,
    };

    fn get_file_load_addr(path: &std::path::Path) -> isize {
        let readelf = String::from_utf8_lossy(
            &std::process::Command::new("readelf")
                .arg("-WS")
                .arg(path)
                .output()
                .unwrap()
                .stdout,
        )
        .into_owned();

        for line in readelf.lines() {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 7 && cols[1] == ".text" {
                let addr = isize::from_str_radix(cols[3], 16).unwrap();
                let offset = isize::from_str_radix(cols[4], 16).unwrap();

                return addr + addr - offset;
            }
        }

        panic!("no .text section");
    }

    fn get_load_addr(path: &std::path::Path, pid: i32) -> usize {
        let file_load_addr = get_file_load_addr(path);

        let maps = std::fs::read_to_string(format!("/proc/{}/maps", pid)).unwrap();
        for line in maps.lines() {
            if line.contains("r-xp") {
                let addr_str = line.split('-').next().unwrap();
                let addr_start = isize::from_str_radix(addr_str, 16).unwrap();
                let offset =
                    isize::from_str_radix(line.split_whitespace().nth(2).unwrap(), 16).unwrap();

                return usize::try_from(addr_start - offset + file_load_addr).unwrap();
            }
        }

        panic!("no hello_world mapping");
    }

    #[test]
    fn test_breakpoint_stops() {
        let hello_world = crate::test::compile("tests/hello_world.c");

        let (mut rx, tx) = std::io::pipe().unwrap();
        let mut command = Command::new(hello_world.as_os_str());
        unsafe {
            command.pre_exec(move || {
                libc::close(libc::STDOUT_FILENO);
                libc::dup2(tx.as_raw_fd(), libc::STDOUT_FILENO);
                Ok(())
            });
        }

        let process = Process::spawn(command).unwrap();
        let mut debugger = Debugger::new(process);

        let load_addr = get_load_addr(hello_world.as_ref(), unsafe { debugger.raw_pid() });
        debugger.add_breakpoint(load_addr).unwrap();

        let status = debugger.resume().unwrap();
        assert!(matches!(
            status,
            WaitStatus::Stopped(_, nix::sys::signal::Signal::SIGTRAP)
        ),);
        assert_eq!(debugger.get_pc().unwrap(), load_addr + 1);

        let status = debugger.resume().unwrap();

        let mut output = String::new();
        std::io::Read::read_to_string(&mut rx, &mut output).unwrap();
        assert_eq!(output, "Hello, World!\n");

        assert!(matches!(status, WaitStatus::Exited(_, 0)),)
    }

    #[test]
    fn test_breakpoint_remove() {
        let hello_world = crate::test::compile("tests/hello_world.c");
        let (mut rx, tx) = std::io::pipe().unwrap();
        let mut command = Command::new(hello_world.as_os_str());
        unsafe {
            command.pre_exec(move || {
                libc::close(libc::STDOUT_FILENO);
                libc::dup2(tx.as_raw_fd(), libc::STDOUT_FILENO);
                Ok(())
            });
        }
        let process = Process::spawn(command).unwrap();
        let mut debugger = Debugger::new(process);
        let load_addr = get_load_addr(hello_world.as_ref(), unsafe { debugger.raw_pid() });
        let bp_id = debugger.add_breakpoint(load_addr).unwrap();
        debugger.remove_breakpoint(bp_id).unwrap();

        let status = debugger.resume().unwrap();
        let mut output = String::new();
        std::io::Read::read_to_string(&mut rx, &mut output).unwrap();
        assert_eq!(output, "Hello, World!\n");

        assert!(matches!(status, WaitStatus::Exited(_, 0)),);
    }

    #[test]
    fn test_breakpoint_list() {
        let hello_world = crate::test::compile("tests/hello_world.c");
        let mut command = Command::new(hello_world.as_os_str());
        command.stdout(std::process::Stdio::null());
        let process = Process::spawn(command).unwrap();
        let mut debugger = Debugger::new(process);
        let load_addr = get_load_addr(hello_world.as_ref(), unsafe { debugger.raw_pid() });
        let bp_id = debugger.add_breakpoint(load_addr).unwrap();

        assert_eq!(debugger.breakpoints().count(), 1);
        assert_eq!(debugger.breakpoints().next().unwrap().1.addr, load_addr);

        debugger.remove_breakpoint(bp_id).unwrap();
        assert_eq!(debugger.breakpoints().count(), 0);
    }

    #[test]
    fn test_read_write_memory() {
        let memory = crate::test::compile("tests/memory.cpp");

        let mut command = Command::new(memory.as_os_str());
        let (mut rx, tx) = std::io::pipe().unwrap();
        unsafe {
            command.pre_exec(move || {
                libc::close(libc::STDOUT_FILENO);
                libc::dup2(tx.as_raw_fd(), libc::STDOUT_FILENO);
                Ok(())
            })
        };

        let process = Process::spawn(command).unwrap();
        let mut debugger = Debugger::new(process);

        debugger.resume().unwrap();

        let mut addr = [0u8; 8];
        rx.read_exact(&mut addr).unwrap();
        let addr = usize::from_le_bytes(addr);

        let value = debugger.read_memory(addr, 8).unwrap();
        let value = u64::from_le_bytes(value.try_into().unwrap());
        assert_eq!(value, 0xcafecafe);

        debugger.resume().unwrap();

        let mut addr = [0u8; 8];
        rx.read_exact(&mut addr).unwrap();
        let addr = usize::from_le_bytes(addr);

        let write_value = b"hello hdb";
        debugger.write_memory(addr, write_value).unwrap();

        debugger.resume().unwrap();

        let mut output = String::new();
        std::io::Read::read_to_string(&mut rx, &mut output).unwrap();
        assert_eq!(output, "hello hdb");
    }
}
