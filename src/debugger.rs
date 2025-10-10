use iced_x86::Formatter;

use crate::{
    breakpoint::{BreakPoint, BreakPointId, BreakPoints},
    process::Process,
    register::RegisterInfo,
};

pub struct Debugger {
    process: Process,
    breakpoints: BreakPoints,
    // used drs
    dr_status: [bool; 4],
}

impl Debugger {
    pub fn new(process: crate::process::Process) -> Self {
        Self {
            process,
            breakpoints: BreakPoints::new(),
            dr_status: [false; 4],
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
            Ok(status)
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

    pub fn read_memory(&mut self, addr: usize, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        self.process.read_at(addr, buf)
    }

    pub fn write_memory(&mut self, addr: usize, data: &[u8]) -> Result<usize, std::io::Error> {
        self.process.write_at(addr, data)
    }

    pub fn breakpoints(&self) -> impl Iterator<Item = (&BreakPointId, &BreakPoint)> {
        self.breakpoints.iter()
    }

    pub fn get_free_dr(&mut self) -> Option<usize> {
        for (i, used) in self.dr_status.iter().enumerate() {
            if !*used {
                self.dr_status[i] = true;
                return Some(i);
            }
        }

        None
    }

    pub fn release_dr(&mut self, dr_index: usize) {
        self.dr_status[dr_index] = false;
    }

    pub fn add_breakpoint_software(&mut self, addr: usize) -> Result<BreakPointId, std::io::Error> {
        let id = self.breakpoints.add_software(&mut self.process, addr)?;
        Ok(id)
    }

    pub fn add_breakpoint_hardware(&mut self, addr: usize) -> Result<BreakPointId, std::io::Error> {
        if let Some(id) = self.get_free_dr() {
            let bp_id = self.breakpoints.add_hardware(&mut self.process, addr, id)?;
            Ok(bp_id)
        } else {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "no free dr"));
        }
    }

    pub fn remove_breakpoint(&mut self, id: BreakPointId) -> Result<(), std::io::Error> {
        if let Some(dr_index) = self.breakpoints.remove(&mut self.process, id)? {
            self.release_dr(dr_index);
        }
        Ok(())
    }

    pub fn disassemble(
        &mut self,
        addr: Option<usize>,
        count: usize,
    ) -> Result<Vec<(usize, String)>, std::io::Error> {
        let pc = if let Some(addr) = addr {
            addr
        } else {
            let pc = self.get_pc()?;
            if self.breakpoints.break_point_at(pc - 1).is_some() {
                pc - 1
            } else {
                pc
            }
        };
        let mut code = vec![0u8; count * 15];
        self.read_memory(pc, &mut code)?;

        self.breakpoints.restore_code(pc, &mut code);

        let mut decoder =
            iced_x86::Decoder::with_ip(64, &code, pc as u64, iced_x86::DecoderOptions::NONE);
        let mut formatter = iced_x86::GasFormatter::new();
        let mut output = String::new();
        let mut instruction = iced_x86::Instruction::default();
        let mut results = Vec::new();
        let mut decoded_count = 0;
        let mut last_pos = 0;
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            let pos = decoder.position();
            output.clear();
            formatter.format(&instruction, &mut output);
            results.push((
                instruction.ip() as usize,
                format!("{}\t{:02x?}", output, &code[last_pos..pos]),
            ));

            last_pos = pos;
            decoded_count += 1;
            if decoded_count >= count {
                break;
            }
        }

        Ok(results)
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
        debugger.add_breakpoint_software(load_addr).unwrap();

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
        let bp_id = debugger.add_breakpoint_software(load_addr).unwrap();
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
        let bp_id = debugger.add_breakpoint_software(load_addr).unwrap();

        assert_eq!(debugger.breakpoints().count(), 1);
        assert_eq!(debugger.breakpoints().next().unwrap().1.addr(), load_addr);

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

        let mut value = [0u8; 8];
        debugger.read_memory(addr, &mut value).unwrap();
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
