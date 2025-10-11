use std::collections::BTreeSet;

use iced_x86::Formatter;
use nix::sys::wait::WaitStatus;

use crate::{
    breakpoint::{StopPoint, StopPointId, StopPoints, WatchMode},
    process::Process,
    register::{DrIndex, RegisterInfo},
    stop_reason::StopReason,
};

pub enum CatchPoints {
    All,
    Syscalls(BTreeSet<i64>),
}

impl CatchPoints {
    pub fn is_empty(&self) -> bool {
        match self {
            CatchPoints::All => false,
            CatchPoints::Syscalls(set) => set.is_empty(),
        }
    }

    fn contains(&self, syscall: i64) -> bool {
        match self {
            CatchPoints::All => true,
            CatchPoints::Syscalls(set) => set.contains(&syscall),
        }
    }
}

impl std::fmt::Display for CatchPoints {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CatchPoints::All => write!(f, "all syscalls"),
            CatchPoints::Syscalls(set) => {
                let mut first = true;
                for syscall in set {
                    if !first {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", syscall)?;
                    first = false;
                }
                Ok(())
            }
        }
    }
}

pub struct Debugger {
    process: Process,
    breakpoints: StopPoints,
    // used drs
    dr_status: [bool; 4],
}

impl Debugger {
    pub fn new(process: crate::process::Process) -> Self {
        Self {
            process,
            breakpoints: StopPoints::new(),
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
        if let Some(breakpoint) = self.breakpoints.break_point_at(pc - 1)
            && breakpoint.enabled()
            && !breakpoint.is_hardware()
        {
            self.set_pc(pc - 1)?;
            let Some(breakpoint) = self.breakpoints.break_point_at(pc - 1) else {
                unreachable!()
            };
            breakpoint.disable(&mut self.process)?;
            let status = self.process.single_step()?;
            breakpoint.enable(&mut self.process, None)?;
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

    pub fn resume(&mut self) -> Result<StopReason, std::io::Error> {
        self.skip_breakpoint()?;

        if self.breakpoints.contains_syscall_catch() {
            self.process.ptrace_syscall()?;
        } else {
            self.process.ptrace_cont()?;
        }
        let pid = unsafe { self.raw_pid() };
        let _ = ctrlc::set_handler(move || {
            let _ =
                nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), nix::sys::signal::SIGSTOP);
        });
        let status = self.process.wait_on_signal()?;

        if matches!(status, WaitStatus::PtraceSyscall(_)) {
            let regs = self.process.read_registers()?;
            let syscall = regs.read(&crate::register::ORIG_RAX).as_i64();

            self.process.ptrace_syscall()?;
            let _status = self.process.wait_on_signal()?;

            if self.breakpoints.contains(syscall) {
                return Ok(StopReason::SysCall(syscall));
            } else {
                return self.resume();
            }
        }

        Ok(StopReason::Other(status))
    }

    pub fn siginfo(&mut self) -> Result<libc::siginfo_t, std::io::Error> {
        self.process.siginfo()
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

    pub fn breakpoints(&self) -> impl Iterator<Item = (&StopPointId, &StopPoint)> {
        self.breakpoints.iter()
    }

    pub fn take_free_dr(&mut self) -> Option<DrIndex> {
        for (i, used) in self.dr_status.iter_mut().enumerate() {
            if !*used {
                *used = true;
                return Some(DrIndex::new(i));
            }
        }

        None
    }

    pub fn release_dr(&mut self, dr_index: DrIndex) {
        self.dr_status[*dr_index] = false;
    }

    pub fn add_breakpoint_software(&mut self, addr: usize) -> Result<StopPointId, std::io::Error> {
        let id = self.breakpoints.add_software(addr)?;
        self.breakpoints.enable(&mut self.process, id, None)?;
        Ok(id)
    }

    pub fn add_breakpoint_hardware(&mut self, addr: usize) -> Result<StopPointId, std::io::Error> {
        if let Some(dr_index) = self.take_free_dr() {
            let bp_id = self.breakpoints.add_hardware(addr)?;
            self.breakpoints
                .enable(&mut self.process, bp_id, Some(dr_index))?;
            Ok(bp_id)
        } else {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "no free dr"));
        }
    }

    pub fn add_catch_syscall(
        &mut self,
        syscall: Option<i64>,
    ) -> Result<StopPointId, std::io::Error> {
        self.breakpoints.add_syscall_catch(syscall)
    }

    pub fn add_watchpoint(
        &mut self,
        addr: usize,
        size: usize,
        mode: WatchMode,
    ) -> Result<StopPointId, std::io::Error> {
        if let Some(id) = self.take_free_dr() {
            let bp_id = self.breakpoints.add_watchpoint(addr, size, mode)?;
            self.breakpoints
                .enable(&mut self.process, bp_id, Some(id))?;
            Ok(bp_id)
        } else {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "no free dr"));
        }
    }

    pub fn remove_breakpoint(&mut self, id: StopPointId) -> Result<(), std::io::Error> {
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
            StopReason::Other(WaitStatus::Stopped(_, nix::sys::signal::Signal::SIGTRAP))
        ),);
        assert_eq!(debugger.get_pc().unwrap(), load_addr + 1);

        let status = debugger.resume().unwrap();

        let mut output = String::new();
        std::io::Read::read_to_string(&mut rx, &mut output).unwrap();
        assert_eq!(output, "Hello, World!\n");

        assert!(matches!(
            status,
            StopReason::Other(WaitStatus::Exited(_, 0))
        ),);
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

        assert!(matches!(
            status,
            StopReason::Other(WaitStatus::Exited(_, 0))
        ),);
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
        assert_eq!(
            debugger.breakpoints().next().unwrap().1.addr(),
            Some(load_addr)
        );

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

    #[test]
    fn test_hw_breakpoint() {
        let anti_debugger = crate::test::compile("tests/anti_debugger.cpp");
        let (mut rx, tx) = std::io::pipe().unwrap();
        let mut command = Command::new(anti_debugger.as_os_str());
        unsafe {
            command.pre_exec(move || {
                libc::close(libc::STDOUT_FILENO);
                libc::dup2(tx.as_raw_fd(), libc::STDOUT_FILENO);
                Ok(())
            });
        }

        let process = Process::spawn(command).unwrap();
        let mut debugger = Debugger::new(process);

        dbg!(debugger.resume().unwrap());

        let mut addr = [0u8; 8];
        rx.read_exact(&mut addr).unwrap();
        let addr = usize::from_le_bytes(addr);

        // Test sw breakpoint is detected
        let bp_id = debugger.add_breakpoint_software(addr).unwrap();
        dbg!(debugger.resume().unwrap());

        let expected = b"Putting pepperoni on pizza...\n";
        let mut buf = vec![0u8; expected.len()];
        rx.read_exact(&mut buf).unwrap();
        assert_eq!(buf.as_slice(), expected);

        debugger.remove_breakpoint(bp_id).unwrap();

        // Test hw breakpoint isn't detected
        debugger.add_breakpoint_hardware(addr).unwrap();
        dbg!(debugger.resume().unwrap());
        dbg!(debugger.resume().unwrap());
        let expected = b"Putting pineapple on pizza...\n";
        let mut buf = vec![0u8; expected.len()];
        rx.read_exact(&mut buf).unwrap();
        assert_eq!(buf.as_slice(), expected);
    }

    #[test]
    fn test_watchpoint() {
        let watchpoint = crate::test::compile("tests/anti_debugger.cpp");
        let (mut rx, tx) = std::io::pipe().unwrap();
        let mut command = Command::new(watchpoint.as_os_str());
        unsafe {
            command.pre_exec(move || {
                libc::close(libc::STDOUT_FILENO);
                libc::dup2(tx.as_raw_fd(), libc::STDOUT_FILENO);
                Ok(())
            });
        }

        let process = Process::spawn(command).unwrap();
        let mut debugger = Debugger::new(process);
        dbg!(debugger.resume().unwrap());

        let mut addr = [0u8; 8];
        rx.read_exact(&mut addr).unwrap();
        let addr = usize::from_le_bytes(addr);
        debugger
            .add_watchpoint(addr, 1, WatchMode::ReadWrite)
            .unwrap();

        dbg!(debugger.resume().unwrap());
        dbg!(debugger.resume().unwrap());
        let expected = b"Putting pineapple on pizza...\n";
        let mut buf = vec![0u8; expected.len()];
        rx.read_exact(&mut buf).unwrap();
        assert_eq!(buf.as_slice(), expected);
    }
}
