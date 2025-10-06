pub struct Debugger {
    process: crate::process::Process,
    breakpoints: Vec<BreakPoint>,
}

pub struct BreakPoint {
    addr: usize,
    orig_byte: u8,
}

impl Debugger {
    pub fn new(process: crate::process::Process) -> Self {
        Self {
            process,
            breakpoints: Vec::new(),
        }
    }

    /// Do not call syscalls with this pid for thread safety.
    /// You should use other methods of this struct.
    pub unsafe fn raw_pid(&self) -> i32 {
        unsafe { self.process.raw_pid() }
    }

    pub fn cont(&mut self) -> Result<nix::sys::wait::WaitStatus, std::io::Error> {
        self.process.resume()?;
        let status = self.process.wait_on_signal()?;

        if let nix::sys::wait::WaitStatus::Stopped(_, nix::sys::signal::Signal::SIGTRAP) = status {
            // Hit a breakpoint
            // Restore original byte at the breakpoint
            let pc = self.get_pc()? - 1;
            if let Some(breakpoint) = self.breakpoints.iter().find(|bp| bp.addr == pc) {
                let orig_data = self.process.read(pc)?;
                let restored_data = (orig_data & !0xff) | (breakpoint.orig_byte as i64);
                self.process.write(pc, restored_data)?;
                // Move instruction pointer back to the original instruction
                self.set_pc(pc)?;
            }
        }

        Ok(status)
    }

    pub fn get_pc(&mut self) -> Result<usize, std::io::Error> {
        // TODO: Handle non-x86_64 architectures
        let rip = self.read_register("rip")?.unwrap().as_usize();
        Ok(rip)
    }

    pub fn set_pc(&mut self, pc: usize) -> Result<(), std::io::Error> {
        // TODO: Handle non-x86_64 architectures
        self.write_register("rip", crate::register::RegisterValue::U64(pc as u64))?;
        Ok(())
    }

    pub fn read_register(
        &mut self,
        name: &str,
    ) -> Result<Option<crate::register::RegisterValue>, std::io::Error> {
        let regs = self.process.read_registers()?;
        Ok(regs.read_by_name(name))
    }

    pub fn write_register(
        &mut self,
        name: &str,
        value: crate::register::RegisterValue,
    ) -> Result<(), std::io::Error> {
        let mut regs = self.process.read_registers()?;
        regs.write_by_name(name, value).unwrap();
        self.process.write_registers(&regs)?;

        Ok(())
    }

    pub fn set_breakpoint(&mut self, addr: usize) -> Result<(), std::io::Error> {
        if self
            .breakpoints
            .iter()
            .any(|breakpoint| breakpoint.addr == addr)
        {
            return Ok(());
        }

        let orig_data = self.process.read(addr)?;
        let orig_byte = (orig_data & 0xff) as u8;
        let int3_data = (orig_data & !0xff) | 0xcc;
        self.process.write(addr, int3_data)?;

        self.breakpoints.push(BreakPoint { addr, orig_byte });

        Ok(())
    }
}
