use crate::{process::Process, register::RegisterInfo};

pub struct Debugger {
    process: crate::process::Process,
    breakpoints: BreakPoints,
}

pub struct BreakPoint {
    addr: usize,
    orig_byte: u8,
}

#[cfg(target_arch = "x86_64")]
impl BreakPoint {
    pub fn new(process: &mut Process, addr: usize) -> Result<Self, std::io::Error> {
        let orig_data = process.read(addr)?;
        let orig_byte = (orig_data & 0xff) as u8;
        let int3_data = (orig_data & !0xff) | 0xcc;
        process.write(addr, int3_data)?;

        Ok(Self { addr, orig_byte })
    }

    pub fn enable(&mut self, process: &mut Process) -> Result<(), std::io::Error> {
        let orig_data = process.read(self.addr)?;
        let int3_data = (orig_data & !0xff) | 0xcc;
        self.orig_byte = (orig_data & 0xff) as u8;
        process.write(self.addr, int3_data)?;
        Ok(())
    }

    pub fn disable(&self, process: &mut Process) -> Result<(), std::io::Error> {
        let orig_data = process.read(self.addr)?;
        let restored_data = (orig_data & !0xff) | (self.orig_byte as i64);
        process.write(self.addr, restored_data)?;
        Ok(())
    }
}

pub struct BreakPoints {
    points: Vec<BreakPoint>,
}

impl BreakPoints {
    pub fn new() -> Self {
        Self { points: Vec::new() }
    }

    pub fn add(&mut self, process: &mut Process, addr: usize) -> Result<(), std::io::Error> {
        if self.points.iter().any(|bp| bp.addr == addr) {
            return Ok(());
        }

        self.points.push(BreakPoint::new(process, addr)?);
        Ok(())
    }

    pub fn break_point_at(&mut self, addr: usize) -> Option<&mut BreakPoint> {
        self.points.iter_mut().find(|bp| bp.addr == addr)
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

    pub fn cont(&mut self) -> Result<nix::sys::wait::WaitStatus, std::io::Error> {
        {
            let pc = self.get_pc()?;
            if let Some(breakpoint) = self.breakpoints.break_point_at(pc) {
                self.process.single_step()?;
                breakpoint.enable(&mut self.process)?;
            }
        }

        self.process.resume()?;
        let status = self.process.wait_on_signal()?;

        if let nix::sys::wait::WaitStatus::Stopped(_, nix::sys::signal::Signal::SIGTRAP) = status {
            let pc = self.get_pc()? - 1;
            if let Some(breakpoint) = self.breakpoints.break_point_at(pc) {
                breakpoint.disable(&mut self.process)?;
                self.set_pc(pc)?;
            }
        }

        Ok(status)
    }

    pub fn get_pc(&mut self) -> Result<usize, std::io::Error> {
        // TODO: Handle non-x86_64 architectures
        let rip = self.read_register(&crate::register::PC)?.as_usize();
        Ok(rip)
    }

    pub fn set_pc(&mut self, pc: usize) -> Result<(), std::io::Error> {
        // TODO: Handle non-x86_64 architectures
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

    pub fn set_breakpoint(&mut self, addr: usize) -> Result<(), std::io::Error> {
        self.breakpoints.add(&mut self.process, addr)?;
        Ok(())
    }
}
