pub struct Debugger {
    process: crate::process::Process,
}

impl Debugger {
    pub fn new(process: crate::process::Process) -> Self {
        Self { process }
    }

    pub fn cont(&mut self) -> Result<(), std::io::Error> {
        self.process.resume()?;
        self.process.wait_on_signal()?;

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
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut regs = self.process.read_registers()?;
        regs.write_by_name(name, value)?;
        self.process.write_registers(&regs)?;

        Ok(())
    }
}
