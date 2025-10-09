use std::{ffi::c_void, os::unix::process::CommandExt, process::Command};

use nix::sys::uio::RemoteIoVec;

use crate::register::Registers;

pub struct Process {
    /// The child process, if we spawned it ourselves.
    /// None if we attached to an existing process.
    child: Option<std::process::Child>,
    pid: i32,
}

impl Drop for Process {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
        }
    }
}

impl Process {
    fn pid(&self) -> nix::unistd::Pid {
        nix::unistd::Pid::from_raw(self.pid)
    }

    /// Do not call syscalls with this pid for thread safety.
    /// You should use other methods of this struct.
    pub unsafe fn raw_pid(&self) -> i32 {
        self.pid
    }

    pub fn spawn(mut command: Command) -> Result<Process, std::io::Error> {
        unsafe {
            command.pre_exec(move || {
                // Disable ASLR for the child process
                nix::sys::personality::set(nix::sys::personality::Persona::ADDR_NO_RANDOMIZE)?;

                // Signal on execve
                nix::sys::ptrace::traceme()?;
                Ok(())
            })
        };

        let child = command.spawn()?;

        let pid = child.id() as i32;

        // In parent process
        let mut proc = Process {
            child: Some(child),
            pid,
        };
        proc.wait_on_signal()?;
        Ok(proc)
    }

    pub fn attach(pid: i32) -> Result<Process, std::io::Error> {
        nix::sys::ptrace::attach(nix::unistd::Pid::from_raw(pid))?;

        let mut proc = Process { child: None, pid };
        proc.wait_on_signal()?;
        Ok(proc)
    }

    fn wait_on_signal(&mut self) -> Result<nix::sys::wait::WaitStatus, std::io::Error> {
        let status = nix::sys::wait::waitpid(self.pid(), None)?;
        Ok(status)
    }

    pub fn resume(&mut self) -> Result<nix::sys::wait::WaitStatus, std::io::Error> {
        nix::sys::ptrace::cont(self.pid(), None)?;
        let status = self.wait_on_signal()?;
        Ok(status)
    }

    pub fn cont(&mut self) -> Result<(), std::io::Error> {
        nix::sys::ptrace::cont(self.pid(), None)?;
        Ok(())
    }

    pub fn read_registers(&mut self) -> Result<Registers, std::io::Error> {
        #[cfg(target_arch = "x86_64")]
        {
            let mut user: libc::user = unsafe { std::mem::zeroed() };

            user.regs =
                nix::sys::ptrace::getregset::<nix::sys::ptrace::regset::NT_PRSTATUS>(self.pid())?;
            user.i387 =
                nix::sys::ptrace::getregset::<nix::sys::ptrace::regset::NT_PRFPREG>(self.pid())?;

            for i in 0..8 {
                let data = nix::sys::ptrace::read_user(
                    self.pid(),
                    (std::mem::offset_of!(libc::user, u_debugreg) + i * 8) as *mut c_void,
                )?;

                user.u_debugreg[i] = i64::cast_unsigned(data);
            }

            return Ok(Registers { user });
        }

        #[cfg(not(target_arch = "x86_64"))]
        todo!()
    }

    pub fn write_registers(&mut self, regs: &Registers) -> Result<(), std::io::Error> {
        #[cfg(target_arch = "x86_64")]
        {
            nix::sys::ptrace::setregset::<nix::sys::ptrace::regset::NT_PRSTATUS>(
                self.pid(),
                regs.user.regs,
            )?;

            nix::sys::ptrace::setregset::<nix::sys::ptrace::regset::NT_PRFPREG>(
                self.pid(),
                regs.user.i387,
            )?;

            /*
            for i in 0..8 {
                if unsafe {
                    libc::ptrace(
                        libc::PTRACE_POKEUSER,
                        self.pid,
                        std::mem::offset_of!(libc::user, u_debugreg).wrapping_add(i * 8)
                            as *const c_void,
                        regs.user.u_debugreg[i] as *const c_void,
                    )
                } < 0
                {
                    eprint!(
                        "Failed to set debugreg: {}",
                        std::io::Error::last_os_error()
                    );
                    return Err(std::io::Error::last_os_error());
                }
            }
            */

            return Ok(());
        }

        #[cfg(not(target_arch = "x86_64"))]
        todo!()
    }

    pub fn read(&mut self, addr: usize) -> Result<i64, std::io::Error> {
        let data = nix::sys::ptrace::read(self.pid(), addr as *mut c_void)?;
        Ok(data)
    }

    pub fn write(&mut self, addr: usize, data: i64) -> Result<(), std::io::Error> {
        nix::sys::ptrace::write(self.pid(), addr as *mut c_void, data as _)?;
        Ok(())
    }

    pub fn single_step(&mut self) -> Result<nix::sys::wait::WaitStatus, std::io::Error> {
        nix::sys::ptrace::step(self.pid(), None)?;
        let status = self.wait_on_signal()?;
        Ok(status)
    }

    pub fn read_at(&mut self, addr: usize, len: usize) -> Result<Vec<u8>, std::io::Error> {
        let mut buf = Vec::with_capacity(len);

        let local_iov = std::io::IoSliceMut::new(unsafe {
            std::slice::from_raw_parts_mut(buf.as_mut_ptr(), len)
        });

        let mut remote_iovs: Vec<RemoteIoVec> = Vec::new();

        // Split into 4KiB page boundaries
        let mut current_addr = addr;
        while (addr + len) > current_addr {
            let left = (addr + len) - current_addr;
            let page_offset = current_addr % 4096;
            let to_read = std::cmp::min(left, 4096 - page_offset);

            let remote_iov = RemoteIoVec {
                base: current_addr,
                len: to_read,
            };
            remote_iovs.push(remote_iov);

            current_addr += to_read;
        }
        let nread = nix::sys::uio::process_vm_readv(self.pid(), &mut [local_iov], &remote_iovs)?;
        unsafe {
            buf.set_len(nread);
        }

        Ok(buf)
    }

    pub fn write_at(&mut self, addr: usize, buf: &[u8]) -> Result<usize, std::io::Error> {
        // use ptrace_pokedata to write protected memory
        let mut written = 0;

        if addr % 8 != 0 {
            let aligned_addr = addr - (addr % 8);
            let existing_data = nix::sys::ptrace::read(self.pid(), aligned_addr as *mut c_void)?;
            let mut data = existing_data.to_ne_bytes();
            let offset = addr % 8;
            let to_write = std::cmp::min(8 - offset, buf.len());
            data[offset..offset + to_write].copy_from_slice(&buf[..to_write]);
            let data = i64::from_ne_bytes(data);
            nix::sys::ptrace::write(self.pid(), aligned_addr as *mut c_void, data as _)?;
            written += to_write;
        }

        while written < buf.len() {
            let remaining = buf.len() - written;

            if remaining >= 8 {
                let mut data = [0u8; 8];
                data.copy_from_slice(&buf[written..written + 8]);
                let data = i64::from_ne_bytes(data);
                nix::sys::ptrace::write(self.pid(), (addr + written) as *mut c_void, data as _)?;
                written += 8;
            } else {
                // Read the existing data
                let existing_data =
                    nix::sys::ptrace::read(self.pid(), (addr + written) as *mut c_void)?;
                let mut data = existing_data.to_ne_bytes();
                data[..remaining].copy_from_slice(&buf[written..]);
                let data = i64::from_ne_bytes(data);
                nix::sys::ptrace::write(self.pid(), (addr + written) as *mut c_void, data as _)?;
                written += remaining;
            }
        }
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;

    use crate::{register::RegisterValue, test::compile};

    use super::*;

    fn stat(process: &Process) -> char {
        let path = format!("/proc/{}/stat", process.pid());

        std::fs::read_to_string(path)
            .unwrap()
            .split_whitespace()
            .nth(2)
            .unwrap()
            .chars()
            .next()
            .unwrap()
    }

    fn read_reg_by_name(regs: &Registers, name: &str) -> RegisterValue {
        let reg = crate::register::REGISTERS
            .iter()
            .find(|r| r.name == name)
            .unwrap();
        regs.read(reg)
    }

    fn write_reg_by_name(regs: &mut Registers, name: &str, value: RegisterValue) {
        let reg = crate::register::REGISTERS
            .iter()
            .find(|r| r.name == name)
            .unwrap();
        regs.write(reg, value);
    }

    #[test]
    fn test_resume() {
        let mut command = Command::new("sleep");
        command.arg("10");

        let mut process = Process::spawn(command).unwrap();
        process.cont().unwrap();

        assert!(matches!(stat(&process), 'S' | 'R'));
    }

    #[test]
    fn test_resume_already_terminated() {
        let command = Command::new("true");

        let mut process = Process::spawn(command).unwrap();
        process.cont().unwrap();
        process.wait_on_signal().unwrap();

        assert!(process.cont().is_err());
    }

    #[test]
    fn test_reg_read() {
        let reg_read = compile("tests/reg_read.s");
        let mut process = Process::spawn(Command::new(&reg_read)).unwrap();

        process.cont().unwrap();
        process.wait_on_signal().unwrap();
        assert_eq!(
            read_reg_by_name(&process.read_registers().unwrap(), "r13"),
            RegisterValue::U64(0xcafecafe)
        );

        process.cont().unwrap();
        process.wait_on_signal().unwrap();
        assert_eq!(
            read_reg_by_name(&process.read_registers().unwrap(), "r13b"),
            RegisterValue::U8(42)
        );

        process.cont().unwrap();
        process.wait_on_signal().unwrap();
        assert_eq!(
            read_reg_by_name(&process.read_registers().unwrap(), "xmm0"),
            RegisterValue::U64(0xba5eba11)
        );

        process.cont().unwrap();
        process.wait_on_signal().unwrap();
        // TODO: find good f128 library
        /*
        assert_eq!(
            process.read_registers().unwrap().read_by_name("st0"),
            Some(RegisterValue::U128(0xba5eba11))
        );
        */
    }

    #[test]
    fn test_reg_write() {
        let reg_write = compile("tests/reg_write.s");

        let (rx, tx) = std::io::pipe().unwrap();
        let mut command = Command::new(&reg_write);
        unsafe {
            command.pre_exec(move || {
                libc::close(libc::STDOUT_FILENO);
                libc::dup2(tx.as_raw_fd(), libc::STDOUT_FILENO);
                Ok(())
            })
        };
        let mut process = Process::spawn(command).unwrap();

        process.cont().unwrap();
        process.wait_on_signal().unwrap();

        let mut regs = process.read_registers().unwrap();
        write_reg_by_name(&mut regs, "rsi", RegisterValue::U64(0xcafecafe));
        process.write_registers(&regs).unwrap();

        process.cont().unwrap();
        process.wait_on_signal().unwrap();
        let mut buf = [0u8; 80];
        let len = unsafe { libc::read(rx.as_raw_fd(), buf.as_mut_ptr() as *mut c_void, 80) };
        let output = std::str::from_utf8(&buf[..len as usize]).unwrap();
        assert_eq!(output, "0xcafecafe");
    }
}
