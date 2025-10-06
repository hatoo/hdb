use core::panic;
use std::{ffi::c_void, os::unix::process::CommandExt, process::Command};

use crate::register::Registers;

pub struct Process {
    /// The child process, if we spawned it ourselves.
    /// None if we attached to an existing process.
    child: Option<std::process::Child>,
    pid: i32,
    state: ProcessState,
}

#[derive(PartialEq, Eq, Debug)]
pub enum ProcessState {
    Running,
    Stopped,
    Exited,
    Terminated,
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
            state: ProcessState::Stopped,
        };
        proc.wait_on_signal()?;
        Ok(proc)
    }

    pub fn attach(pid: i32) -> Result<Process, std::io::Error> {
        nix::sys::ptrace::attach(nix::unistd::Pid::from_raw(pid))?;

        let mut proc = Process {
            child: None,
            pid,
            state: ProcessState::Stopped,
        };
        proc.wait_on_signal()?;
        Ok(proc)
    }

    pub fn wait_on_signal(&mut self) -> Result<nix::sys::wait::WaitStatus, std::io::Error> {
        let status = nix::sys::wait::waitpid(self.pid(), None)?;

        // TODO: revisit this logic. This is from AI.
        self.state = match status {
            nix::sys::wait::WaitStatus::Exited(_, _)
            | nix::sys::wait::WaitStatus::Signaled(_, _, _) => ProcessState::Exited,
            nix::sys::wait::WaitStatus::Stopped(_, _) => ProcessState::Stopped,
            nix::sys::wait::WaitStatus::Continued(_) => ProcessState::Running,
            _ => panic!("Unexpected wait status: {:?}", status),
        };

        Ok(status)
    }

    pub fn resume(&mut self) -> Result<(), std::io::Error> {
        nix::sys::ptrace::cont(self.pid(), None)?;
        self.state = ProcessState::Running;

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

    #[cfg(test)]
    fn stat(&self) -> char {
        let path = format!("/proc/{}/stat", self.pid);

        std::fs::read_to_string(path)
            .unwrap()
            .split_whitespace()
            .nth(2)
            .unwrap()
            .chars()
            .next()
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;

    use crate::register::RegisterValue;

    use super::*;

    #[test]
    fn test_resume() {
        let mut command = Command::new("sleep");
        command.arg("10");

        let mut process = Process::spawn(command).unwrap();
        process.resume().unwrap();

        assert!(matches!(process.stat(), 'S' | 'R'));
    }

    #[test]
    fn test_resume_already_terminated() {
        let command = Command::new("true");

        let mut process = Process::spawn(command).unwrap();
        process.resume().unwrap();
        process.wait_on_signal().unwrap();

        assert!(process.resume().is_err());
    }

    #[test]
    fn test_reg_read() {
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path().join("reg_read");

        let mut command = Command::new("gcc");
        command.arg("-o").arg(&temp_path).arg("tests/reg_read.s");
        command.stderr(std::process::Stdio::null());

        command.spawn().unwrap().wait().unwrap();

        let mut process = Process::spawn(Command::new(&temp_path)).unwrap();

        process.resume().unwrap();
        process.wait_on_signal().unwrap();
        assert_eq!(
            process.read_registers().unwrap().read_by_name("r13"),
            Some(RegisterValue::U64(0xcafecafe))
        );

        process.resume().unwrap();
        process.wait_on_signal().unwrap();
        assert_eq!(
            process.read_registers().unwrap().read_by_name("r13b"),
            Some(RegisterValue::U8(42))
        );

        process.resume().unwrap();
        process.wait_on_signal().unwrap();
        assert_eq!(
            process.read_registers().unwrap().read_by_name("xmm0"),
            Some(RegisterValue::U64(0xba5eba11))
        );

        process.resume().unwrap();
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
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path().join("reg_write");
        let mut command = Command::new("gcc");
        command.arg("-o").arg(&temp_path).arg("tests/reg_write.s");
        command.stderr(std::process::Stdio::null());
        command.spawn().unwrap().wait().unwrap();

        let (rx, tx) = std::io::pipe().unwrap();
        let mut command = Command::new(&temp_path);
        unsafe {
            command.pre_exec(move || {
                libc::close(libc::STDOUT_FILENO);
                libc::dup2(tx.as_raw_fd(), libc::STDOUT_FILENO);
                Ok(())
            })
        };
        let mut process = Process::spawn(command).unwrap();

        process.resume().unwrap();
        process.wait_on_signal().unwrap();

        let mut regs = process.read_registers().unwrap();
        regs.write_by_name("rsi", RegisterValue::U64(0xcafecafe))
            .unwrap();
        process.write_registers(&regs).unwrap();

        process.resume().unwrap();
        process.wait_on_signal().unwrap();
        let mut buf = [0u8; 80];
        let len = unsafe { libc::read(rx.as_raw_fd(), buf.as_mut_ptr() as *mut c_void, 80) };
        let output = std::str::from_utf8(&buf[..len as usize]).unwrap();
        assert_eq!(output, "0xcafecafe");
    }
}
