use core::panic;
use std::{ffi::c_void, os::unix::process::CommandExt, process::Command};

use crate::register::Registers;

pub struct Process {
    pid: i32,
    state: ProcessState,
    terminate_on_drop: bool,
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
        if self.state == ProcessState::Running {
            unsafe { libc::kill(self.pid, libc::SIGSTOP) };
            self.state = ProcessState::Stopped;
            let _ = self.wait_on_signal();
        }
        unsafe {
            libc::ptrace(
                libc::PTRACE_DETACH,
                self.pid,
                std::ptr::null() as *const c_void,
                std::ptr::null() as *const c_void,
            );
            libc::kill(self.pid, libc::SIGCONT);
        }

        if self.terminate_on_drop {
            let _ = unsafe { libc::kill(self.pid, libc::SIGKILL) };
            let _ = self.wait_on_signal();
        }
    }
}

impl Process {
    pub fn spawn(mut command: Command) -> Result<Process, std::io::Error> {
        let pid = unsafe { libc::fork() };

        if pid < 0 {
            // Fork failed
            let err = std::io::Error::last_os_error();
            panic!("{}", err);
        }

        if pid == 0 {
            // In child process
            if unsafe {
                libc::ptrace(
                    libc::PTRACE_TRACEME,
                    0,
                    std::ptr::null() as *const c_void,
                    std::ptr::null() as *const c_void,
                )
            } < 0
            {
                panic!("{}", std::io::Error::last_os_error());
            }
            unreachable!("{}", command.exec());
        }

        // In parent process
        let mut proc = Process {
            pid,
            state: ProcessState::Stopped,
            terminate_on_drop: true,
        };
        proc.wait_on_signal()?;
        Ok(proc)
    }

    pub fn wait_on_signal(&mut self) -> Result<(), std::io::Error> {
        let pid = self.pid;
        let mut status: i32 = 0;

        let ret = unsafe { libc::waitpid(pid, &mut status as *mut i32, 0) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        // TODO: revisit this logic. This is from AI.
        self.state = if libc::WIFEXITED(status) {
            ProcessState::Exited
        } else if libc::WIFSIGNALED(status) {
            ProcessState::Terminated
        } else if libc::WIFSTOPPED(status) {
            ProcessState::Stopped
        } else {
            panic!("Unknown waitpid status: {status}");
        };

        Ok(())
    }

    pub fn resume(&mut self) -> Result<(), std::io::Error> {
        let pid = self.pid;

        if unsafe {
            libc::ptrace(
                libc::PTRACE_CONT,
                pid,
                std::ptr::null() as *const c_void,
                std::ptr::null() as *const c_void,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        self.state = ProcessState::Running;
        Ok(())
    }

    pub fn read_registers(&mut self) -> Result<Registers, std::io::Error> {
        #[cfg(target_arch = "x86_64")]
        {
            let mut user: libc::user = unsafe { std::mem::zeroed() };

            if unsafe {
                libc::ptrace(
                    libc::PTRACE_GETREGS,
                    self.pid,
                    std::ptr::null() as *const c_void,
                    &mut user.regs as *mut _ as *mut c_void,
                )
            } < 0
            {
                return Err(std::io::Error::last_os_error());
            }

            if unsafe {
                libc::ptrace(
                    libc::PTRACE_GETFPREGS,
                    self.pid,
                    std::ptr::null() as *const c_void,
                    &mut user.i387 as *mut _ as *mut c_void,
                )
            } < 0
            {
                return Err(std::io::Error::last_os_error());
            }

            for i in 0..8 {
                let data = unsafe {
                    libc::ptrace(
                        libc::PTRACE_PEEKUSER,
                        self.pid,
                        std::mem::offset_of!(libc::user, u_debugreg).wrapping_add(i * 8)
                            as *const c_void,
                        std::ptr::null() as *const c_void,
                    )
                };

                if std::io::Error::last_os_error().raw_os_error().unwrap_or(0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                user.u_debugreg[i] = i64::cast_unsigned(data);
            }

            return Ok(Registers { user });
        }

        todo!()
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

        return;
    }
}
