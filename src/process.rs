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

    pub fn get_registers(&self) -> Result<libc::user_regs_struct, std::io::Error> {
        let mut regs = libc::user_regs_struct {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbp: 0,
            rbx: 0,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            orig_rax: 0,
            rip: 0,
            cs: 0,
            eflags: 0,
            rsp: 0,
            ss: 0,
            fs_base: 0,
            gs_base: 0,
            ds: 0,
            es: 0,
            fs: 0,
            gs: 0,
        };

        if unsafe {
            libc::ptrace(
                libc::PTRACE_GETREGS,
                self.pid,
                std::ptr::null() as *const c_void,
                &mut regs as *mut libc::user_regs_struct as *mut c_void,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error());
        }

        Ok(regs)
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
        let regs = process.get_registers().unwrap();
        assert_eq!(regs.r13, 0xcafecafe);

        process.resume().unwrap();
    }
}
