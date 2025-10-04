use std::{ffi::c_void, os::unix::process::CommandExt, process::Command};

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
            let _ = self.wait();
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
            let _ = self.wait();
        }
    }
}

impl Process {
    pub fn spawn(mut command: Command) -> Result<Process, std::io::Error> {
        let pid = unsafe { libc::fork() };

        if pid < 0 {
            // Fork failed
            let err = std::io::Error::last_os_error();
            return Err(err);
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
        proc.wait()?;
        Ok(proc)
    }

    pub fn wait(&mut self) -> Result<(), std::io::Error> {
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
}
