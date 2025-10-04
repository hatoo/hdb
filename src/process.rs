use std::{os::unix::process::CommandExt, process::Command};

pub struct Process {
    pid: i32,
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
                    std::ptr::null() as *const i32,
                    std::ptr::null() as *const i32,
                )
            } < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            return Err(command.exec());
        }

        Ok(Process { pid })
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
}
