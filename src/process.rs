use std::{
    os::unix::process::CommandExt,
    process::Command,
    sync::{LockResult, Mutex, PoisonError},
};

struct ProcessInner {
    pid: i32,
}

pub struct Process {
    inner: Mutex<ProcessInner>,
}

pub struct ProcessLock<'a> {
    guard: std::sync::MutexGuard<'a, ProcessInner>,
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
            return Err(command.exec());
        }

        Ok(Process {
            inner: Mutex::new(ProcessInner { pid }),
        })
    }

    pub fn lock(&self) -> LockResult<ProcessLock<'_>> {
        self.inner
            .lock()
            .map(|guard| ProcessLock { guard })
            .map_err(|e| {
                PoisonError::new(ProcessLock {
                    guard: e.into_inner(),
                })
            })
    }
}

impl<'a> ProcessLock<'a> {
    pub fn wait(&self) -> Result<(), std::io::Error> {
        let pid = self.guard.pid;
        let mut status: i32 = 0;

        let ret = unsafe { libc::waitpid(pid, &mut status as *mut i32, 0) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}
