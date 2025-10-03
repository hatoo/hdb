use std::{
    os::unix::process::CommandExt,
    process::Command,
    sync::{LockResult, Mutex, MutexGuard},
};

pub struct ProcessInner {
    pid: i32,
}

pub struct Process {
    inner: Mutex<ProcessInner>,
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

    pub fn lock(&self) -> LockResult<MutexGuard<'_, ProcessInner>> {
        self.inner.lock()
    }
}

impl ProcessInner {
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
