pub mod breakpoint;
pub mod debugger;
pub mod process;
pub mod register;
pub mod stop_reason;

#[cfg(test)]
mod test {
    pub fn compile<P: AsRef<std::path::Path>>(path: P) -> tempfile::TempPath {
        let output = tempfile::NamedTempFile::new().unwrap().into_temp_path();

        assert_eq!(
            std::process::Command::new("g++")
                .arg(path.as_ref())
                .arg("-pie")
                .arg("-O0")
                .arg("-g")
                .arg("-o")
                .arg(&output)
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap(),
            std::process::ExitStatus::default()
        );

        output
    }
}
