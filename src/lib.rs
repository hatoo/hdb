pub mod debugger;
pub mod process;
pub mod register;

#[cfg(test)]
mod test {
    pub fn compile<P: AsRef<std::path::Path>>(path: P) -> tempfile::TempPath {
        let output = tempfile::NamedTempFile::new().unwrap().into_temp_path();

        assert_eq!(
            std::process::Command::new("gcc")
                .arg(path.as_ref())
                .arg("-pie")
                .arg("-O0")
                .arg("-g")
                .arg("-o")
                .arg(&output)
                .status()
                .unwrap(),
            std::process::ExitStatus::default()
        );

        output
    }
}
