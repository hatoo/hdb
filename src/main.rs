use clap::Parser;

mod process;

#[derive(Parser, Debug)]
struct Opt {
    commands: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    let mut commands = opt.commands.iter();
    let mut command = std::process::Command::new(commands.next().unwrap());
    command.args(commands);

    let mut process = process::Process::spawn(command)?;

    process.wait()?;

    Ok(())
}
