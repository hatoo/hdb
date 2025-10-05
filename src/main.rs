use clap::{Parser, Subcommand};
use rustyline::DefaultEditor;

mod process;
mod register;

#[derive(Parser, Debug)]
struct Opt {
    commands: Vec<String>,
}

#[derive(Parser, Debug)]
#[clap(infer_subcommands = true, override_usage = "<COMMAND>")]
struct UserInput {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Continue,
}

fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    let mut commands = opt.commands.iter();
    let mut command = std::process::Command::new(commands.next().unwrap());
    command.args(commands);

    let mut process = process::Process::spawn(command)?;

    let mut rl = DefaultEditor::new()?;
    loop {
        let line = rl.readline(">> ")?;

        if line.trim().is_empty() {
            continue;
        }

        let cmd = {
            let mut cmd: Vec<_> = line.trim().split_whitespace().collect();
            cmd.insert(0, "input");
            cmd
        };

        match UserInput::try_parse_from(cmd) {
            Ok(UserInput {
                command: Commands::Continue,
            }) => {
                process.resume()?;
                process.wait_on_signal()?;
            }
            Err(e) => {
                e.print()?;
            }
        }
    }
}
