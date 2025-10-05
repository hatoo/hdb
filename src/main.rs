use clap::{Parser, Subcommand};
use rustyline::DefaultEditor;

use crate::register::REGISTERS;

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
    Read {
        #[clap(value_parser=clap::builder::PossibleValuesParser::new(REGISTERS.iter().map(|r| r.name)))]
        name: String,
    },
}

fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    let mut commands = opt.commands.iter();
    let mut command = std::process::Command::new(commands.next().unwrap());
    command.args(commands);

    let mut process = process::Process::spawn(command, None)?;

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

        let _ = rl.add_history_entry(&line);
        match UserInput::try_parse_from(cmd) {
            Ok(input) => match input.command {
                Commands::Continue => {
                    process.resume()?;
                    process.wait_on_signal()?;
                }
                Commands::Read { name } => {
                    let regs = process.read_registers()?;
                    if let Some(value) = regs.read_by_name(&name) {
                        println!("{name} = {value:?}");
                    } else {
                        println!("Unknown register: {name}");
                    }
                }
            },
            Err(e) => {
                e.print()?;
            }
        }
    }
}
