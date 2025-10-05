use clap::{Parser, Subcommand};

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
    Write {
        #[clap(value_parser=clap::builder::PossibleValuesParser::new(REGISTERS.iter().map(|r| r.name)))]
        name: String,
        value: String,
    },
}

fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    let mut commands = opt.commands.iter();
    let mut command = std::process::Command::new(commands.next().unwrap());
    command.args(commands);

    let prompt = reedline::DefaultPrompt::default();
    let mut rl = reedline::Reedline::create();

    let mut process = process::Process::spawn(command, move || Ok(()))?;

    loop {
        let line = rl.read_line(&prompt)?;

        let line = match line {
            reedline::Signal::Success(input) => input,
            reedline::Signal::CtrlC | reedline::Signal::CtrlD => {
                // println!("Exiting...");
                break;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        let cmd = {
            let mut cmd: Vec<_> = line.trim().split_whitespace().collect();
            cmd.insert(0, "input");
            cmd
        };

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
                Commands::Write { name, value } => {
                    let mut regs = process.read_registers()?;
                    let reg_info = REGISTERS.iter().find(|r| r.name == name).unwrap();
                    let reg_value = match reg_info.size {
                        1 => register::RegisterValue::U8(value.parse()?),
                        8 => register::RegisterValue::U64(value.parse()?),
                        16 => register::RegisterValue::U128(value.parse()?),
                        _ => unreachable!(),
                    };
                    regs.write_by_name(&name, reg_value)?;
                    process.write_registers(&regs)?;
                }
            },
            Err(e) => {
                e.print()?;
            }
        }
    }

    Ok(())
}
