use clap::{Parser, Subcommand};

use crate::register::REGISTERS;

mod debugger;
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
    Step {
        #[clap(default_value_t = 1)]
        count: usize,
    },
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
    BreakPoint {
        #[command(subcommand)]
        command: BreakPointCommands,
    },
}

#[derive(Subcommand, Debug)]
enum BreakPointCommands {
    Set { addr: String },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::parse();

    let mut commands = opt.commands.iter();
    let mut command = std::process::Command::new(commands.next().unwrap());
    command.args(commands);

    let prompt = reedline::DefaultPrompt::default();
    let mut rl = reedline::Reedline::create();

    let process = process::Process::spawn(command)?;
    let mut debugger = debugger::Debugger::new(process);

    println!("Process started. PID = {}", unsafe { debugger.raw_pid() });

    loop {
        let line = rl.read_line(&prompt)?;

        let line = match line {
            reedline::Signal::Success(input) => input,
            reedline::Signal::CtrlC | reedline::Signal::CtrlD => {
                break;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        let cmd = {
            let mut cmd: Vec<_> = line.split_whitespace().collect();
            cmd.insert(0, "input");
            cmd
        };

        match UserInput::try_parse_from(cmd) {
            Ok(input) => match input.command {
                Commands::Step { count } => {
                    for _ in 0..count {
                        // println!("{:?}", debugger.step()?);
                        // println!("PC = {:#x}", debugger.get_pc()?);
                        debugger.step()?;
                    }
                }
                Commands::Continue => {
                    println!("{:?}", debugger.cont()?);
                }
                Commands::Read { name } => {
                    let info = REGISTERS.iter().find(|r| r.name == name).unwrap();
                    let value = debugger.read_register(info)?;
                    println!("{:?}", value);
                }
                Commands::Write { name, value } => {
                    let reg_info = REGISTERS.iter().find(|r| r.name == name).unwrap();
                    let reg_value = match reg_info.size {
                        1 => register::RegisterValue::U8(parse_int::parse(&value)?),
                        8 => register::RegisterValue::U64(parse_int::parse(&value)?),
                        16 => register::RegisterValue::U128(parse_int::parse(&value)?),
                        _ => unreachable!(),
                    };

                    debugger.write_register(reg_info, reg_value)?;
                }
                Commands::BreakPoint { command } => match command {
                    BreakPointCommands::Set { addr } => {
                        let addr = parse_int::parse::<usize>(&addr)?;
                        debugger.set_breakpoint(addr)?;
                    }
                },
            },
            Err(e) => {
                e.print()?;
            }
        }
    }

    Ok(())
}
