use clap::{Parser, Subcommand};

use hdb::{
    debugger, process,
    register::{REGISTERS, RegisterValue},
};

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
    Register {
        #[command(subcommand)]
        command: RegisterCommands,
    },
    BreakPoint {
        #[command(subcommand)]
        command: BreakPointCommands,
    },
    Memory {
        #[command(subcommand)]
        command: MemoryCommands,
    },
    Disassemble {
        #[clap(value_parser = parse_int::parse::<usize>)]
        addr: Option<usize>,
        #[clap(default_value_t = 16, short = 'c', long = "count")]
        count: usize,
    },
    Quit,
}

#[derive(Subcommand, Debug)]
enum BreakPointCommands {
    #[clap(alias = "set")]
    Add {
        #[clap(value_parser = parse_int::parse::<usize>)]
        addr: usize,
    },
    Remove {
        id: usize,
    },
    List,
}

#[derive(Subcommand, Debug)]
enum RegisterCommands {
    Read {
        #[clap(value_parser=clap::builder::PossibleValuesParser::new(REGISTERS.iter().map(|r| r.name)))]
        name: String,
    },
    Write {
        #[clap(value_parser=clap::builder::PossibleValuesParser::new(REGISTERS.iter().map(|r| r.name)))]
        name: String,
        #[clap(value_parser = parse_int::parse::<u128>)]
        value: u128,
    },
}

#[derive(Subcommand, Debug)]
enum MemoryCommands {
    Read {
        #[clap(value_parser = parse_int::parse::<usize>)]
        addr: usize,
        #[clap(default_value_t = 32)]
        size: usize,
    },

    Write {
        #[clap(value_parser = parse_int::parse::<usize>)]
        addr: usize,
        #[clap(value_parser = parse_int::parse::<u8>)]
        data: Vec<u8>,
    },
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

        let result: Result<bool, Box<dyn std::error::Error>> = (|| {
            match UserInput::try_parse_from(std::iter::once("input").chain(line.split_whitespace()))
            {
                Ok(input) => match input.command {
                    Commands::Step { count } => {
                        for _ in 0..count {
                            // println!("{:?}", debugger.step()?);
                            // println!("PC = {:#x}", debugger.get_pc()?);
                            debugger.step()?;
                        }
                    }
                    Commands::Continue => {
                        println!("{:?}", debugger.resume()?);
                    }
                    Commands::Register { command } => match command {
                        RegisterCommands::Read { name } => {
                            let info = REGISTERS.iter().find(|r| r.name == name).unwrap();
                            let value = debugger.read_register(info)?;
                            println!("{:x}", value.as_usize());
                        }
                        RegisterCommands::Write { name, value } => {
                            let reg_info = REGISTERS.iter().find(|r| r.name == name).unwrap();
                            let reg_value = match reg_info.size {
                                1 => RegisterValue::U8(value as u8),
                                8 => RegisterValue::U64(value as u64),
                                16 => RegisterValue::U128(value),
                                _ => unreachable!(),
                            };

                            debugger.write_register(reg_info, reg_value)?;
                        }
                    },
                    Commands::BreakPoint { command } => match command {
                        BreakPointCommands::Add { addr } => {
                            debugger.add_breakpoint(addr)?;
                        }
                        BreakPointCommands::Remove { id } => {
                            debugger.remove_breakpoint(debugger::BreakPointId(id))?;
                        }
                        BreakPointCommands::List => {
                            for (id, bp) in debugger.breakpoints() {
                                println!("{}: {:#x}", id, bp.addr);
                            }
                        }
                    },

                    Commands::Memory { command } => match command {
                        MemoryCommands::Read { addr, size } => {
                            let mut data = vec![0u8; size];
                            debugger.read_memory(addr, &mut data)?;
                            for (i, byte) in data.iter().enumerate() {
                                if i % 16 == 0 {
                                    if i != 0 {
                                        println!();
                                    }
                                    print!("{:08x}: ", addr + i);
                                }
                                print!("{:02x} ", byte);
                            }
                            println!();
                        }
                        MemoryCommands::Write { addr, data } => {
                            debugger.write_memory(addr, &data)?;
                        }
                    },

                    Commands::Disassemble { addr, count } => {
                        for (addr, asm) in debugger.disassemble(addr, count)? {
                            println!("{:016x}: {}", addr, asm);
                        }
                    }

                    Commands::Quit => {
                        return Ok(true);
                    }
                },
                Err(e) => {
                    e.print()?;
                }
            };
            Ok(false)
        })();

        match result {
            Ok(true) => break,
            Ok(false) => {}
            Err(e) => {
                eprintln!("Error: {}", e);
            }
        }
    }

    Ok(())
}
