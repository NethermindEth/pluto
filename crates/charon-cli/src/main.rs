//! # Pluto CLI
//!
//! Command-line interface for the Pluto distributed validator node.
//! This crate provides the CLI tools and commands for managing and operating
//! Pluto validator nodes.

use clap::{CommandFactory, FromArgMatches};

mod ascii;
mod cli;
mod commands;
pub mod duration;
mod error;

use cli::{Cli, Commands, CreateCommands, TestCommands};
use error::Result;

/// Updates the --test-cases argument help text to include available tests dynamically.
/// This matches Go's behavior: `fmt.Sprintf("Available tests are: %v", listTestCases(cmd))`.
fn update_test_cases_help(mut cmd: clap::Command) -> clap::Command {
    use commands::test::TestCategory;

    // Navigate to test subcommand and update each test category's --test-cases help text
    if let Some(test_cmd) = cmd.find_subcommand_mut("test") {
        for category in &[
            TestCategory::Validator,
            TestCategory::Beacon,
            TestCategory::Mev,
            TestCategory::Peers,
            TestCategory::Infra,
            TestCategory::All,
        ] {
            if let Some(category_cmd) = test_cmd.find_subcommand_mut(category.as_str()) {
                let available_tests = commands::test::list_test_cases(*category);
                let help_text = format!(
                        "Comma-separated list of test names to execute. Available tests are: {}",
                        available_tests.join(", ")
                    );

                *category_cmd = category_cmd.clone()
                    .mut_arg("test_cases", |arg| {
                        arg.help(help_text.clone()).long_help(help_text)
                    });
            }
        }
    }
    cmd
}

#[tokio::main]
async fn main() -> Result<()> {
    // Build the command structure and inject dynamic help text
    let cmd = update_test_cases_help(Cli::command());
    let matches = cmd.get_matches();
    let cli = Cli::from_arg_matches(&matches)
        .map_err(|e| error::CliError::Other(e.to_string()))?;

    match cli.command {
        Commands::Create(args) => match args.command {
            CreateCommands::Enr(args) => commands::create_enr::run(args),
        },
        Commands::Enr(args) => commands::enr::run(args),
        Commands::Version(args) => commands::version::run(args),
        Commands::Test(args) => {
            let mut stdout = std::io::stdout();
            match args.command {
                TestCommands::Peers(args) => {
                    commands::test::peers::run(args, &mut stdout).await?;
                    Ok(())
                }
                TestCommands::Beacon(args) => {
                    commands::test::beacon::run(args, &mut stdout).await?;
                    Ok(())
                }
                TestCommands::Validator(args) => {
                    commands::test::validator::run(args, &mut stdout).await?;
                    Ok(())
                }
                TestCommands::Mev(args) => {
                    commands::test::mev::run(args, &mut stdout).await?;
                    Ok(())
                }
                TestCommands::Infra(args) => {
                    commands::test::infra::run(args, &mut stdout).await?;
                    Ok(())
                }
                TestCommands::All(args) => commands::test::all::run(*args, &mut stdout).await,
            }
        }
    }
}
