pub mod cli;
pub mod password;

use crate::{
    cli::types::Cli,
    password::{format_password_output, generate_password_with_entropy},
};
use clap::Parser;

fn main() {
    let mut cli = Cli::parse();

    // Set default min entropy from strength if provided
    if let Some(strength) = cli.strength {
        let strength_entropy = strength.min_entropy();
        cli.min_entropy = Some(cli.min_entropy.unwrap_or(0.0).max(strength_entropy));
    }

    // Ensure minimum password length
    cli.length = std::cmp::max(cli.length, 4);

    // Ensure at least one character type is enabled
    if !cli.uppercase && !cli.lowercase && !cli.numbers && !cli.special {
        eprintln!("Error: need at least 1 character type enabled");
        std::process::exit(1);
    }

    // Generate password with required entropy
    let generated = generate_password_with_entropy(
        cli.length,
        cli.uppercase,
        cli.lowercase,
        cli.numbers,
        cli.special,
        cli.min_entropy.unwrap_or(0.0),
    );

    // Print output
    for line in format_password_output(&generated) {
        println!("{}", line);
    }
}
