pub mod cli;
pub mod password;

use crate::{
    cli::types::Cli,
    password::{
        calc_entropy, generate_secure_password, password_strength::PasswordStrength,
        validate_password,
    },
};
use clap::Parser;

fn main() {
    let mut args = Cli::parse();

    if let Some(strength) = args.strength {
        let strength_entropy = strength.min_entropy();
        args.min_entropy = Some(args.min_entropy.unwrap_or(0.0).max(strength_entropy));
    }

    args.length = std::cmp::max(args.length, 4);

    if !args.uppercase && !args.lowercase && !args.numbers && !args.special {
        eprintln!("Error: need at least 1 character");
        std::process::exit(1);
    }

    let mut password = String::new();
    let mut current_entropy = args.min_entropy.unwrap_or(0.0);
    let min_entropy = args.min_entropy.unwrap_or(0.0);

    for _ in 0..10 {
        password = generate_secure_password(
            args.length,
            args.uppercase,
            args.lowercase,
            args.numbers,
            args.special,
        );
        current_entropy = calc_entropy(&password);

        if current_entropy >= min_entropy {
            break;
        }

        args.length += 2;
    }

    if current_entropy < min_entropy {
        eprintln!(
            "Warning: Could not generate password with entropy of {:.2} bits.",
            min_entropy
        );
        eprintln!(
            "Generated password with entropy of {:.2} bits instead.",
            current_entropy
        );
    }

    println!("Generated password: {}", password);
    println!("Password length: {}", password.len());
    println!("Estimated entropy: {:.2} bits", current_entropy);

    let strength = PasswordStrength::from_entropy(current_entropy);
    println!("Password strength: {}", strength.description());

    let validation = validate_password(
        &password,
        args.uppercase,
        args.lowercase,
        args.numbers,
        args.special,
    );

    println!(
        "Validation: {}",
        if validation.is_valid {
            "PASSED ✓"
        } else {
            "FAILED ✗"
        }
    );

    if !validation.is_valid {
        println!(
            "Missing character types: {}",
            validation.missing_types.join(", ")
        );
    }
}
