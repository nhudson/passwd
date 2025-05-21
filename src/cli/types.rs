use crate::password::password_strength::PasswordStrength;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about = "A secure password generator", long_about = None)]
pub struct Cli {
    #[arg(short, long, default_value_t = 32)]
    pub length: usize,

    #[arg(short = 'e', long)]
    pub min_entropy: Option<f64>,

    #[arg(long, default_value_t = true)]
    pub uppercase: bool,

    #[arg(long, default_value_t = true)]
    pub lowercase: bool,

    #[arg(long, default_value_t = true)]
    pub numbers: bool,

    #[arg(long, default_value_t = true)]
    pub special: bool,

    #[arg(short, long, value_enum)]
    pub strength: Option<PasswordStrength>,
}
