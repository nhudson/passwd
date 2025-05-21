pub const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
pub const NUMBERS: &[u8] = b"0123456789";
pub const SPECIAL: &[u8] = b"!@#$%^&*()-_=+[]{}|;:,.<>?";

pub struct PasswordValidation {
    pub is_valid: bool,
    pub missing_types: Vec<String>,
}

pub struct GeneratedPassword {
    pub password: String,
    pub entropy: f64,
    pub validation: PasswordValidation,
    pub original_min_entropy: f64,
    pub reached_min_entropy: bool,
}
