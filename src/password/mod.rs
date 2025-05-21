pub mod password_strength;

use rand::{Rng, prelude::SliceRandom};

const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const NUMBERS: &[u8] = b"0123456789";
const SPECIAL: &[u8] = b"!@#$%^&*()-_=+[]{}|;:,.<>?";

pub struct PasswordValidation {
    pub is_valid: bool,
    pub missing_types: Vec<String>,
}

pub fn generate_secure_password(
    length: usize,
    use_uppercase: bool,
    use_lowercase: bool,
    use_numbers: bool,
    use_special: bool,
) -> String {
    let mut charsets = Vec::new();
    if use_uppercase {
        charsets.push(UPPERCASE);
    }
    if use_lowercase {
        charsets.push(LOWERCASE);
    }
    if use_numbers {
        charsets.push(NUMBERS);
    }
    if use_special {
        charsets.push(SPECIAL);
    }

    let mut rng = rand::rng();
    let mut password = String::with_capacity(length);

    for charset in charsets.iter() {
        if password.len() < length {
            let idx = rng.random_range(0..charset.len());
            password.push(charset[idx] as char);
        }
    }

    // Create a combined character set from all enabled sets
    let all_chars = charsets.concat();

    // Fill the rest with random characters from all enabled sets
    for _ in password.len()..length {
        let idx = rng.random_range(0..all_chars.len());
        password.push(all_chars[idx] as char);
    }

    // Shuffle the password to avoid predictable pattern
    let mut password_chars: Vec<char> = password.chars().collect();
    password_chars.shuffle(&mut rng);

    password_chars.into_iter().collect()
}

pub fn validate_password(
    password: &str,
    check_uppercase: bool,
    check_lowercase: bool,
    check_numbers: bool,
    check_special: bool,
) -> PasswordValidation {
    let has_uppercase = !check_uppercase || password.chars().any(|c| c.is_ascii_uppercase());
    let has_lowercase = !check_lowercase || password.chars().any(|c| c.is_ascii_lowercase());
    let has_number = !check_numbers || password.chars().any(|c| c.is_ascii_digit());
    let has_special = !check_special || password.chars().any(|c| !c.is_alphanumeric());

    let mut missing = Vec::new();
    if check_uppercase && !has_uppercase {
        missing.push("uppercase".to_string());
    }
    if check_lowercase && !has_lowercase {
        missing.push("lowercase".to_string());
    }
    if check_numbers && !has_number {
        missing.push("number".to_string());
    }
    if check_special && !has_special {
        missing.push("special character".to_string());
    }

    PasswordValidation {
        is_valid: has_uppercase && has_lowercase && has_number && has_special,
        missing_types: missing,
    }
}

pub fn calc_entropy(password: &str) -> f64 {
    let char_set_size = get_charset_size(password);
    (char_set_size as f64).log2() * (password.len() as f64)
}

pub fn get_charset_size(password: &str) -> usize {
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    let mut has_special = false;

    for c in password.chars() {
        if c.is_ascii_uppercase() {
            has_upper = true;
        } else if c.is_ascii_lowercase() {
            has_lower = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else {
            has_special = true;
        }
    }

    let mut size = 0;
    if has_upper {
        size += 26;
    }
    if has_lower {
        size += 26;
    }
    if has_digit {
        size += 10;
    }
    if has_special {
        size += 32;
    }

    size
}
