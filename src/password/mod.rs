pub mod password_strength;
pub mod types;

use crate::password::types::{
    GeneratedPassword, LOWERCASE, NUMBERS, PasswordValidation, SPECIAL, UPPERCASE,
};
use rand::{Rng, prelude::SliceRandom};

// Generate a password that meets the required minimum entropy
pub fn generate_password_with_entropy(
    mut length: usize,
    use_uppercase: bool,
    use_lowercase: bool,
    use_numbers: bool,
    use_special: bool,
    min_entropy: f64,
) -> GeneratedPassword {
    let mut password = String::new();
    let mut current_entropy = 0.0;
    let mut reached_min_entropy = false;

    // Try up to 10 times, increasing length if needed
    for _ in 0..10 {
        password = generate_secure_password(
            length,
            use_uppercase,
            use_lowercase,
            use_numbers,
            use_special,
        );
        current_entropy = calc_entropy(&password);

        if current_entropy >= min_entropy {
            reached_min_entropy = true;
            break;
        }

        length += 2;
    }

    let validation = validate_password(
        &password,
        use_uppercase,
        use_lowercase,
        use_numbers,
        use_special,
    );

    GeneratedPassword {
        password,
        entropy: current_entropy,
        validation,
        original_min_entropy: min_entropy,
        reached_min_entropy,
    }
}

pub fn format_password_output(generated: &GeneratedPassword) -> Vec<String> {
    let mut output = Vec::new();

    output.push(format!("Generated password: {}", generated.password));
    output.push(format!("Password length: {}", generated.password.len()));
    output.push(format!("Estimated entropy: {:.2} bits", generated.entropy));

    let strength = password_strength::PasswordStrength::from_entropy(generated.entropy);
    output.push(format!("Password strength: {}", strength.description()));

    output.push(format!(
        "Validation: {}",
        if generated.validation.is_valid {
            "PASSED ✓"
        } else {
            "FAILED ✗"
        }
    ));

    if !generated.validation.is_valid {
        output.push(format!(
            "Missing character types: {}",
            generated.validation.missing_types.join(", ")
        ));
    }

    if !generated.reached_min_entropy {
        output.push(format!(
            "Warning: Could not generate password with entropy of {:.2} bits.",
            generated.original_min_entropy
        ));
        output.push(format!(
            "Generated password with entropy of {:.2} bits instead.",
            generated.entropy
        ));
    }

    output
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
