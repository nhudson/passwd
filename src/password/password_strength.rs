use clap::ValueEnum;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum PasswordStrength {
    Weak,
    Moderate,
    Strong,
    VeryStrong,
    Extreme,
}

impl PasswordStrength {
    pub fn min_entropy(&self) -> f64 {
        match self {
            PasswordStrength::Weak => 30.0,
            PasswordStrength::Moderate => 50.0,
            PasswordStrength::Strong => 70.0,
            PasswordStrength::VeryStrong => 90.0,
            PasswordStrength::Extreme => 120.0,
        }
    }

    pub fn from_entropy(entropy: f64) -> Self {
        match entropy as usize {
            0..=45 => PasswordStrength::Weak,
            46..=60 => PasswordStrength::Moderate,
            61..=80 => PasswordStrength::Strong,
            81..=100 => PasswordStrength::VeryStrong,
            _ => PasswordStrength::Extreme,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            PasswordStrength::Weak => "Weak - easily crackable",
            PasswordStrength::Moderate => "Moderate - acceptable for non-critical accounts",
            PasswordStrength::Strong => "Strong - good for most purposes",
            PasswordStrength::VeryStrong => "Very strong - suitable for sensitive accounts",
            PasswordStrength::Extreme => {
                "Extremely strong - suitable for high-security applications"
            }
        }
    }
}
