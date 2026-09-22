use std::fmt;

pub const EXIT_OK: i32 = 0;
pub const EXIT_USAGE: i32 = 1;
pub const EXIT_UNRESOLVED: i32 = 2;

#[derive(Debug, PartialEq, Eq)]
pub struct AppError(pub String);

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl std::error::Error for AppError {}

impl From<String> for AppError {
    fn from(value: String) -> Self {
        AppError(value)
    }
}

impl From<&str> for AppError {
    fn from(value: &str) -> Self {
        AppError(value.to_string())
    }
}
