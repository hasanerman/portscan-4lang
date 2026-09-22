use std::collections::BTreeSet;

use crate::error::AppError;

pub const PORT_MIN: u32 = 1;
pub const PORT_MAX: u32 = 65535;

fn parse_number(text: &str) -> Result<u32, AppError> {
    let value: u32 = text
        .parse()
        .map_err(|_| AppError(format!("a number was expected: {text}")))?;
    if !(PORT_MIN..=PORT_MAX).contains(&value) {
        return Err(AppError(
            "port must be a number between 1 and 65535".to_string(),
        ));
    }
    Ok(value)
}

fn mark_token(token: &str, marked: &mut BTreeSet<u16>) -> Result<(), AppError> {
    match token.split_once('-') {
        None => {
            let port = parse_number(token)?;
            marked.insert(port as u16);
        }
        Some((head, tail)) => {
            let first = parse_number(head)?;
            let last = parse_number(tail)?;
            if first > last {
                return Err(AppError(
                    "port range start is greater than its end".to_string(),
                ));
            }
            for port in first..=last {
                marked.insert(port as u16);
            }
        }
    }
    Ok(())
}

pub fn parse(spec: &str) -> Result<Vec<u16>, AppError> {
    if spec.is_empty() {
        return Err(AppError("port list is empty".to_string()));
    }

    let mut marked = BTreeSet::new();
    for token in spec.split(',') {
        mark_token(token, &mut marked)?;
    }
    Ok(marked.into_iter().collect())
}
