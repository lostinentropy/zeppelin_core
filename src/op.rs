//! Experimental wrapper for 1Password CLI 2.0

use std::process::{Command, Stdio};

#[allow(dead_code)]
fn check_available() -> bool {
    let out = Command::new("op")
        .arg("-v")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    match out {
        Ok(inner) => {
            if !inner.status.success() {
                return false;
            }
        }
        Err(_) => {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installed() {
        assert!(check_available())
    }
}
