//! The exit code contract every caller relies on.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Exit {
    /// Scanned, no leaks.
    Clean = 0,
    /// Leaks found, strict or loose.
    Leaks = 1,
    /// No rules loaded; candidates are still printed. For `hydrate`, a listed key has no value.
    NoRules = 2,
    /// Usage or IO error, missing path, nothing scanned.
    Error = 3,
}

impl Exit {
    /// A leak wins, since it is the finding to act on. An incomplete scan outranks
    /// "no rules", and neither may ever read as clean.
    pub fn decide(leaks: usize, rules: usize, scanned: usize, io_errors: usize) -> Exit {
        if leaks > 0 {
            Exit::Leaks
        } else if scanned == 0 || io_errors > 0 {
            Exit::Error
        } else if rules == 0 {
            Exit::NoRules
        } else {
            Exit::Clean
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Exit::{self, *};

    #[test]
    fn precedence() {
        assert_eq!(Exit::decide(0, 1, 1, 0), Clean);
        assert_eq!(Exit::decide(1, 1, 0, 1), Leaks);
        assert_eq!(Exit::decide(0, 0, 1, 0), NoRules);
        assert_eq!(Exit::decide(0, 0, 0, 0), Error);
        assert_eq!(Exit::decide(0, 1, 1, 1), Error);
    }
}
