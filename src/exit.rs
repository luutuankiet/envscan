//! The exit code contract every caller relies on.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Exit {
    /// Scanned, no leaks.
    Clean = 0,
    /// Leaks found, strict or loose.
    Leaks = 1,
    /// No rules loaded; candidates are still printed. For `hydrate`, a listed key has no value.
    /// For `promotion add`, the repo has no commits or is shallow, so it has no identity.
    NoRules = 2,
    /// Usage or IO error, missing path, nothing scanned, or a data file left unscanned.
    Error = 3,
}

impl Exit {
    /// A leak wins, since it is the finding to act on. An incomplete scan outranks
    /// "no rules", and neither may ever read as clean.
    /// `incomplete` counts inputs that were not read: IO errors and unscanned data files.
    pub fn decide(leaks: usize, rules: usize, scanned: usize, incomplete: usize) -> Exit {
        if leaks > 0 {
            Exit::Leaks
        } else if scanned == 0 || incomplete > 0 {
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
