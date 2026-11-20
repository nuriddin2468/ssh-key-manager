//! How serious a finding is: shared by the audit of `~/.ssh`, the vault's
//! audit and the leak scanner, so the vault's findings keep it on builds
//! without the `ssh-audit` feature.

use serde::{Deserialize, Serialize};

/// How serious a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum Severity {
    /// Insecure or broken; fix now.
    Critical,
    /// Should be fixed.
    Warning,
    /// Worth knowing.
    Info,
}
