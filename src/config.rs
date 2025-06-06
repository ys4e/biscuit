use serde::{Serialize, Deserialize};

/// Configuration used for the matcher.
///
/// This does not include any programmable logic.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Config {
    /// The path to a directory containing matching script files.
    /// The specific path needs to be readable and writable.
    ///
    /// This cannot be left blank.
    ///
    /// # Default
    ///
    /// `scripts`
    pub script_path: String,
    
    /// The path to a file containing environment variables.
    /// 
    /// These are the only variables that will be accessible to scripts.
    /// 
    /// If left blank, no environment variables will be loaded.
    /// 
    /// # Default
    /// 
    /// `.env`
    pub environment_file: String
}

impl Default for Config {
    fn default() -> Self {
        Config {
            script_path: "scripts".to_string(),
            environment_file: ".env".to_string()
        }
    }
}