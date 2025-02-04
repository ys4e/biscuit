use std::path::Path;
use std::sync::{Arc, Mutex};
use lazy_static::lazy_static;
use anyhow::{Result, anyhow};
use is_main_thread::is_main_thread;
use crate::config::Config;
use crate::matcher::Matcher;

pub mod config;
mod matcher;
mod utils;
mod message;

lazy_static! {
    static ref MATCHER: Arc<Mutex<Matcher>> = Arc::new(Mutex::new(Matcher::new()));
}

/// Initializes the library.
///
/// This method should be called at the beginning of the program's lifecycle.
///
/// # Example
///
/// ```rust,no_run
/// use biscuit::config::Config;
///
/// let config = Config::default();
/// biscuit::initialize(config)
///     .expect("invalid configuration specified");
/// ```
pub fn initialize(config: Config) -> Result<()> {
    let mut matcher = MATCHER.lock().unwrap();

    // Load all matcher scripts.
    let path = config.script_path.clone();
    let path = Path::new(&path);
    if !path.exists() {
        return Err(anyhow!("script folder does not exist"));
    }

    // Initialize the matcher.
    matcher.config = Arc::new(config);
    matcher.load_scripts(path)?;

    Ok(())
}

/// Processes the input data.
/// 
/// # Notice
/// 
/// This should **only** be called on the main thread.
pub fn input(data: &[u8]) -> Result<()> {
    // Check if we are on the main thread.
    let is_main = is_main_thread().unwrap_or_else(|| true);
    if !is_main {
        return Err(anyhow!("input can only be called on the main thread"));
    }
    
    // Fetch the matcher.
    let mut matcher = MATCHER.lock().unwrap();
    
    // Compare the data.
    matcher.compare(data)?;
    
    Ok(())
}
