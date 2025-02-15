use std::path::Path;
use std::sync::{Arc, Mutex};
use lazy_static::lazy_static;
use anyhow::{Result, anyhow};
use dotenv_parser::parse_dotenv;
use is_main_thread::is_main_thread;
use crate::config::Config;
use crate::matcher::{Cache, Matcher};

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

    // Try loading the environment file.
    let env_file = &config.environment_file;
    let variables = {
        let file = Path::new(env_file);
        
        if file.exists() {
            let content = std::fs::read_to_string(file)?;
            match parse_dotenv(&content) {
                Ok(map) => Some(map),
                Err(error) => {
                    log::warn!("failed to parse environment file: {}", error);
                    None
                }
            }
        } else {
            None
        }
    };

    // Initialize the matcher.
    matcher.config = Arc::new(config);
    matcher.initialize(path, variables)?;

    Ok(())
}

/// Processes the input data.
/// 
/// # Notice
/// 
/// This should **only** be called on the main thread.
pub fn input(id: u16, header: &[u8], data: &[u8]) -> Result<()> {
    // Check if we are on the main thread.
    let is_main = is_main_thread().unwrap_or_else(|| true);
    if !is_main {
        return Err(anyhow!("input can only be called on the main thread"));
    }
    
    // Fetch the matcher.
    let mut matcher = MATCHER.lock().unwrap();
    
    // Compare the data.
    matcher.compare(id, header, data)?;
    
    Ok(())
}

/// Fetches the cache.
///
/// This returns a clone.
pub fn cache() -> Cache {
    let matcher = MATCHER.lock().unwrap();
    let cache = matcher.cache.lock().unwrap();

    cache.clone()
}