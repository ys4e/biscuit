use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use anyhow::{anyhow, Result};
use boa_engine::{js_string, Context, Finalize, JsData, JsNativeError, JsString, JsValue, NativeFunction, Source, Trace};
use boa_engine::realm::Realm;
use boa_engine::value::TryIntoJs;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use protoshark::{SerializedMessage as ProtoMessage};
use crate::config::Config;
use crate::message::SerializedMessage;
use crate::{js_catch, js_get, from_realm, js_error, js_convert};

/// Represents the deobfuscated packet cache.
#[derive(Deserialize, Serialize, Clone, Debug, Default, Trace, Finalize, JsData)]
pub struct Cache {
    /// This is an array of known packet names.
    ///
    /// This is not definitive, and is used only for quick reference.
    known_names: Vec<String>,

    /// This is an array of known packet IDs.
    ///
    /// This is not definitive, and is used only for quick reference.
    known_ids: Vec<u16>,

    /// This maps packet IDs to their guessed name.
    id_map: HashMap<u16, String>,

    string: String
}

#[derive(Trace, Finalize, JsData)]
struct JsCache(#[unsafe_ignore_trace] GlobalCache);

/// This type is an alias for a cache shared between comparers.
type GlobalCache = Arc<Mutex<Cache>>;

/// A matcher is a struct containing a group of comparers.
///
/// Each comparer is responsible for checking binary data against a specific condition.
///
/// Additionally, the matcher holds previous context for each comparer.
#[derive(Debug)]
pub struct Matcher {
    pub config: Arc<Config>,
    pub cache: GlobalCache,

    comparers: Vec<Comparer>
}

impl Matcher {
    /// Creates a new matcher instance.
    pub fn new() -> Self {
        Matcher {
            config: Arc::new(Config::default()),
            cache: Arc::new(Mutex::new(Cache::default())),
            comparers: vec![]
        }
    }

    /// Loads all scripts from the specified path.
    pub fn load_scripts(&mut self, path: &Path) -> Result<()> {
        // Enumerate the directory for JavaScript files.
        for entry in path.read_dir()? {
            // Check if the entry is an error.
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    warn!("Failed to read file: {:#?}", error);
                    continue;
                }
            };

            // Create a script instance.
            let comparer = match Comparer::from(&entry.path(), self.cache.clone()) {
                Ok(script) => script,
                Err(error) => {
                    warn!("Invalid script (maybe syntax error?): {:#?}", error);
                    continue;
                }
            };

            // Add the script to the list.
            self.comparers.push(comparer);
        }

        Ok(())
    }

    /// Provides the given data to the matcher.
    ///
    /// The data is first decoded, then checked against all comparers.
    pub fn compare(&mut self, data: &[u8]) -> Result<()> {
        // Decode the data.
        let decoded = match protoshark::decode(data) {
            Ok(decoded) => decoded,
            Err(error) => {
                return Err(anyhow!("failed to decode packet: {:#?}", error));
            }
        };

        // Send the data to each comparer.
        for comparer in &mut self.comparers {
            if let Err(error) = comparer.compare(&decoded) {
                warn!("Failed to compare packet: {:#?}", error);
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct Comparer {
    context: Context
}

/// This unsafe implementation is used to allow any comparers to be sent between threads.
///
/// A JavaScript `Context` is not thread-safe, so ensure that it is always being called on the same thread.
unsafe impl Send for Comparer {}

impl Comparer {
    /// Creates a script instance from the contents of script.
    pub fn from(script: &Path, cache: GlobalCache) -> Result<Self> {
        // Parse the script.
        let script = Source::from_filepath(script)?;

        // Create a script context.
        let mut context = Context::default();

        // Add the cache to the realm.
        let realm = context.realm().clone();
        realm
            .host_defined_mut()
            .insert(JsCache(cache.clone()));
        
        // Update the runtime.
        declare_runtime(realm, &mut context)?;
        
        // Load the script into the context.
        if let Err(error) = context.eval(script) {
            return Err(anyhow!("failed to evaluate script: {:#?}", error));
        };

        // Run the initialize function if it exists.
        if let Ok(initialize) = js_get!(context, "init"; as_callable) {
            js_catch!(initialize.call(&JsValue::undefined(), &[], &mut context));
        }

        Ok(Comparer { context })
    }

    /// Provides the given data to the comparer.
    ///
    /// This will run the comparer's logic and return the result.
    pub fn compare(&mut self, data: &ProtoMessage) -> Result<()> {
        // Convert the `protoshark` message into a JavaScript object.
        let data = SerializedMessage::from(data);

        // Find the compare function.
        // If it doesn't exist, we can't compare the data.
        let compare = match js_get!(self.context, "compare"; as_callable) {
            Ok(compare) => compare,
            Err(error) => return Err(error)
        };

        // Convert the data into JavaScript.
        let js_data = match data.try_into_js(&mut self.context) {
            Ok(data) => data,
            Err(error) => return Err(anyhow!("failed to convert data to JavaScript: {:#?}", error))
        };

        // Run the compare function.
        if let Err(error) = compare.call(
            &JsValue::undefined(),
            &[js_data],
            &mut self.context
        ) {
            return Err(anyhow!("failed to run compare function: {:#?}", error));
        }

        Ok(())
    }
}

/// Adds functions to the JavaScript context.
fn declare_runtime(_: Realm, context: &mut Context) -> Result<()> {
    js_catch!(context.register_global_builtin_callable(
        JsString::from("info"), 1,
        NativeFunction::from_fn_ptr(|_, args, _| {
            let Some(message) = args.get(0) else {
                return js_error!("missing message argument");
            };
            
            let message = js_convert!(message, context, as_string)
                .to_std_string_escaped();
            info!("{}", message);
            
            Ok(JsValue::Undefined)
        })
    ));

    js_catch!(context.register_global_builtin_callable(
        JsString::from("warn"), 1,
        NativeFunction::from_fn_ptr(|_, args, _| {
            let Some(message) = args.get(0) else {
                return js_error!("missing message argument");
            };
            
            let message = js_convert!(message, context, as_string)
                .to_std_string_escaped();
            warn!("{}", message);
            
            Ok(JsValue::Undefined)
        })
    ));
    
    js_catch!(context.register_global_builtin_callable(
        JsString::from("writeString"), 0,
        NativeFunction::from_fn_ptr(|_, _, context| {
            let realm = context.realm().host_defined_mut();
            let Ok(mut cache) = from_realm!(realm => JsCache).0.lock() else {
                return Err(JsNativeError::typ()
                    .with_message("failed to get cache")
                    .into());
            };
            
            cache.string = "Hello, World!".to_string();
            drop(cache); // Release the lock.

            Ok(JsValue::Undefined)
        })
    ));
    
    Ok(())
}