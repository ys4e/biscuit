use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use anyhow::{anyhow, Result};
use boa_engine::{js_string, Context, Finalize, JsData, JsNativeError, JsResult, JsString, JsValue, NativeFunction, Source, Trace};
use boa_engine::property::Attribute;
use boa_engine::realm::Realm;
use boa_engine::value::{TryFromJs, TryIntoJs};
use boa_runtime::Console;
use log::warn;
use serde::{Deserialize, Serialize};
use protoshark::{SerializedMessage as ProtoMessage};
use crate::config::Config;
use crate::message::SerializedMessage;
use crate::{js_catch, js_get, from_realm, js_error, js_convert, utils};

/// Represents a JavaScript object containing field data.
#[derive(Deserialize, Serialize, Clone, Debug, Default, Trace, Finalize, TryFromJs)]
pub struct MessageField {
    /// The name of the field.
    /// 
    /// # Repeated Names
    /// 
    /// If this field name is repeated, the other fields will be categorized under a `oneof`.
    pub field_name: String,
    
    /// The type of the field.
    pub field_type: String,
    
    /// The ID of the field.
    /// 
    /// This must be unique.
    pub field_id: u16
}

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
    
    /// All cached messages.
    messages: HashMap<String, Vec<MessageField>>
}

impl Cache {
    /// Simple check to see if the cache knows the given ID.
    pub fn id_known(&self, id: u16) -> bool {
        self.id_map.contains_key(&id)
    }
    
    /// Simple check to see if the cache knows the given name.
    pub fn name_known(&self, name: &str) -> bool {
        self.known_names.contains(&name.to_string())
    }
    
    /// Updates the cache with the guessed name, ID, and field data.
    pub fn update(
        &mut self,
        message_name: String,
        packet_id: u16,
        field: MessageField
    ) {
        // Add the message to the cache if it doesn't exist.
        if !self.id_map.contains_key(&packet_id) {
            self.known_names.push(message_name.clone());
            self.known_ids.push(packet_id);
            self.id_map.insert(packet_id, message_name.clone());
        }
        
        // Add the field to the message.
        let fields = self.messages.entry(message_name).or_default();
        fields.push(field);
    }
}

/// Represents a JavaScript object containing packet data.
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
            let entry = entry.path();
            if let Some(extension) = entry.extension() {
                if extension != "js" {
                    continue;
                }
            } else {
                continue;
            }

            let comparer = match Comparer::from(&entry, self.cache.clone()) {
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
    pub fn compare(&mut self, id: u16, header: &[u8], data: &[u8]) -> Result<()> {
        // Decode the data.
        let data = match protoshark::decode(data) {
            Ok(decoded) => decoded,
            Err(error) => {
                return Err(anyhow!("failed to decode packet: {:#?}", error));
            }
        };

        let header = match protoshark::decode(header) {
            Ok(decoded) => decoded,
            Err(error) => {
                return Err(anyhow!("failed to decode header: {:#?}", error));
            }
        };

        // Send the data to each comparer.
        for comparer in &mut self.comparers {
            if let Err(error) = comparer.compare(id, &header, &data) {
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
    pub fn compare(&mut self, id: u16, header: &ProtoMessage, data: &ProtoMessage) -> Result<()> {
        // Convert the `protoshark` message into a JavaScript object.
        let id = js_catch!(id.try_into_js(&mut self.context));
        let header = SerializedMessage::from_to_js(&mut self.context, header)?;
        let data = SerializedMessage::from_to_js(&mut self.context, data)?;

        // Find the compare function.
        // If it doesn't exist, we can't compare the data.
        let compare = match js_get!(self.context, "compare"; as_callable) {
            Ok(compare) => compare,
            Err(error) => return Err(error)
        };

        // Run the compare function.
        if let Err(error) = compare.call(
            &JsValue::undefined(),
            &[id, JsValue::from(header), JsValue::from(data)],
            &mut self.context
        ) {
            return Err(anyhow!("failed to run compare function: {:#?}", error));
        }

        Ok(())
    }
}

/// Adds functions to the JavaScript context.
fn declare_runtime(_: Realm, context: &mut Context) -> Result<()> {
    let console = Console::init(context);

    context
        .register_global_property(Console::NAME, console, Attribute::all())
        .expect("global property 'console' already exists");
    context
        .register_global_class::<SerializedMessage>()
        .expect("class SerializedMessage already exists");

    js_catch!(context.register_global_builtin_callable(
        JsString::from("info"), 1,
        NativeFunction::from_fn_ptr(utils::js_info)
    ));

    js_catch!(context.register_global_builtin_callable(
        JsString::from("warn"), 1,
        NativeFunction::from_fn_ptr(utils::js_warn)
    ));

    js_catch!(context.register_global_builtin_callable(
        JsString::from("error"), 1,
        NativeFunction::from_fn_ptr(utils::js_error)
    ));

    js_catch!(context.register_global_builtin_callable(
        JsString::from("base64Decode"), 1,
        NativeFunction::from_fn_ptr(utils::js_base64_decode)
    ));

    js_catch!(context.register_global_builtin_callable(
        JsString::from("rsaDecrypt"), 2,
        NativeFunction::from_fn_ptr(utils::js_rsa_decrypt)
    ));

    js_catch!(context.register_global_builtin_callable(
        JsString::from("identify"), 3,
        NativeFunction::from_fn_ptr(js_identify)
    ));
    
    js_catch!(context.register_global_builtin_callable(
        JsString::from("isKnown"), 1,
        NativeFunction::from_fn_ptr(js_is_known)
    ));

    Ok(())
}

/// JavaScript-compatible function that identifies a packet and its fields.
fn js_identify(_: &JsValue, args: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
    let realm = context.realm().clone();
    let realm = realm.host_defined_mut();

    // Fetch the cache from the realm.
    let Ok(mut cache) = from_realm!(realm => JsCache).0.lock() else {
        return Err(JsNativeError::typ()
            .with_message("failed to get cache")
            .into());
    };

    // Get the data from the arguments.
    let Some(packet_name) = args.get(0) else {
        return js_error!("missing packet name argument");
    };
    let Some(packet_id) = args.get(1) else {
        return js_error!("missing packet ID argument");
    };
    let Some(field) = args.get(2) else {
        return js_error!("missing field argument");
    };

    // Convert the data into Rust-owned values.
    let packet_name = js_convert!(packet_name, as_string).to_std_string_escaped();
    let packet_id = js_convert!(packet_id, as_number) as u16;
    let packet_field = MessageField::try_from_js(field, context)?;

    // Update the cache.
    cache.update(packet_name, packet_id, packet_field);

    Ok(JsValue::Undefined)
}

/// JavaScript-compatible function that checks if a packet is known.
fn js_is_known(_: &JsValue, args: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
    // Fetch the cache from the realm.
    let realm = context.realm().host_defined_mut();
    let Ok(cache) = from_realm!(realm => JsCache).0.lock() else {
        return Err(JsNativeError::typ()
            .with_message("failed to get cache")
            .into());
    };

    // Get the data from the arguments.
    let Some(packet_id) = args.get(0) else {
        return js_error!("missing packet ID argument");
    };

    if packet_id.is_string() {
        let packet_name = js_convert!(packet_id, as_string).to_std_string_escaped();
        Ok(JsValue::Boolean(cache.name_known(&packet_name)))
    } else if packet_id.is_number() {
        let packet_id = js_convert!(packet_id, as_number) as u16;
        Ok(JsValue::Boolean(cache.id_known(packet_id)))
    } else {
        js_error!("invalid packet ID type")
    }
}
