use paste::paste;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use boa_engine::{Context, JsResult, JsValue, JsNativeError};
use boa_engine::object::builtins::JsArrayBuffer;
use boa_engine::value::{TryIntoJs, Type};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};

/// Macro utility to fetch a value from the global context.
///
/// This performs the validation required, leaving only one result to catch.
///
/// # Example
///
/// ```rust,no_run
/// use boa_engine::Context;
/// use biscuit::js_get;
///
/// let mut context = Context::default();
/// let result = js_get!(context, "init"; as_callable);
/// ```
#[macro_export]
macro_rules! js_get {
    ($context:expr, $name:expr; $type:ident) => {
        {
            let value = match $context.global_object().get(js_string!($name), &mut $context) {
                Ok(value) => value,
                Err(error) => return Err(anyhow!("failed to get {}: {:#?}", $name, error)),
            };

            match value.$type() {
                Some(value) => Ok(value.clone()),
                None => Err(anyhow!("failed to get {} as {}", $name, stringify!($type))),
            }
        }
    };
}

/// Converts a JavaScript value into any type.
/// 
/// # Example
/// 
/// ```rust,no_run
/// use boa_engine::JsValue;
/// use biscuit::js_convert;
/// 
/// let value = JsValue::from(42);
/// let number = js_convert!(value, as_number);
/// ```
#[macro_export]
macro_rules! js_convert {
    ($variable:expr, $type:ident) => {
        {
            let Some(value) = $variable.$type() else {
                return js_error!(format!("failed to convert {} to {}", stringify!($variable), stringify!($type)));
            };
            
            value
        }
    };
}

/// Catches a `JsResult` and returns an `anyhow` error if it fails.
/// 
/// # Example
/// 
/// ```rust,no_run
/// use boa_engine::{Context, Source};
/// use biscuit::js_catch;
///
/// let mut context = Context::default();
/// let script = Source::from_bytes("console.log('Hello, World!')");
/// js_catch!(context.eval(script));
/// ```
#[macro_export]
macro_rules! js_catch {
    ($func:expr) => {
        match $func {
            Ok(value) => value,
            Err(error) => return Err(anyhow!("failed to run function: {:#?}", error)),
        }
    };
}

/// Creates a native JavaScript engine error.
/// 
/// # Example
/// 
/// ```rust,no_run
/// use biscuit::js_error;
/// 
/// let error = js_error!("this is an error");
/// ```
#[macro_export]
macro_rules! js_error {
    ($message:expr) => {
        Err(JsNativeError::typ()
            .with_message($message)
            .into())
    };
}

/// Retrieves a value from a JavaScript context's realm.
/// 
/// # Example
/// 
/// ```rust,no_run
/// use boa_engine::{Context, Finalize, JsData, Trace};
/// use biscuit::from_realm;
///
/// #[derive(Trace, Finalize, JsData)]
/// struct Figure(i32);
///
/// let mut context = Context::default();
/// let realm = context.realm().host_defined_mut();
/// let figure = from_realm!(realm => Figure);
/// ```
#[macro_export]
macro_rules! from_realm {
    ($realm:expr => $cast:tt) => {
        {
            let Some(value) = $realm.get::<$cast>() else {
                return Err(JsNativeError::typ()
                    .with_message(concat!("failed to get ", stringify!($cast)))
                    .into());
            };
            
            value
        }
    };
}

/// Converts a JavaScript value into a Rust managed string.
pub(crate) fn js_stringify(value: &JsValue, context: &mut Context) -> String {
    match value.get_type() {
        Type::Undefined => "undefined".to_string(),
        Type::Null => "null".to_string(),
        Type::Boolean => value.as_boolean()
            .unwrap_or(false)
            .to_string(),
        Type::Number => value.as_number()
            .unwrap_or(0.0)
            .to_string(),
        Type::String => {
            match value.as_string() {
                Some(string) => string.to_std_string_escaped(),
                None => "undefined".to_string()
            }
        },
        Type::Symbol => {
            match value.as_symbol() {
                Some(symbol) => symbol.fn_name()
                    .to_std_string_escaped(),
                None => "undefined".to_string()
            }
        }
        Type::BigInt => {
            match value.as_bigint() {
                Some(bigint) => bigint.to_string(),
                None => "undefined".to_string()
            }
        }
        Type::Object => {
            match value.as_object() {
                Some(object) => {
                    let Ok(value) = object.try_into_js(context) else {
                        return "undefined".to_string();
                    };

                    match value.to_string(context) {
                        Ok(string) => string.to_std_string_escaped(),
                        Err(_) => "undefined".to_string()
                    }
                },
                None => "undefined".to_string()
            }
        }
    }
}

macro_rules! js_log {
    ($($level:ident),*) => {
        $(
            paste! {
                pub(crate) fn [<js_ $level>](_: &JsValue, args: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
                    let Some(message) = args.get(0) else {
                        return js_error!("missing message argument");
                    };

                    let string = js_stringify(message, context);
                    log::$level!("{}", string);

                    Ok(JsValue::Undefined)
                }
            }
        )*
    };
}

js_log!(info, warn, error);

/// Base64 encoding method that is JavaScript compatible.
///
/// # Example
///
/// ```js
/// console.log(base64Decode("Gw=="));
/// ```
pub(crate) fn js_base64_decode(
    _: &JsValue,
    args: &[JsValue],
    context: &mut Context
) -> JsResult<JsValue> {
    let Some(value) = args.get(0) else {
        return js_error!("missing value argument");
    };

    let string = value.to_string(context)?
        .to_std_string_escaped();

    let Ok(bytes) = BASE64_STANDARD.decode(string) else {
        return js_error!("failed to decode base64");
    };

    // Convert the Rust byte array into a JavaScript array buffer.
    let buffer = JsArrayBuffer::from_byte_block(bytes, context)?;

    Ok(buffer.into())
}

/// RSA decryption method that is JavaScript compatible.
///
/// The private key must be formatted in the PKCS#1 PEM format.
///
/// # Example
///
/// ```js
/// const privateKey = "...";
/// // This value is Base64-encoded.
/// const encryptedMessage = "...";
///
/// try {
///     const result = rsaDecrypt(privateKey, encryptedMessage);
/// } catch (error) {
///     error("Failed to decrypt message.");
/// }
/// ```
pub(crate) fn js_rsa_decrypt(
    _: &JsValue,
    args: &[JsValue],
    context: &mut Context
) -> JsResult<JsValue> {
    let Some(private_key) = args.get(0) else {
        return js_error!("missing private key argument");
    };
    let Some(encrypted) = args.get(1) else {
        return js_error!("missing encrypted message argument");
    };

    // Convert the private key into a string.
    let private_key = private_key.to_string(context)?
        .to_std_string_escaped();

    // Parse the private key.
    let Ok(private_key) = RsaPrivateKey::from_pkcs1_pem(&private_key) else {
        return js_error!("failed to parse private key");
    };
    
    // Decode the bytes.
    let encrypted = encrypted.to_string(context)?
        .to_std_string_escaped();
    let Ok(encrypted) = BASE64_STANDARD.decode(encrypted) else {
        return js_error!("failed to decode base64");
    };

    // Try to decrypt the message.
    let Ok(decrypted) = private_key.decrypt(Pkcs1v15Encrypt, &encrypted) else {
        return js_error!("failed to decrypt message");
    };
    
    // Convert the Rust byte array into a JavaScript array buffer.
    let buffer = JsArrayBuffer::from_byte_block(decrypted, context)?;

    Ok(buffer.into())
}
