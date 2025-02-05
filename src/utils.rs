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
                return js_error!(concat!("failed to convert {} to {}", stringify!($variable), stringify!($type)));
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
        if let Err(error) = $func {
            return Err(anyhow!("failed to run function: {:#?}", error));
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