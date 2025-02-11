use std::collections::HashMap;
use anyhow::{Result, anyhow};
use paste::paste;
use boa_engine::{js_string, Context, Finalize, JsData, JsResult, JsValue, NativeFunction, Trace, JsNativeError, JsObject};
use boa_engine::class::{Class, ClassBuilder};
use boa_engine::object::builtins::JsArray;
use boa_engine::value::TryIntoJs;
use protoshark::{Number, SerializedMessage as ProtoMessage, Value as ProtoValue, VarInt};
use crate::{js_catch, js_convert, js_error};

/// Generates JavaScript-compatible methods for transforming
/// `protoshark`'s `Value`s into JavaScript values.
macro_rules! js_method {
    ($($value_type:ty),*) => {
        $(
            paste! {
                pub(crate) fn [<js_get_ $value_type:lower>](
                    this: &JsValue,
                    args: &[JsValue],
                    context: &mut Context
                ) -> JsResult<JsValue> {
                    let object = js_convert!(this, as_object);
                    let Some(message) = object.downcast_ref::<crate::message::SerializedMessage>() else {
                        return js_error!("failed to cast object to SerializedMessage");
                    };

                    let Some(field_id) = args.get(0) else {
                        return js_error!("missing field ID");
                    };
                    let field_id = js_convert!(field_id, as_number) as i32;

                    let value = message.get(field_id);
                    match value {
                        Some(value) => {
                            match value {
                                crate::message::Value::$value_type(_) => value.try_into_js(context),
                                _ => Ok(JsValue::Undefined)
                            }
                        },
                        None => Ok(JsValue::Undefined)
                    }
                }

                pub(crate) fn [<js_get_all_ $value_type:lower>](
                    this: &JsValue,
                    _: &[JsValue],
                    context: &mut Context
                ) -> JsResult<JsValue> {
                    let object = js_convert!(this, as_object);
                    let Some(message) = object.downcast_ref::<crate::message::SerializedMessage>() else {
                        return js_error!("failed to cast object to SerializedMessage");
                    };

                    // Get all fields.
                    let fields = JsArray::new(context);
                    for (field_id, value) in &message.inner {
                        if let Value::$value_type(_) = value {
                            let field_id = (*field_id).try_into_js(context)?;
                            let field_value = value.try_into_js(context)?;

                            let object = JsArray::new(context);
                            object.push(field_id, context)?;
                            object.push(field_value, context)?;

                            fields.push(object, context)?;
                        }
                    }

                    Ok(fields.into())
                }
            }
        )*
    };
}

/// Generates the code to declare the JavaScript prototype methods.
macro_rules! js_impl {
    ($class:expr => $($value_type:ident),*) => {
        paste! {
            $(
                $class.method(
                    js_string!(stringify!([<$value_type:lower>])), 1,
                    NativeFunction::from_fn_ptr(Self::[<js_get_ $value_type:lower>])
                );

                $class.method(
                    js_string!(stringify!([<all $value_type>])), 1,
                    NativeFunction::from_fn_ptr(Self::[<js_get_all_ $value_type:lower>])
                );
            )*
        }
    };
}

/// A protobuf-encoded message.
#[derive(Debug, JsData, Trace, Finalize, TryIntoJs)]
pub struct SerializedMessage {
    #[unsafe_ignore_trace]
    inner: HashMap<i32, Value>
}

impl SerializedMessage {
    /// Converts a `protoshark` message into a JavaScript-convertable message.
    pub fn from(message: &ProtoMessage) -> Self {
        let mut map = HashMap::new();
        
        // Convert every value in the map.
        for entry in message {
            let (key, value) = entry;
            let value = match value {
                ProtoValue::VarInt(value) => Value::VarInt(value.clone()),
                ProtoValue::Float(value) => Value::Float(value.clone()),
                ProtoValue::Double(value) => Value::Double(value.clone()),
                ProtoValue::String(value) => Value::String(value.clone()),
                ProtoValue::Bytes(value) => Value::Bytes(value.clone()),
                ProtoValue::Message(value) => Value::Message(SerializedMessage::from(value))
            };
            
            map.insert(*key, value);
        }
        
        SerializedMessage { inner: map }
    }

    /// Converts a `protoshark` message into a JavaScript object.
    ///
    /// Under the hood, this uses `SerializedMessage::from`.
    pub fn from_to_js(context: &mut Context, message: &ProtoMessage) -> Result<JsObject> {
        let message = Self::from(message);
        Ok(js_catch!(Self::from_data(message, context)))
    }

    /// Fetches a value from the message.
    ///
    /// Returns `None` if the field with the given ID does not exist.
    pub fn get(&self, key: i32) -> Option<&Value> {
        self.inner.get(&key)
    }

    /// A JavaScript-friendly implementation of `SerializedMessage::get`.
    ///
    /// # Example (JavaScript)
    ///
    /// ```js
    /// const message = new SerializedMessage();
    /// const value = message.get(1); // Returns the value at field ID 1.
    ///
    /// if (value == undefined) {
    ///     // When the value doesn't exist, it returns `undefined`.
    ///     info("Field does not exist.");
    /// } else {
    ///    info("Field exists.");
    /// }
    /// ```
    pub(crate) fn js_get(this: &JsValue, args: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
        // Get the object.
        let object = js_convert!(this, as_object);
        // Cast into a `SerializedMessage`.
        let Some(message) = object.downcast_ref::<SerializedMessage>() else {
            return js_error!("failed to cast object to SerializedMessage");
        };

        // Invoke the message's `get` method.
        let Some(field_id) = args.get(0) else {
            return js_error!("missing field ID");
        };
        let field_id = js_convert!(field_id, as_number) as i32;

        let value = message.get(field_id);
        match value {
            Some(value) => value.try_into_js(context),
            None => Ok(JsValue::Undefined)
        }
    }

    /// A JavaScript-friendly method to enumerate over all keys of the message.
    pub(crate) fn js_keys(this: &JsValue, _: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
        // Get the object.
        let object = js_convert!(this, as_object);
        // Cast into a `SerializedMessage`.
        let Some(message) = object.downcast_ref::<SerializedMessage>() else {
            return js_error!("failed to cast object to SerializedMessage");
        };

        let array = JsArray::new(context);
        message.inner.keys().for_each(|key| {
            let _ = array.push((*key).try_into_js(context).unwrap(), context);
        });

        Ok(array.into())
    }

    js_method!(VarInt, Float, Double, String, Bytes, Message);
}

impl Class for SerializedMessage {
    const NAME: &'static str = "SerializedMessage";

    /// This `init` function is where we mutate the 'prototype' of the class.
    ///
    /// In essence, this is where we add methods for JavaScript to call on the object.
    fn init(class: &mut ClassBuilder<'_>) -> JsResult<()> {
        class.method(
            js_string!("get"), 1,
            NativeFunction::from_fn_ptr(Self::js_get)
        );

        class.method(
            js_string!("keys"), 0,
            NativeFunction::from_fn_ptr(Self::js_keys)
        );

        js_impl!(class => VarInt, Float, Double, String, Bytes, Message);

        Ok(())
    }

    /// Since we don't need to construct the `SerializedMessage` in JavaScript,
    /// we don't add any functionality to the constructor.
    /// 
    /// If it is called anyway, we return an empty message.
    fn data_constructor(_: &JsValue, _: &[JsValue], _: &mut Context) -> JsResult<Self> {
        Ok(SerializedMessage { inner: HashMap::new() })
    }
}

/// Represents one (or multiple) values in a protobuf-encoded message.
#[derive(Debug)]
pub enum Value {
    VarInt(VarInt),
    Float(f32),
    Double(f64),
    String(String),
    Bytes(Vec<u8>),
    Message(SerializedMessage)
}

impl TryIntoJs for Value {
    fn try_into_js(&self, context: &mut Context) -> JsResult<JsValue> {
        match self {
            Value::VarInt(value) => {
                let number = Number::closest(value.clone());
                match number {
                    Number::Integer(value) => value.try_into_js(context),
                    Number::UnsignedInteger(value) => value.try_into_js(context),
                    Number::Long(value) => value.try_into_js(context),
                    Number::UnsignedLong(value) => value.try_into_js(context)
                }
            },
            Value::Float(value) => value.try_into_js(context),
            Value::Double(value) => value.try_into_js(context),
            Value::String(value) => value.try_into_js(context),
            Value::Bytes(value) => value.try_into_js(context),
            Value::Message(value) => value.try_into_js(context)
        }
    }
}