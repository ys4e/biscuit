use std::collections::HashMap;
use boa_engine::{Context, JsResult, JsValue};
use boa_engine::value::TryIntoJs;
use protoshark::{Number, SerializedMessage as ProtoMessage, Value as ProtoValue, VarInt};

/// A protobuf-encoded message.
#[derive(Debug, TryIntoJs)]
pub struct SerializedMessage {
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