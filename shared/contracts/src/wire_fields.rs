//! The wire names of a struct's fields, as its own `Deserialize` declares them.
//!
//! Read from the derive rather than listed by hand, so a check of "does this
//! message carry a key the receiver does not know" and a golden of a payload's
//! shape cannot drift from the struct they describe.

use serde::de::{self, DeserializeOwned, Deserializer, Visitor};

/// Every field name `T` accepts, after `rename_all`. Empty for a type that is
/// not a plain named-field struct (an enum, a map, a struct with `flatten`).
pub fn struct_wire_fields<T: DeserializeOwned>() -> &'static [&'static str] {
    let mut fields: &'static [&'static str] = &[];
    // The probe always ends the deserialization with an error, once the
    // field list has been handed over.
    let _ = T::deserialize(FieldProbe(&mut fields));
    fields
}

/// The keys of `payload` that `T` does not declare, in payload order.
pub fn unknown_wire_keys<T: DeserializeOwned>(
    payload: &serde_json::Map<String, serde_json::Value>,
) -> Vec<&str> {
    let known = struct_wire_fields::<T>();
    payload
        .keys()
        .map(String::as_str)
        .filter(|key| !known.contains(key))
        .collect()
}

struct FieldProbe<'a>(&'a mut &'static [&'static str]);

impl<'de> Deserializer<'de> for FieldProbe<'_> {
    type Error = de::value::Error;

    fn deserialize_any<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
        Err(de::Error::custom("not a named-field struct"))
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Self::Error> {
        *self.0 = fields;
        Err(de::Error::custom("field probe"))
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map enum identifier ignored_any
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(rename_all = "kebab-case")]
    #[allow(dead_code)]
    struct Sample {
        first_field: u32,
        #[serde(default)]
        second: bool,
        #[serde(rename = "third-one")]
        third: String,
    }

    #[test]
    fn the_fields_are_the_renamed_wire_names() {
        assert_eq!(
            struct_wire_fields::<Sample>(),
            ["first-field", "second", "third-one"]
        );
    }

    #[test]
    fn a_non_struct_has_no_fields() {
        assert!(struct_wire_fields::<Vec<u32>>().is_empty());
        assert!(struct_wire_fields::<String>().is_empty());
    }

    #[test]
    fn unknown_keys_are_the_ones_the_struct_does_not_declare() {
        let payload = serde_json::json!({
            "first-field": 1,
            "kill-switch-enabled": true,
            "third-one": "x",
            "first_field": 2,
        });
        let map = payload.as_object().cloned().unwrap_or_default();
        let mut unknown = unknown_wire_keys::<Sample>(&map);
        unknown.sort_unstable();
        assert_eq!(unknown, ["first_field", "kill-switch-enabled"]);
    }
}
