use std::{collections::BTreeMap, fmt, str::FromStr};

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Default, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd)]
#[schemars(with = "String")]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    pub fn of_bytes(value: impl AsRef<[u8]>) -> Self {
        Self(Sha256::digest(value.as_ref()).into())
    }

    pub fn of_json(value: &Value) -> Self {
        let canonical = canonical_json(value);
        Self::of_bytes(serde_json::to_vec(&canonical).expect("canonical JSON serializes"))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", hex::encode(self.0))
    }
}

impl FromStr for Sha256Digest {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let raw = value
            .strip_prefix("sha256:")
            .ok_or("missing sha256 prefix")?;
        let bytes = hex::decode(raw).map_err(|_| "invalid hex digest")?;
        let array: [u8; 32] = bytes.try_into().map_err(|_| "invalid digest length")?;
        Ok(Self(array))
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(D::Error::custom)
    }
}

pub fn canonical_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let ordered: BTreeMap<_, _> = map
                .iter()
                .map(|(key, value)| (key.clone(), canonical_json(value)))
                .collect();
            serde_json::to_value(ordered).expect("ordered JSON serializes")
        }
        Value::Array(values) => Value::Array(values.iter().map(canonical_json).collect()),
        primitive => primitive.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn object_order_does_not_change_digest() {
        assert_eq!(
            Sha256Digest::of_json(&json!({"a": 1, "b": 2})),
            Sha256Digest::of_json(&json!({"b": 2, "a": 1}))
        );
    }

    #[test]
    fn digest_round_trips() {
        let digest = Sha256Digest::of_bytes("gaugemesh");
        assert_eq!(digest.to_string().parse(), Ok(digest));
    }
}
