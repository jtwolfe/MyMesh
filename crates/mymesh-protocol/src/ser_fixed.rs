//! Serde helpers for arrays larger than 32 bytes (serde's default limit).

pub mod array64 {
    use serde::de::{self, SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S>(data: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeTuple;
        let mut tup = serializer.serialize_tuple(64)?;
        for byte in data.iter() {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ArrayVisitor;

        impl<'de> Visitor<'de> for ArrayVisitor {
            type Value = [u8; 64];

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a 64-byte array")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<[u8; 64], A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut data = [0u8; 64];
                for (i, slot) in data.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                if seq.next_element::<u8>()?.is_some() {
                    return Err(de::Error::invalid_length(65, &self));
                }
                Ok(data)
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<[u8; 64], E>
            where
                E: de::Error,
            {
                v.try_into()
                    .map_err(|_| de::Error::invalid_length(v.len(), &self))
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<[u8; 64], E>
            where
                E: de::Error,
            {
                self.visit_bytes(&v)
            }
        }

        deserializer.deserialize_tuple(64, ArrayVisitor)
    }
}
