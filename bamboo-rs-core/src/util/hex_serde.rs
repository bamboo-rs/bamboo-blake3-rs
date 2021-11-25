use blake3::Hash;
use core::borrow::Borrow;
use ed25519_dalek::PublicKey as DalekPublicKey;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serializer};

#[cfg(feature = "std")]
pub fn serialize_pub_key<S>(public_key: &DalekPublicKey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if serializer.is_human_readable() {
        let bytes = hex::encode(public_key.as_bytes());
        serializer.serialize_str(&bytes)
    } else {
        serializer.serialize_bytes(public_key.as_bytes())
    }
}

#[cfg(feature = "std")]
pub fn deserialize_pub_key<'de, D>(deserializer: D) -> Result<DalekPublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        let s: &str = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(s).map_err(Error::custom)?;
        let pub_key = DalekPublicKey::from_bytes(bytes.as_slice()).map_err(Error::custom)?;
        Ok(pub_key)
    } else {
        let bytes: &[u8] = Deserialize::deserialize(deserializer)?;
        let pub_key = DalekPublicKey::from_bytes(bytes).map_err(Error::custom)?;
        Ok(pub_key)
    }
}

pub fn hash_opt_from_hex<'de, D>(deserializer: D) -> Result<Option<Hash>, D::Error>
where
    D: Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        let s: Option<&str> = Deserialize::deserialize(deserializer)?;

        let hash = s.map(|s: &str| Hash::from_hex(s).unwrap());
        Ok(hash)
    } else {
        let bytes: Option<[u8; 32]> = Deserialize::deserialize(deserializer)?;

        Ok(bytes.map(Hash::from))
    }
}

pub fn hash_from_hex<'de, D>(deserializer: D) -> Result<Hash, D::Error>
where
    D: Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        let s: &str = Deserialize::deserialize(deserializer)?;
        Ok(Hash::from_hex(s).unwrap())
    } else {
        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        Ok(Hash::from(bytes))
    }
}

pub fn hex_from_hash<S>(hash: &Hash, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if serializer.is_human_readable() {
        serializer.serialize_str(&hash.to_hex())
    } else {
        serializer.serialize_bytes(hash.as_bytes())
    }
}

pub fn hex_opt_from_hash<S>(hash: &Option<Hash>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if serializer.is_human_readable() {
        match hash {
            Some(hash) => serializer.serialize_some(hash.to_hex().as_str()),
            None => serializer.serialize_none(),
        }
    } else {
        match hash {
            Some(hash) => serializer.serialize_some(hash.as_bytes()),
            None => serializer.serialize_none(),
        }
    }
}
pub fn vec_from_hex<'de, D, B>(deserializer: D) -> Result<B, D::Error>
where
    D: Deserializer<'de>,
    B: From<Vec<u8>>,
{
    if deserializer.is_human_readable() {
        let s: &str = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(s).map_err(Error::custom)?;
        Ok(B::from(bytes))
    } else {
        let bytes: &[u8] = Deserialize::deserialize(deserializer)?;
        Ok(B::from(bytes.to_owned()))
    }
}

pub fn hex_from_bytes<S, B>(bytes: &B, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    B: Borrow<[u8]>,
{
    if serializer.is_human_readable() {
        let bytes = hex::encode(bytes.borrow());
        serializer.serialize_str(&bytes)
    } else {
        serializer.serialize_bytes(bytes.borrow())
    }
}
