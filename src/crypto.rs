use secp256k1::{All, PublicKey, Secp256k1, SecretKey};

use super::math;

pub struct KeyPair(pub SecretKey, pub PublicKey);

pub struct Signature(pub SecretKey, pub PublicKey);

#[cfg(test)]
mod tests {}
