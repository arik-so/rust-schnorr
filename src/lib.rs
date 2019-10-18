#[macro_use]
extern crate lazy_static;
extern crate num;
extern crate rand;
extern crate secp256k1;
extern crate sha2;

use secp256k1::{PublicKey, SecretKey};

pub mod crypto;
pub mod math;

pub fn sign_message(sk: &SecretKey, message: &str) -> Vec<u8> {
	let randomness_keypair = crypto::calculate_signature_r_keypair(&sk, &message);
	let signature_s = crypto::sign_message_raw(&sk, &message, &randomness_keypair);

	return crypto::encode_signature(&crypto::Signature(randomness_keypair.1, signature_s));
}

pub fn verify_signature(pk: &PublicKey, message: &str, signature: &[u8]) -> bool {
	let decoded_signature = crypto::decode_signature(&signature);
	if decoded_signature.is_err() {
		return false;
	}
	let crypto::Signature(r_point, s_secret) = decoded_signature.unwrap();
	return crypto::verify_signature_raw(&pk, &message, &s_secret, &r_point, None);
}

#[cfg(test)]
mod tests {
	use std::str::FromStr;

	use secp256k1::{PublicKey, SecretKey};

	#[test]
	fn it_works() {
		let message = "Arik is rolling his own crypto";
		let sk = SecretKey::from_str("e5d5ca46ab3fe61af6a001e02a5b979ee2c1f205c94804dd575aa6134de43ab3").unwrap();
		let signature = super::sign_message(&sk, &message);

		let pk = PublicKey::from_secret_key(&*super::math::CURVE, &sk);
		let is_valid = super::verify_signature(&pk, &message, &signature);
		assert_eq!(is_valid, true);
	}
}
