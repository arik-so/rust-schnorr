use std::convert::TryInto;
use std::error::Error;
use std::ops::Sub;

use num::{BigInt, bigint, Integer};
use rand::Rng;
use secp256k1::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

use crate::math;

pub struct KeyPair(pub SecretKey, pub PublicKey);

pub struct Signature(pub PublicKey, pub SecretKey);

pub(crate) fn sign_message_raw(sk: &SecretKey, message: &str, randomness_keypair: &KeyPair) -> SecretKey {
	let KeyPair(r_secret, r_point) = randomness_keypair;
	let pk = PublicKey::from_secret_key(&*super::math::CURVE, &sk);

	// calculate the message hash
	// hash input: r_point || pk || message
	let message_hash = compute_message_hash(&r_point, &pk, &message, Some("BIPSchnorr"));
	let mut signature_s = SecretKey::from_slice(&message_hash).unwrap();
	signature_s.mul_assign(&sk[..]).unwrap();
	signature_s.add_assign(&r_secret[..]).unwrap();

	return signature_s;
}

pub(crate) fn verify_signature_raw(pk: &PublicKey, message: &str, signature_s: &SecretKey, r_point: &PublicKey, damage: Option<&PublicKey>) -> bool {
	let message_hash = compute_message_hash(&r_point, &pk, &message, Some("BIPSchnorr"));
	let mut hash_point = pk.clone();
	hash_point.mul_assign(&*math::CURVE, &message_hash).unwrap();
	hash_point = hash_point.combine(&r_point).unwrap();

	let mut s_point = PublicKey::from_secret_key(&*math::CURVE, &signature_s);
	if damage.is_some() {
		s_point = s_point.combine(&damage.unwrap()).unwrap();
	}

	let are_points_equal = hash_point.eq(&s_point);
	return are_points_equal;
}

pub(crate) fn encode_signature(signature_struct: &Signature) -> Vec<u8> {
	let Signature(r_point, signature_s) = signature_struct;
	let mut signature = vec![];
	signature.extend_from_slice(&super::math::point_x(&r_point));
	signature.extend_from_slice(&signature_s[..]);
	return signature;
}

pub(crate) fn decode_signature(signature: &[u8]) -> Result<Signature, Box<dyn Error>> {
	let r_x = &signature[..32];
	let signature_s = &signature[32..];

	let r_point = math::quadratic_residue_point_from_x(&r_x)?;
	let s_secret = SecretKey::from_slice(&signature_s)?;
	return Ok(Signature(r_point, s_secret));
}

pub(crate) fn generate_quadratically_residual_keypair() -> KeyPair {
	let mut rng = rand::thread_rng();
	let sk_bytes = rng.gen::<[u8; 32]>();
	let sk_int = BigInt::from_bytes_be(bigint::Sign::Plus, &sk_bytes[..]);

	// modulate the integer
	let sk_int = sk_int.mod_floor(&*math::CURVE_ORDER_N);
	let (_, sk_bytes) = sk_int.to_bytes_be();
	let padded_sk_bytes = pad_byte_array(sk_bytes.as_slice(), None);
	let mut sk = SecretKey::from_slice(padded_sk_bytes.as_slice()).unwrap();

	// calculate the public key
	let mut pk = PublicKey::from_secret_key(&*math::CURVE, &sk);
	let is_residue = math::is_quadratic_residue(&pk);

	if !is_residue {
		sk = math::negate_int(&sk);
		pk = PublicKey::from_secret_key(&*math::CURVE, &sk);
	}

	return KeyPair(sk, pk);
}

pub(crate) fn calculate_signature_r_keypair(sk: &SecretKey, message: &str) -> KeyPair {
	let pk = PublicKey::from_secret_key(&*math::CURVE, &sk);

	// calculate d
	let mut d = BigInt::from_bytes_be(bigint::Sign::Plus, &sk[..]);
	if !math::is_quadratic_residue(&pk) {
		d = (&*math::CURVE_ORDER_N).sub(&d);
	}

	// calculate k
	let mut hash_preimage = vec![];
	hash_preimage.extend_from_slice(&d.to_signed_bytes_be().as_slice());
	hash_preimage.extend_from_slice(message.as_bytes());
	let hash = compute_tagged_hash(&hash_preimage, "BIPSchnorrDerive");

	// calculate r
	let mut r_secret = SecretKey::from_slice(&hash).unwrap();
	let mut r_point = PublicKey::from_secret_key(&*math::CURVE, &r_secret);
	if !math::is_quadratic_residue(&r_point) {
		r_secret = math::negate_int(&r_secret);
		r_point = PublicKey::from_secret_key(&*math::CURVE, &r_secret);
	}

	return KeyPair(r_secret, r_point);
}

fn compute_message_hash(r_point: &PublicKey, pk: &PublicKey, message: &str, tag: Option<&str>) -> [u8; 32] {
	let r_x_bytes = math::point_x(&r_point);
	let p_x_bytes = math::point_x(&pk);
	let mut hash_preimage = vec![];
	hash_preimage.extend_from_slice(&r_x_bytes);
	hash_preimage.extend_from_slice(&p_x_bytes);
	hash_preimage.extend_from_slice(message.as_bytes());

	let message_tag = tag.unwrap_or("BIPSchnorr");
	return compute_tagged_hash(&hash_preimage[..], &message_tag);
}

fn compute_tagged_hash(data: &[u8], tag: &str) -> [u8; 32] {
	let mut hasher = Sha256::new();
	hasher.input(&tag.as_bytes());
	let tag_hash = hasher.result();

	hasher = Sha256::new();
	hasher.input(&tag_hash.as_slice());
	hasher.input(&tag_hash.as_slice());
	hasher.input(&data);

	let final_hash = hasher.result();
	return final_hash.try_into().unwrap();
}

pub(crate) fn pad_byte_array(data: &[u8], expected_length: Option<usize>) -> Vec<u8> {
	let expected_length = expected_length.unwrap_or(32);
	let given_length = data.len();
	if given_length == expected_length {
		return data.to_vec();
	}
	let delta = expected_length - given_length;
	let mut padded_bytes = vec![0u8; delta];
	padded_bytes.extend_from_slice(&data);
	return padded_bytes;
}

#[cfg(test)]
mod tests {
	use std::str::FromStr;

	use secp256k1::{PublicKey, SecretKey};

	use crate::crypto::pad_byte_array;

	#[test]
	fn test_compute_tagged_hash() {
		let message = b"Hello World!";
		let tag = "BIPSchnorrTest";
		let hash = super::compute_tagged_hash(&message[..], &tag);
		let hash_string = format!("{:?}", &hash);
		assert_eq!(hash_string, "[93, 164, 218, 202, 18, 178, 19, 174, 43, 43, 229, 71, 169, 106, 152, 50, 27, 63, 106, 176, 235, 120, 232, 19, 57, 67, 124, 241, 30, 200, 165, 50]");
	}

	#[test]
	fn test_compute_message_hash() {
		let message = "Arik is rolling his own crypto";
		let public_key = PublicKey::from_str("0219877ed8cc48ed3ac0b4e0295aaecb3b00dc3c1c49049fc566780d054dec1986").unwrap();
		let r_point = PublicKey::from_str("02fe3084cb1cc9163425bff89b0ecfc2a396a9c96270cc783f3e3d89a4a049b5a1").unwrap();

		let auto_tagged_hash = super::compute_message_hash(&r_point, &public_key, &message, None);
		let hash_string = format!("{:?}", &auto_tagged_hash);
		assert_eq!(hash_string, "[125, 119, 65, 57, 140, 214, 233, 246, 147, 118, 83, 40, 216, 109, 0, 222, 49, 146, 106, 81, 224, 156, 229, 0, 149, 66, 219, 117, 90, 178, 244, 223]");

		let custom_tagged_hash = super::compute_message_hash(&r_point, &public_key, &message, Some("BIPArik"));
		let hash_string = format!("{:?}", &custom_tagged_hash);
		assert_eq!(hash_string, "[51, 32, 22, 97, 103, 115, 38, 3, 56, 154, 196, 182, 118, 195, 99, 47, 143, 105, 232, 29, 229, 130, 25, 81, 99, 32, 91, 182, 167, 107, 72, 247]");
	}

	#[test]
	fn test_calculate_r() {
		let message = "Arik is rolling his own crypto";
		let secret_key = SecretKey::from_str("e5d5ca46ab3fe61af6a001e02a5b979ee2c1f205c94804dd575aa6134de43ab3").unwrap();
		let super::KeyPair(_, r_point) = super::calculate_signature_r_keypair(&secret_key, &message);

		assert_eq!(super::math::is_quadratic_residue(&r_point), true);
		assert_eq!(r_point.to_string(), "03fe3084cb1cc9163425bff89b0ecfc2a396a9c96270cc783f3e3d89a4a049b5a1");
	}

	#[test]
	fn test_generate_residue_keypair() {
		for _ in 0..100 {
			let super::KeyPair(_, public_key) = super::generate_quadratically_residual_keypair();
			assert_eq!(super::math::is_quadratic_residue(&public_key), true);
		}
	}

	#[test]
	fn test_signature_codec() {
		let r_point = PublicKey::from_str("03fe3084cb1cc9163425bff89b0ecfc2a396a9c96270cc783f3e3d89a4a049b5a1").unwrap();
		let signature_s = SecretKey::from_str("e5d5ca46ab3fe61af6a001e02a5b979ee2c1f205c94804dd575aa6134de43ab3").unwrap();
		let signature = super::Signature(r_point, signature_s);
		let encoded_signature = super::encode_signature(&signature);
		let restored_signature = super::decode_signature(&encoded_signature).unwrap();
		assert_eq!(restored_signature.0.to_string(), "03fe3084cb1cc9163425bff89b0ecfc2a396a9c96270cc783f3e3d89a4a049b5a1");
		assert_eq!(restored_signature.1.to_string(), "e5d5ca46ab3fe61af6a001e02a5b979ee2c1f205c94804dd575aa6134de43ab3");
	}

	#[test]
	fn test_pad_byte_array() {
		let byte_array = vec![123, 234];
		let padded_array = pad_byte_array(&byte_array, Some(6));
		assert_eq!(padded_array.len(), 6);
		let array_string = format!("{:?}", &padded_array);
		assert_eq!(array_string, "[0, 0, 0, 0, 123, 234]");
	}
}
