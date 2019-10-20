use secp256k1::{PublicKey, SecretKey};

use crate::{crypto, math};

pub struct AdapterSignature {
	damaged_signature: crypto::Signature,
	damage_point: PublicKey,
}

pub struct SecretAdapterSignature {
	signature: AdapterSignature,
	damage: SecretKey,
}

pub fn generate_damaged_signature(sk: &SecretKey, message: &str) -> SecretAdapterSignature {
	let [r_keypair, damage_keypair] = generate_quadratically_residual_damage_keypair_set();

	let mut combined_r_secret = r_keypair.0.clone();
	combined_r_secret.add_assign(&damage_keypair.0[..]);

	let combined_r_point = PublicKey::from_secret_key(&*math::CURVE, &combined_r_secret);
	let combined_r_keypair = crypto::KeyPair(combined_r_secret, combined_r_point);

	let mut damaged_signature = crypto::sign_message_raw(&sk, &message, &combined_r_keypair);
	// subtract the damage from the raw signature
	let delta = math::negate_int(&damage_keypair.0);
	damaged_signature.add_assign(&delta[..]);

	let signature = crypto::Signature(combined_r_point, damaged_signature);
	let adapter_signature = AdapterSignature {
		damaged_signature: signature,
		damage_point: damage_keypair.1,
	};

	return SecretAdapterSignature {
		signature: adapter_signature,
		damage: damage_keypair.0,
	};
}

pub fn verify_adapter_signature(pk: &PublicKey, message: &str, adapter_signature: &AdapterSignature) -> bool {
	let r_point = &adapter_signature.damaged_signature.0;
	let s_secret = &adapter_signature.damaged_signature.1;
	let damage_point = &adapter_signature.damage_point;
	return crypto::verify_signature_raw(&pk, &message, &s_secret, &r_point, Some(&damage_point));
}

fn generate_quadratically_residual_damage_keypair_set() -> [crypto::KeyPair; 2] {
	loop {
		let pair_a = crypto::generate_quadratically_residual_keypair();
		let pair_b = crypto::generate_quadratically_residual_keypair();
		let point_sum = (&pair_a.1).combine(&pair_b.1).unwrap();
		let is_residue = super::math::is_quadratic_residue(&point_sum);
		if is_residue {
			return [pair_a, pair_b];
		}
	}
}

#[cfg(test)]
mod tests {
	use std::str::FromStr;

	use secp256k1::{PublicKey, SecretKey};

	use crate::crypto;

	#[test]
	fn test_generate_residue_keypair_pair() {
		for _ in 0..100 {
			let keypair_pair = super::generate_quadratically_residual_damage_keypair_set();
			let [pair_a, pair_b] = keypair_pair;
			assert_eq!(super::math::is_quadratic_residue(&pair_a.1), true);
			assert_eq!(super::math::is_quadratic_residue(&pair_b.1), true);

			let point_sum = (&pair_a.1).combine(&pair_b.1).unwrap();
			assert_eq!(super::math::is_quadratic_residue(&point_sum), true);
		}
	}

	#[test]
	fn test_adapter_signatures() {
		let message = "Arik is rolling his own crypto";
		let sk = SecretKey::from_str("e5d5ca46ab3fe61af6a001e02a5b979ee2c1f205c94804dd575aa6134de43ab3").unwrap();
		let adapter_signature = super::generate_damaged_signature(&sk, &message);

		let pk = PublicKey::from_secret_key(&*super::math::CURVE, &sk);
		let is_correctly_damaged_signature = super::verify_adapter_signature(&pk, &message, &adapter_signature.signature);
		assert_eq!(is_correctly_damaged_signature, true);

		let raw_signature = adapter_signature.signature.damaged_signature;
		let is_valid_signature = crypto::verify_signature_raw(&pk, &message, &raw_signature.1, &raw_signature.0, None);
		assert_eq!(is_valid_signature, false);
	}
}
