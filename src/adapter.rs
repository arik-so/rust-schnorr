use crate::{crypto, math};

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
}
