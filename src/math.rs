use std::convert::TryInto;
use std::error::Error;
use std::io::ErrorKind;
use std::ops::{Div, Sub};
use std::str::FromStr;

use num::{bigint, BigInt, Integer, Num, ToPrimitive};
use secp256k1::{All, PublicKey, Secp256k1, SecretKey};

lazy_static! {
	pub static ref CURVE: Secp256k1<All> = Secp256k1::new();
	pub static ref GENERATOR: PublicKey = PublicKey::from_str("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
	pub static ref CURVE_ORDER_N: BigInt = BigInt::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap();
	pub static ref FIELD_ORDER_P: BigInt = BigInt::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16).unwrap();
	static ref LEGENDRE_EXPONENT: BigInt = (&*FIELD_ORDER_P).sub(1u8).div(2u8);
}

pub fn quadratic_residue_point_from_x(x: &[u8]) -> Result<PublicKey, Box<dyn Error>> {
	let odd_point = point_from_x(&x, Some(true))?;
	let even_point = point_from_x(&x, Some(false))?;

	let is_odd_residual = is_quadratic_residue(&odd_point);
	let is_even_residual = is_quadratic_residue(&even_point);
	if is_even_residual == is_odd_residual {
		let error = "Coordinates of a point cannot both be (non-)residual";
		return Err(std::io::Error::new(ErrorKind::Other, error).into());
	}

	if is_even_residual {
		return Ok(even_point);
	}
	return Ok(odd_point);
}

pub fn point_from_x(x: &[u8], is_odd: Option<bool>) -> Result<PublicKey, Box<dyn Error>> {
	let prefix = if is_odd.unwrap_or(true) {
		3u8
	} else {
		2u8
	};
	let mut compressed_slice = vec![prefix];
	compressed_slice.extend_from_slice(&x);
	let point = PublicKey::from_slice(&compressed_slice)?;
	return Ok(point);
}

pub fn point_x(point: &PublicKey) -> [u8; 32] {
	let uncompressed = point.serialize_uncompressed();
	return uncompressed[1..33].try_into().unwrap();
}

fn point_y(point: &PublicKey) -> [u8; 32] {
	let uncompressed = point.serialize_uncompressed();
	return uncompressed[33..].try_into().unwrap();
}

pub fn is_quadratic_residue(point: &PublicKey) -> bool {
	let jacobi_check = legendre_point(&point);
	return jacobi_check.to_i8().unwrap_or(-1) == 1;
}

fn legendre_point(point: &PublicKey) -> BigInt {
	// TODO: improve to multiplication of y and z in Jacobian coordinates
	let y_component = point_y(&point);
	let y_bigint = BigInt::from_bytes_be(bigint::Sign::Plus, &y_component);
	let legendre = legendre_int(&y_bigint);
	return legendre;
}

fn legendre_int(value: &BigInt) -> BigInt {
	let legendre = (&value).modpow(&*LEGENDRE_EXPONENT, &*FIELD_ORDER_P);
	return legendre;
}

pub fn negate_int(secret: &SecretKey) -> SecretKey {
	let mut integer = BigInt::from_bytes_be(bigint::Sign::Plus, &secret[..]);
	integer = (&*CURVE_ORDER_N).sub(&integer);
	let (_, negative_integer_bytes) = integer.to_bytes_be();
	let negative_secret = SecretKey::from_slice(negative_integer_bytes.as_slice()).unwrap();
	return negative_secret;
}

#[cfg(test)]
mod tests {
	use std::str::FromStr;

	use num::{BigInt, bigint::Sign, Num, ToPrimitive};
	use rand::prelude::ThreadRng;
	use rand::Rng;
	use secp256k1::{PublicKey, SecretKey};

	#[test]
	fn test_point_from_x() {
		let x_coordinate = "02db04732d5f1270f9e084710124b82bc5d921bcf721be8061f39c747f98702f";
		let x_int = BigInt::from_str_radix(&x_coordinate, 16).unwrap();
		let (_, x_bytes) = x_int.to_bytes_be();
		let odd_point = super::point_from_x(&x_bytes, Some(true)).unwrap();
		let even_point = super::point_from_x(&x_bytes, Some(false)).unwrap();
		assert_eq!(odd_point.to_string(), "0302db04732d5f1270f9e084710124b82bc5d921bcf721be8061f39c747f98702f");
		assert_eq!(even_point.to_string(), "0202db04732d5f1270f9e084710124b82bc5d921bcf721be8061f39c747f98702f");
	}

	#[test]
	fn test_point_x() {
		let odd_point = PublicKey::from_str("0302db04732d5f1270f9e084710124b82bc5d921bcf721be8061f39c747f98702f").unwrap();
		let even_point = PublicKey::from_str("0202db04732d5f1270f9e084710124b82bc5d921bcf721be8061f39c747f98702f").unwrap();
		let odd_x = super::point_x(&odd_point);
		let even_x = super::point_x(&even_point);
		assert_eq!(odd_x, even_x);

		let x_int = BigInt::from_bytes_be(Sign::Plus, &odd_x);
		let x_hex = &x_int.to_str_radix(16);
		assert_eq!(x_hex, "2db04732d5f1270f9e084710124b82bc5d921bcf721be8061f39c747f98702f");
	}

	#[test]
	fn test_point_y() {
		let odd_point = PublicKey::from_str("0302db04732d5f1270f9e084710124b82bc5d921bcf721be8061f39c747f98702f").unwrap();
		let even_point = PublicKey::from_str("0202db04732d5f1270f9e084710124b82bc5d921bcf721be8061f39c747f98702f").unwrap();
		let odd_y = super::point_y(&odd_point);
		let even_y = super::point_y(&even_point);
		assert_ne!(odd_y, even_y);

		let odd_y_int = BigInt::from_bytes_be(Sign::Plus, &odd_y);
		let odd_y_hex = &odd_y_int.to_str_radix(16);
		assert_eq!(odd_y_hex, "ff4ea781bb318cfeaf09edc81e409335da8ad89711716f5f1f5e6def6815093f");

		let even_y_int = BigInt::from_bytes_be(Sign::Plus, &even_y);
		let even_y_hex = &even_y_int.to_str_radix(16);
		assert_eq!(even_y_hex, "b1587e44ce730150f61237e1bf6cca25752768ee8e90a0e0a1920f97eaf2f0");
	}

	#[test]
	fn test_legendre_int() {
		let residue_hex = "b1587e44ce730150f61237e1bf6cca25752768ee8e90a0e0a1920f97eaf2f0";
		let non_residue_hex = "ff4ea781bb318cfeaf09edc81e409335da8ad89711716f5f1f5e6def6815093f";
		let residue_int = BigInt::from_str_radix(&residue_hex, 16).unwrap();
		let non_residue_int = BigInt::from_str_radix(&non_residue_hex, 16).unwrap();
		let residue_legendre = super::legendre_int(&residue_int);
		let non_residue_legendre = super::legendre_int(&non_residue_int);
		assert_eq!(residue_legendre.to_i8().unwrap_or(-1), 1);
		assert_eq!(non_residue_legendre.to_i8().unwrap_or(-1), -1);
	}

	#[test]
	fn test_legendre_point() {
		let residue_point = PublicKey::from_str("0202db04732d5f1270f9e084710124b82bc5d921bcf721be8061f39c747f98702f").unwrap();
		let non_residue_point = PublicKey::from_str("0302db04732d5f1270f9e084710124b82bc5d921bcf721be8061f39c747f98702f").unwrap();
		let residue_legendre = super::legendre_point(&residue_point);
		let non_residue_legendre = super::legendre_point(&non_residue_point);
		assert_eq!(residue_legendre.to_i8().unwrap_or(-1), 1);
		assert_eq!(non_residue_legendre.to_i8().unwrap_or(-1), -1);
	}

	#[test]
	fn test_is_residue_point() {
		let residue_point = PublicKey::from_str("0202db04732d5f1270f9e084710124b82bc5d921bcf721be8061f39c747f98702f").unwrap();
		let non_residue_point = PublicKey::from_str("0302db04732d5f1270f9e084710124b82bc5d921bcf721be8061f39c747f98702f").unwrap();
		let residue_test = super::is_quadratic_residue(&residue_point);
		let non_residue_test = super::is_quadratic_residue(&non_residue_point);
		assert_eq!(residue_test, true);
		assert_eq!(non_residue_test, false);
	}

	#[test]
	fn test_quadratic_residue_point_from_x() {
		let x_coordinate = "02db04732d5f1270f9e084710124b82bc5d921bcf721be8061f39c747f98702f";
		let x_int = BigInt::from_str_radix(&x_coordinate, 16).unwrap();
		let (_, x_bytes) = x_int.to_bytes_be();
		let quadratic_residue_point = super::quadratic_residue_point_from_x(&x_bytes).unwrap();
		assert_eq!(quadratic_residue_point.to_string(), "0202db04732d5f1270f9e084710124b82bc5d921bcf721be8061f39c747f98702f");
	}

	#[test]
	fn test_negate_int() {
		let mut rng = rand::thread_rng();
		let random_bytes = rng.gen::<[u8; 32]>();
		let random_int = SecretKey::from_slice(&random_bytes).unwrap();

		let random_bytes = rng.gen::<[u8; 32]>();
		let random_delta = SecretKey::from_slice(&random_bytes).unwrap();
		assert_ne!(random_int.to_string(), random_delta.to_string());

		let mut sum = random_int.clone();
		sum.add_assign(&random_delta[..]).unwrap();
		assert_ne!(sum.to_string(), random_int.to_string());
		assert_ne!(sum.to_string(), random_delta.to_string());

		let mut original = sum.clone();
		let negative_delta = super::negate_int(&random_delta);
		original.add_assign(&negative_delta[..]);
		assert_eq!(original.to_string(), random_int.to_string());
	}
}
