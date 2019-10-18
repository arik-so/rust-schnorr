use num::{bigint, BigInt, Num, ToPrimitive, Integer};
use secp256k1::{All, PublicKey, Secp256k1, SecretKey};
use std::convert::TryInto;
use std::ops::{Div, Sub};
use std::str::FromStr;

lazy_static! {
	pub static ref CURVE: Secp256k1<All> = Secp256k1::new();
	pub static ref GENERATOR: PublicKey = PublicKey::from_str("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
	pub static ref CURVE_ORDER_N: BigInt = BigInt::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap();
	pub static ref FIELD_ORDER_P: BigInt = BigInt::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16).unwrap();
	static ref LEGENDRE_EXPONENT: BigInt = (&*FIELD_ORDER_P).sub(1u8).div(2u8);
}

pub fn point_from_x(x: &[u8], is_odd: Option<bool>) -> PublicKey {
    let prefix = if is_odd.unwrap_or(true) {
        3u8
    } else {
        2u8
    };
    let mut compressed_slice = vec![prefix];
    compressed_slice.extend_from_slice(&x);
    let point = PublicKey::from_slice(&compressed_slice).unwrap();
    return point;
}

pub fn point_x(point: &PublicKey) -> [u8; 32] {
    let uncompressed = point.serialize_uncompressed();
    return uncompressed[1..33].try_into().unwrap();
}

fn point_y(point: &PublicKey) -> [u8; 32] {
    let uncompressed = point.serialize_uncompressed();
    return uncompressed[33..].try_into().unwrap();
}

fn legendre_int(value: &BigInt) -> BigInt {
    let legendre = (&value).modpow(&*LEGENDRE_EXPONENT, &*FIELD_ORDER_P);
    return legendre;
}

mod tests {
    use num::{BigInt, Num, bigint::Sign, ToPrimitive};
    use std::str::FromStr;
    use secp256k1::PublicKey;

    #[test]
    fn test_point_from_x() {
        let x_coordinate = "02db04732d5f1270f9e084710124b82bc5d921bcf721be8061f39c747f98702f";
        let x_int = BigInt::from_str_radix(&x_coordinate, 16).unwrap();
        let (_, x_bytes) = x_int.to_bytes_be();
        let odd_point = super::point_from_x(&x_bytes, Some(true));
        let even_point = super::point_from_x(&x_bytes, Some(false));
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
}