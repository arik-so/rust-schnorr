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

mod tests {
    use num::{BigInt, Num};
    use std::str::FromStr;

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
}