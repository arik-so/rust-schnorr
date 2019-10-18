#[macro_use]
extern crate lazy_static;
extern crate num;
extern crate rand;
extern crate secp256k1;
extern crate sha2;

pub mod math;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
