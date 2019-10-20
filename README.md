# rust-schnorr

Experimental library for Schnorr signatures in Rust.

# Example

```rust
extern crate rust_schnorr;
use rust_schnorr;

fn main() {
    let message = "Arik is rolling his own crypto";
    let sk = SecretKey::from_str("e5d5ca46ab3fe61af6a001e02a5b979ee2c1f205c94804dd575aa6134de43ab3").unwrap();
    let signature = rust_schnorr::sign_message(&sk, &message);

    println!("Signature: {:?}", signature);
}
```
