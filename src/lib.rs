#![no_std]
mod signature;
mod signing_key;
mod verification_key;

pub enum Error {
    MalformedPublicKey,
    InvalidSignature,
    InvalidSliceLength,
}

pub use signature::Signature;
pub use signing_key::SigningKey;
pub use verification_key::{VerificationKey, VerificationKeyBytes};
