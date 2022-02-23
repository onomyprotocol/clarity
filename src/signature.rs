use crate::address::Address;
use crate::constants::SECPK1N;
use crate::context::SECP256K1;
use crate::error::Error;
use crate::u256;
use crate::utils::{
    big_endian_uint256_deserialize, big_endian_uint256_serialize, bytes_to_hex_str,
    hex_str_to_bytes,
};
use crate::Uint256;

use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::Message;
use sha3::{Digest, Keccak256};
use std::fmt::{self, Display};
use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct Signature {
    #[serde(
        serialize_with = "big_endian_uint256_serialize",
        deserialize_with = "big_endian_uint256_deserialize"
    )]
    pub v: Uint256,
    #[serde(
        serialize_with = "big_endian_uint256_serialize",
        deserialize_with = "big_endian_uint256_deserialize"
    )]
    pub r: Uint256,
    #[serde(
        serialize_with = "big_endian_uint256_serialize",
        deserialize_with = "big_endian_uint256_deserialize"
    )]
    pub s: Uint256,
}

impl Signature {
    pub const fn new(v: Uint256, r: Uint256, s: Uint256) -> Signature {
        Signature { v, r, s }
    }

    /// Like is_valid() but returns a reason
    pub fn error_check(&self) -> Result<(), Error> {
        if self.r >= SECPK1N || self.r.is_zero() {
            return Err(Error::InvalidR);
        } else if self.s >= SECPK1N || self.s.is_zero() {
            return Err(Error::InvalidS);
        } else if let Err(e) = self.get_v() {
            return Err(e);
        }

        Ok(())
    }

    pub fn is_valid(&self) -> bool {
        self.error_check().is_ok()
    }

    pub fn network_id(&self) -> Option<Uint256> {
        if self.r.is_zero() && self.s.is_zero() {
            Some(self.v)
        } else if self.v == u256!(27) || self.v == u256!(28) {
            None
        } else {
            Some(
                self.v
                    .wrapping_sub(u256!(1))
                    .shr1()
                    .wrapping_sub(u256!(17)),
            )
        }
    }

    pub fn check_low_s_metropolis(&self) -> Result<(), Error> {
        if self.s > SECPK1N.shr1() {
            return Err(Error::InvalidS);
        }
        Ok(())
    }

    pub fn check_low_s_homestead(&self) -> Result<(), Error> {
        if self.s > SECPK1N.shr1() || self.s.is_zero() {
            return Err(Error::InvalidS);
        }
        Ok(())
    }

    /// Converts a signature into a bytes string.
    ///
    /// A signature in binary form consists of 65 bytes where
    /// first 32 bytes are "r" in big endian form, next 32 bytes are "s"
    /// in big endian form, and at the end there is one byte made of "v".
    ///
    /// This also consumes the signature.
    pub fn into_bytes(self) -> [u8; 65] {
        // Since 0.1.20 it calls `as_bytes` and consumes self
        self.to_bytes()
    }

    /// Extracts signature as bytes.
    ///
    /// This supersedes `into_bytes` as it does not consume the object itself.
    pub fn to_bytes(&self) -> [u8; 65] {
        let mut result = [0x00u8; 65];
        // Put r at the beginning
        result[0..32].copy_from_slice(&self.r.to_u8_array_be());
        // Add s in the middle
        result[32..64].copy_from_slice(&self.s.to_u8_array_be());
        // End up with v at the end
        result[64] = self.v.resize_to_u8();
        result
    }

    /// Constructs a signature from a bytes string
    ///
    /// This is opposite to `into_bytes()` where a signature is created based
    /// on a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 65 {
            return Err(Error::InvalidSignatureLength);
        }

        let r = Uint256::from_bytes_be(&bytes[0..32]).unwrap();
        let s = Uint256::from_bytes_be(&bytes[32..64]).unwrap();
        let v = bytes[64];
        Ok(Signature::new(Uint256::from_u8(v), r, s))
    }

    /// Extract V parameter with regards to network ID. Use this rather than V directly
    pub fn get_v(&self) -> Result<Uint256, Error> {
        if self.v == u256!(27) || self.v == u256!(28) {
            // Valid V values are in {27, 28} according to Ethereum Yellow paper Appendix F (282).
            Ok(self.v)
        } else if self.v >= u256!(37) {
            let network_id = self.network_id().ok_or(Error::InvalidNetworkId)?;
            // // Otherwise we have to extract "v"...
            let vee = self
                .v
                .wrapping_sub(network_id.shl1())
                .wrapping_sub(u256!(8));
            // // ... so after all v will still match 27<=v<=28
            assert!(vee == u256!(27) || vee == u256!(28));
            Ok(vee)
        } else {
            // All other V values would be errorneous for our calculations
            Err(Error::InvalidV)
        }
    }

    /// Recover an address from a signature
    ///
    /// This can be called with any arbitrary signature, and a hashed message.
    pub fn recover(&self, hash: &[u8]) -> Result<Address, Error> {
        // Create recovery ID which is "v" minus 27. Without this it wouldn't be possible to extract recoverable signature.

        // check that it can fit under i32::MAX
        let v = self.get_v()?;
        if v.sig_bits() >= 32 {
            return Err(Error::InvalidV);
        }
        let v = v.resize_to_u32() as i32;
        let v = RecoveryId::from_i32(v.wrapping_sub(27)).map_err(Error::DecodeRecoveryId)?;
        // A message to recover which is a hash of the transaction
        let msg = Message::from_slice(hash).map_err(Error::ParseMessage)?;

        // Get the compact form using bytes, and "v" parameter
        let compact = RecoverableSignature::from_compact(&self.to_bytes()[..64], v)
            .map_err(Error::ParseRecoverableSignature)?;
        // Acquire secp256k1 context from thread local storage
        let pkey = SECP256K1.with(move |object| -> Result<_, Error> {
            // Borrow once and reuse
            let secp256k1 = object.borrow();
            // Recover public key
            let pkey = secp256k1
                .recover_ecdsa(&msg, &compact)
                .map_err(Error::RecoverSignature)?;
            // Serialize the recovered public key in uncompressed format
            Ok(pkey.serialize_uncompressed())
        })?;
        assert_eq!(pkey.len(), 65);
        if pkey[1..].to_vec() == [0x00u8; 64].to_vec() {
            return Err(Error::ZeroPrivKey);
        }
        // Finally an address is last 20 bytes of a hash of the public key.
        let sender = Keccak256::digest(&pkey[1..]);
        debug_assert_eq!(sender.len(), 32);
        Address::from_slice(&sender[12..])
    }
}

impl Default for Signature {
    fn default() -> Signature {
        Signature {
            r: u256!(0),
            v: u256!(0),
            s: u256!(0),
        }
    }
}

impl Display for Signature {
    // Constructs a string from a given signature
    // The resulting string's length is 130
    // first 32 bytes is "r" value
    // second 32 bytes i s "s" value
    // last byte is "v"
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", bytes_to_hex_str(&self.to_bytes()))
    }
}

impl FromStr for Signature {
    type Err = Error;
    /// Constructs a signature back from a string representation
    ///
    /// The input string's length should be exactly 130 not including
    /// optional "0x" prefix at the beggining.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Strip optional prefix
        let s = match s.strip_prefix("0x") {
            Some(s) => s,
            None => s,
        };

        // Parse hexadecimal form back to bytes
        let bytes = hex_str_to_bytes(s)?;
        Signature::from_bytes(&bytes)
    }
}

impl fmt::LowerHex for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            write!(
                f,
                "0x{}",
                bytes_to_hex_str(&self.clone().to_bytes()).to_lowercase()
            )
        } else {
            write!(
                f,
                "{}",
                bytes_to_hex_str(&self.clone().to_bytes()).to_lowercase()
            )
        }
    }
}

impl fmt::UpperHex for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            write!(f, "0x{}", bytes_to_hex_str(&self.to_bytes()).to_uppercase())
        } else {
            write!(f, "{}", bytes_to_hex_str(&self.to_bytes()).to_uppercase())
        }
    }
}

#[cfg(test)]
const SIG123: Signature = Signature::new(u256!(1), u256!(2), u256!(3));

#[test]
fn new_signature() {
    let sig = SIG123;
    assert_eq!(sig.v, u256!(1));
    assert_eq!(sig.r, u256!(2));
    assert_eq!(sig.s, u256!(3));
}

#[test]
fn to_string() {
    let sig = SIG123;
    let sig_string = sig.to_string();
    assert_eq!(
        sig_string,
        concat!(
            "0x",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000000000000000000000000000000000000000000003",
            "01"
        )
    );
    let new_sig = Signature::from_str(&sig_string).expect("Unable to parse signature");
    assert_eq!(sig, new_sig);

    // Without 0x
    assert!(sig_string.starts_with("0x"));
    let new_sig = Signature::from_str(&sig_string[2..]).expect("Unable to parse signature");
    assert_eq!(sig, new_sig);
}

#[test]
fn to_upper_hex() {
    let sig = Signature::new(u256!(1), u256!(65450), u256!(32456));
    let sig_string = format!("{:#X}", sig);
    assert_eq!(
        sig_string,
        concat!(
            "0x",
            "000000000000000000000000000000000000000000000000000000000000FFAA",
            "0000000000000000000000000000000000000000000000000000000000007EC8",
            "01"
        )
    );
    let sig_string = format!("{:X}", sig);
    assert_eq!(
        sig_string,
        concat!(
            "000000000000000000000000000000000000000000000000000000000000FFAA",
            "0000000000000000000000000000000000000000000000000000000000007EC8",
            "01"
        )
    );
}
#[test]
fn to_lower_hex() {
    let sig = Signature::new(u256!(1), u256!(65450), u256!(32456));
    let sig_string = format!("{:#x}", sig);
    assert_eq!(
        sig_string,
        concat!(
            "0x",
            "000000000000000000000000000000000000000000000000000000000000ffaa",
            "0000000000000000000000000000000000000000000000000000000000007ec8",
            "01"
        )
    );
    let sig_string = format!("{:x}", sig);
    assert_eq!(
        sig_string,
        concat!(
            "000000000000000000000000000000000000000000000000000000000000ffaa",
            "0000000000000000000000000000000000000000000000000000000000007ec8",
            "01"
        )
    );
}

#[test]
fn into_bytes() {
    let sig = SIG123;

    let sig_bytes = sig.to_bytes();
    assert_eq!(
        sig_bytes.to_vec(),
        vec![
            /* r */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 2, /* s */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, /* v */ 1
        ],
    );

    let new_sig = Signature::from_bytes(&sig_bytes).expect("Unable to reconstruct signature");
    assert_eq!(sig, new_sig);
}

#[test]
fn to_string_with_zero_v() {
    let mut sig = SIG123;
    sig.v = u256!(0);
    let sig_str = sig.to_string();
    assert_eq!(
        sig_str,
        concat!(
            "0x",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000000000000000000000000000000000000000000003",
            "00"
        )
    );

    let new_sig = Signature::from_str(&sig_str).expect("Unable to reconstruct signature");
    assert_eq!(sig, new_sig);
}

#[test]
#[should_panic]
fn parse_invalid_signature() {
    let _sig: Signature = "deadbeef".parse().unwrap();
    let _sig: Signature = "0x".parse().unwrap();
}

#[test]
fn generate_ethereum_signature() {
    use crate::PrivateKey;
    let private_key: PrivateKey =
        "0xc5e8f61d1ab959b397eecc0a37a6517b8e67a0e7cf1f4bce5591f3ed80199122"
            .parse()
            .unwrap();
    let address: Address = "0xc783df8a850f42e7F7e57013759C285caa701eB6"
        .parse()
        .unwrap();
    let checkpoint =
        hex_str_to_bytes("0x666f6f0000000000000000000000000000000000000000000000000000000000636865636b706f696e7400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000003000000000000000000000000c783df8a850f42e7f7e57013759c285caa701eb6000000000000000000000000ead9c93b79ae7c1591b1fb5323bd777e86e150d4000000000000000000000000e5904695748fe4a84b40b3fc79de2277660bd1d300000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000d050000000000000000000000000000000000000000000000000000000000000d050000000000000000000000000000000000000000000000000000000000000d05")
            .unwrap();
    let sig: Signature = "0xe108a7776de6b87183b0690484a74daef44aa6daf907e91abaf7bbfa426ae7706b12e0bd44ef7b0634710d99c2d81087a2f39e075158212343a3b2948ecf33d01c".parse().unwrap();

    assert_eq!(private_key.to_address(), address);

    let generated_sig = private_key.sign_ethereum_msg(&checkpoint);
    assert_eq!(sig, generated_sig)
}

#[test]
fn parse_hex_signature() {
    let sig: Signature = "0xe108a7776de6b87183b0690484a74daef44aa6daf907e91abaf7bbfa426ae7706b12e0bd44ef7b0634710d99c2d81087a2f39e075158212343a3b2948ecf33d01c".parse().unwrap();
    let correct_r =
        hex_str_to_bytes("0xe108a7776de6b87183b0690484a74daef44aa6daf907e91abaf7bbfa426ae770")
            .unwrap();
    let correct_s =
        hex_str_to_bytes("0x6b12e0bd44ef7b0634710d99c2d81087a2f39e075158212343a3b2948ecf33d0")
            .unwrap();
    let correct_v = vec![28u8];

    assert_eq!(sig.r, Uint256::from_bytes_be(&correct_r).unwrap());
    assert_eq!(sig.s, Uint256::from_bytes_be(&correct_s).unwrap());
    assert_eq!(sig.v, Uint256::from_bytes_be(&correct_v).unwrap());
}
