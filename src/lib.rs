// Base64 encoding extended with HRP and mnemonic checksum information
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2024 by
//     Dr Maxim Orlovsky <orlovsky@ubideco.//>
//
// Copyright (C) 2024 UBIDECO Institute, Switzerland. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[macro_use]
extern crate amplify;
pub extern crate base64;

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use base64::Engine;
use sha2::Digest;

pub const ID_MIN_LEN: usize = 4;
pub const HRI_MAX_LEN: usize = 16;

pub const BAID64_ALPHABET: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_~";

fn check<const LEN: usize>(hri: &'static str, payload: [u8; LEN]) -> [u8; 4] {
    let key = sha2::Sha256::digest(hri.as_bytes());
    let mut sha = sha2::Sha256::new_with_prefix(key);
    sha.update(payload);
    let sha = sha.finalize();
    [sha[0], sha[1], sha[1], sha[2]]
}

pub trait DisplayBaid64<const LEN: usize = 32> {
    const HRI: &'static str;
    const CHUNKING: bool;
    const PREFIX: bool;
    const EMBED_CHECKSUM: bool;
    const MNEMONIC: bool;
    const CHUNK_FIRST: usize = 8;
    const CHUNK_LEN: usize = 7;

    fn to_baid64_payload(&self) -> [u8; LEN];
    fn to_baid64_string(&self) -> String { self.display_baid64().to_string() }
    fn to_baid64_mnemonic(&self) -> String { self.display_baid64().mnemonic }
    fn display_baid64(&self) -> Baid64Display<LEN> {
        Baid64Display::with(
            Self::HRI,
            self.to_baid64_payload(),
            Self::CHUNKING,
            Self::CHUNK_FIRST,
            Self::CHUNK_LEN,
            Self::PREFIX,
            Self::MNEMONIC,
            Self::EMBED_CHECKSUM,
        )
    }
    fn fmt_baid64(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(&self.display_baid64(), f)
    }
}

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum Baid64ParseError {
    /// invalid human-readable prefix in {0} ({1} is expected).
    InvalidHri(String, &'static str),

    /// invalid length of identifier {0}.
    InvalidLen(String),

    /// invalid checksum value in {0} - expected {1:#x} while found
    /// {2:#x}.
    InvalidChecksum(String, u32, u32),

    /// invalid length of mnemonic in {0}.
    InvalidMnemonicLen(String),

    #[from]
    #[display(inner)]
    InvalidMnemonic(mnemonic::Error),

    #[from]
    #[display(inner)]
    Base64(base64::DecodeError),

    /// invalid Baid64 payload - {0}
    InvalidPayload(String),
}

pub trait FromBaid64Str<const LEN: usize = 32>
where
    Self: DisplayBaid64<LEN> + TryFrom<[u8; LEN]>,
    <Self as TryFrom<[u8; LEN]>>::Error: Error,
{
    fn from_baid64_str(mut s: &str) -> Result<Self, Baid64ParseError> {
        let orig = s;

        use base64::alphabet::Alphabet;
        use base64::engine::GeneralPurpose;
        use base64::engine::general_purpose::NO_PAD;

        let mut checksum = None;

        if let Some((hri, rest)) = s.rsplit_once(':') {
            if hri != Self::HRI {
                return Err(Baid64ParseError::InvalidHri(orig.to_owned(), Self::HRI));
            }
            s = rest;
        }

        if let Some((rest, sfx)) = s.split_once('#') {
            let mut mnemo = Vec::<u8>::with_capacity(4);
            mnemonic::decode(sfx, &mut mnemo)?;
            if mnemo.len() != 4 {
                return Err(Baid64ParseError::InvalidMnemonicLen(orig.to_string()));
            }
            checksum = Some([mnemo[0], mnemo[1], mnemo[2], mnemo[3]]);
            s = rest;
        }

        let s = if s.contains('-') {
            s.replace('-', "")
        } else {
            s.to_owned()
        };

        let alphabet = Alphabet::new(BAID64_ALPHABET).expect("invalid Baid64 alphabet");
        let engine = GeneralPurpose::new(&alphabet, NO_PAD);
        let data = engine.decode(s)?;

        if data.len() != LEN && data.len() != LEN + 4 {
            return Err(Baid64ParseError::InvalidLen(orig.to_owned()));
        }
        let mut payload = [0u8; LEN];
        payload.copy_from_slice(&data[..LEN]);
        if data.len() == LEN + 4 {
            checksum = Some([data[LEN], data[LEN + 1], data[LEN + 2], data[LEN + 3]]);
        }

        let ck = check(Self::HRI, payload);
        if matches!(checksum, Some(c) if c != ck) {
            return Err(Baid64ParseError::InvalidChecksum(
                orig.to_owned(),
                u32::from_le_bytes(ck),
                u32::from_le_bytes(checksum.unwrap()),
            ));
        }

        Self::try_from(payload).map_err(|e| Baid64ParseError::InvalidPayload(e.to_string()))
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct Baid64Display<const LEN: usize = 32> {
    hri: &'static str,
    chunking: bool,
    chunk_first: usize,
    chunk_len: usize,
    mnemonic: String,
    prefix: bool,
    suffix: bool,
    embed_checksum: bool,
    checksum: [u8; 4],
    payload: [u8; LEN],
}

impl<const LEN: usize> Baid64Display<LEN> {
    pub fn with(
        hri: &'static str,
        payload: [u8; LEN],
        chunking: bool,
        chunk_first: usize,
        chunk_len: usize,
        prefix: bool,
        suffix: bool,
        embed_checksum: bool,
    ) -> Self {
        debug_assert!(
            hri.len() <= HRI_MAX_LEN,
            "HRI is too long; it must not exceed {HRI_MAX_LEN} bytes"
        );
        debug_assert!(LEN >= ID_MIN_LEN, "Baid64 id payload must be at least {ID_MIN_LEN} bytes");

        let checksum = check(hri, payload);
        let mnemonic = mnemonic::to_string(checksum);

        Self {
            hri,
            chunking,
            chunk_first,
            chunk_len,
            mnemonic,
            prefix,
            suffix,
            embed_checksum,
            checksum,
            payload,
        }
    }

    pub fn new(hri: &'static str, payload: [u8; LEN]) -> Self {
        Self::with(hri, payload, false, 8, 7, false, false, false)
    }
    pub const fn use_hri(mut self) -> Self {
        self.prefix = true;
        self
    }
    pub const fn use_chunking(mut self) -> Self {
        self.chunking = true;
        self
    }
    pub const fn use_mnemonic(mut self) -> Self {
        self.suffix = true;
        self
    }
    pub const fn embed_checksum(mut self) -> Self {
        self.embed_checksum = true;
        self
    }

    pub const fn human_identifier(&self) -> &'static str { self.hri }

    pub fn mnemonic(&self) -> &str { self.mnemonic.as_str() }
    pub const fn checksum(&self) -> [u8; 4] { self.checksum }
}

impl<const LEN: usize> Display for Baid64Display<LEN> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use base64::alphabet::Alphabet;
        use base64::engine::GeneralPurpose;
        use base64::engine::general_purpose::NO_PAD;

        if (self.prefix && !f.sign_minus()) || (!self.prefix && f.sign_minus()) {
            write!(f, "{}:", self.hri)?;
        }

        let alphabet = Alphabet::new(BAID64_ALPHABET).expect("invalid Baid64 alphabet");
        let engine = GeneralPurpose::new(&alphabet, NO_PAD);

        let mut payload = self.payload.to_vec();
        if self.embed_checksum {
            payload.extend(self.checksum);
        }
        let s = engine.encode(payload);

        if self.chunking {
            let bytes = s.as_bytes();
            f.write_str(&String::from_utf8_lossy(&bytes[..self.chunk_first]))?;
            for chunk in bytes[self.chunk_first..].chunks(self.chunk_len) {
                write!(f, "-{}", &String::from_utf8_lossy(chunk))?;
            }
        } else {
            f.write_str(&s)?;
        }

        if (self.suffix && !f.alternate()) || (!self.suffix && f.alternate()) {
            write!(f, "#{}", self.mnemonic)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use base64::alphabet::Alphabet;
    use base64::engine::GeneralPurpose;
    use fmt::Write;
    use sha2::{Digest, Sha256};

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestBaid64 {
        payload: [u8; 32],
    }

    impl DisplayBaid64<32> for TestBaid64 {
        const HRI: &'static str = "testHRI";
        const CHUNKING: bool = false;
        const PREFIX: bool = true;
        const EMBED_CHECKSUM: bool = true;
        const MNEMONIC: bool = true;

        fn to_baid64_payload(&self) -> [u8; 32] { self.payload }
    }

    impl TryFrom<[u8; 32]> for TestBaid64 {
        type Error = Infallible;

        fn try_from(_value: [u8; 32]) -> Result<Self, Self::Error> {
            Ok(TestBaid64 { payload: _value })
        }
    }

    impl FromBaid64Str for TestBaid64 {}

    /// Test the `check` function for accurate checksum computation.
    #[test]
    fn test_check_function() {
        let hri = "testHRI";
        let payload: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];

        // Manually compute the expected checksum
        let key = Sha256::digest(hri.as_bytes());
        let mut sha = Sha256::new_with_prefix(key);
        sha.update(payload);
        let sha_result = sha.finalize();
        let expected = [sha_result[0], sha_result[1], sha_result[1], sha_result[2]];

        let result = check(hri, payload);
        assert_eq!(result, expected, "Checksum does not match expected value");
    }

    /// Test the `Baid64Display` struct for correct initialization and checksum.
    #[test]
    fn test_baid64_display() {
        let hri = "testHRI";
        let payload: [u8; 32] = [1; 32];
        let display = Baid64Display::with(
            hri, payload, true, // chunking
            true, // prefix
            true, // suffix (mnemonic)
            true, // embed_checksum
        );

        assert_eq!(display.hri, hri);
        assert_eq!(display.payload, payload);
        assert!(display.chunking);
        assert!(display.prefix);
        assert!(display.suffix);
        assert!(display.embed_checksum);
        // Since payload is all 1s and hri is "testHRI", compute the expected checksum
        let expected_checksum = check(hri, payload);
        assert_eq!(display.checksum, expected_checksum);
        // Since mnemonic is derived from checksum
        let expected_mnemonic = mnemonic::to_string(expected_checksum);
        assert_eq!(display.mnemonic, expected_mnemonic);
    }

    /// Test the `Display` implementation of `Baid64Display` for correct
    /// formatting.
    #[test]
    fn test_baid64_display_fmt() {
        let hri = "testHRI";
        let payload: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
        let display = Baid64Display::with(
            hri, payload, // Using LEN=4 for simplicity in test
            false,   // chunking
            true,    // prefix
            true,    // suffix (mnemonic)
            true,    // embed_checksum
        );

        // Manually compute the expected string
        let mut expected = format!("{}:", hri);
        let alphabet = Alphabet::new(BAID64_ALPHABET).expect("invalid Baid64 alphabet");
        let engine = GeneralPurpose::new(&alphabet, base64::engine::general_purpose::NO_PAD);
        let mut encoded_payload = payload.to_vec();
        encoded_payload.extend(display.checksum);
        let encoded_str = engine.encode(encoded_payload);
        expected.push_str(&encoded_str);
        expected.push('#');
        expected.push_str(&display.mnemonic);

        let mut formatted = String::new();
        write!(&mut formatted, "{}", display).unwrap();
        let actual = display.to_string();
        assert_eq!(actual, expected, "Formatted Base64 string does not match expected");
    }

    /// Test the `from_baid64_str` method for accurate parsing and error
    /// handling.
    #[test]
    fn test_from_baid64_str() {
        let hri = "testHRI";
        let payload: [u8; 32] = [2; 32];
        let checksum = check(hri, payload);
        let mnemonic_str = mnemonic::to_string(checksum);

        // Encode payload + checksum
        let alphabet = Alphabet::new(BAID64_ALPHABET).expect("invalid Baid64 alphabet");
        let engine = GeneralPurpose::new(&alphabet, base64::engine::general_purpose::NO_PAD);
        let mut encoded_payload = payload.to_vec();
        let raw_payload = encoded_payload.clone();
        encoded_payload.extend(&checksum);
        let encoded_str = engine.encode(&encoded_payload);
        let encoded_str_without_checksum = engine.encode(&raw_payload);
        // Construct the Baid64 string with prefix and mnemonic
        let baid64_str = format!("{}:{}#{}", hri, encoded_str, mnemonic_str);

        // Parse the Baid64 string
        let parsed =
            TestBaid64::from_baid64_str(&baid64_str).expect("Failed to parse Baid64 string");

        // Verify the parsed payload
        assert_eq!(parsed.payload, payload, "Parsed payload does not match original payload");

        // Test with incorrect HRI
        let bad_hri_str = format!("wrongHRI:{}#{}", encoded_str, mnemonic_str);
        let result = TestBaid64::from_baid64_str(&bad_hri_str);
        match result {
            Err(Baid64ParseError::InvalidHri(orig, expected)) => {
                assert_eq!(orig, bad_hri_str);
                assert_eq!(expected, "testHRI");
            }
            _ => panic!("Expected InvalidHri error"),
        }

        // Test with incorrect checksum
        let bad_checksum = [0x00, 0x00, 0x00, 0x00];
        let bad_mnemonic = mnemonic::to_string(bad_checksum);
        let bad_baid64_str = format!("{}:{}#{}", hri, encoded_str_without_checksum, bad_mnemonic);
        let result = TestBaid64::from_baid64_str(&bad_baid64_str);
        match result {
            Err(Baid64ParseError::InvalidChecksum(orig, expected, found)) => {
                assert_eq!(orig, bad_baid64_str);
                assert_eq!(u32::from_le_bytes(checksum), expected);
                assert_eq!(u32::from_le_bytes(bad_checksum), found);
            }
            e => panic!("Expected InvalidChecksum error, actual error: {:?}", e),
        }

        // Test with invalid Base64
        let invalid_base64_str = format!("{}:invalidbase64#{}", hri, mnemonic_str);
        let result = TestBaid64::from_baid64_str(&invalid_base64_str);
        match result {
            Err(Baid64ParseError::Base64(_)) => {}
            _ => panic!("Expected Base64 error"),
        }

        // Test with missing HRI
        let missing_hri_str = format!("{}#{}", encoded_str, mnemonic_str);
        let result =
            TestBaid64::from_baid64_str(&missing_hri_str).expect("Failed to parse without HRI");
        assert_eq!(
            result.payload, payload,
            "Parsed payload does not match original payload without HRI"
        );

        // Test with missing checksum
        let no_checksum_str = format!("{}:{}", hri, engine.encode(payload));
        let result = TestBaid64::from_baid64_str(&no_checksum_str)
            .expect("Failed to parse without checksum");
        assert_eq!(
            result.payload, payload,
            "Parsed payload does not match original payload without checksum"
        );
    }

    /// Test the end-to-end encoding and decoding process.
    #[test]
    fn test_encode_decode_round_trip() {
        let payload: [u8; 32] = [
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0,
            0xF0, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
            0xDD, 0xEE, 0xFF, 0x00,
        ];

        let test_obj = TestBaid64 { payload };
        let baid64_str = test_obj.to_baid64_string();
        let decoded_obj =
            TestBaid64::from_baid64_str(&baid64_str).expect("Failed to decode Baid64 string");

        assert_eq!(test_obj, decoded_obj, "Round-trip encoding/decoding failed");
    }

    /// Test chunking feature in `Baid64Display`.
    #[test]
    fn test_baid64_display_chunking() {
        let hri = "testHRI";
        let payload: [u8; 32] = [3; 32];
        let display = Baid64Display::with(
            hri, payload, true, // chunking
            true, // prefix
            true, // suffix
            true, // embed_checksum
        );

        // Encode payload + checksum
        let alphabet = Alphabet::new(BAID64_ALPHABET).expect("invalid Baid64 alphabet");
        let engine = GeneralPurpose::new(&alphabet, base64::engine::general_purpose::NO_PAD);
        let mut encoded_payload = payload.to_vec();
        encoded_payload.extend(&display.checksum);
        let encoded_str = engine.encode(&encoded_payload);

        // Apply chunking: first 8 characters, then chunks of 7 separated by '-'
        let mut expected = format!("{}:", hri);
        expected.push_str(&encoded_str[..8]);
        for chunk in encoded_str[8..].as_bytes().chunks(7) {
            expected.push('-');
            expected.push_str(std::str::from_utf8(chunk).unwrap());
        }
        expected.push('#');
        expected.push_str(&display.mnemonic);

        let actual = display.to_string();

        assert_eq!(actual, expected, "Chunked Baid64 string does not match expected format");
    }
}
