pub mod numbers;

use core::str;
use std::fmt::{Debug, Display};

#[derive(Debug)]
pub struct ParseError(pub String);
impl Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ParseError {}

pub type Result<T, E = ParseError> = std::result::Result<T, E>;

#[derive(Clone)]
pub struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self(data)
    }

    pub fn remaining(&self) -> &[u8] {
        self.0
    }

    pub fn has_data(&self) -> bool {
        !self.0.is_empty()
    }

    pub fn u8(&mut self) -> Result<u8> {
        let arr = self.array::<1>()?;
        Ok(arr[0])
    }

    pub fn u32(&mut self) -> Result<u32> {
        let arr = self.array()?;
        Ok(u32::from_be_bytes(arr))
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        assert!(N < 100_000);
        if self.0.len() < N {
            return Err(ParseError(format!(
                "packet too short, expected {N} but found {}",
                self.0.len()
            )));
        }
        let result = self.0[..N].try_into().unwrap();
        self.0 = &self.0[N..];
        Ok(result)
    }

    pub fn slice(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.0.len() < len {
            return Err(ParseError(format!(
                "packet too short, expected {len} but found {}",
                self.0.len()
            )));
        }
        if len > 100_000 {
            return Err(ParseError(format!("bytes too long: {len}")));
        }
        let result = &self.0[..len];
        self.0 = &self.0[len..];
        Ok(result)
    }

    pub fn bool(&mut self) -> Result<bool> {
        let b = self.u8()?;
        match b {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ParseError(format!("invalid bool: {b}"))),
        }
    }

    pub fn name_list(&mut self) -> Result<NameList<'a>> {
        let list = self.utf8_string()?;
        Ok(NameList(list))
    }

    pub fn mpint(&mut self) -> Result<&'a [u8]> {
        let mut s = self.string()?;

        if s.first() == Some(&0) {
            // Skip the leading zero byte in case the number is negative.
            s = &s[1..];
        }

        Ok(s)
    }

    pub fn string(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()?;
        let data = self.slice(len.try_into().unwrap())?;
        Ok(data)
    }

    pub fn utf8_string(&mut self) -> Result<&'a str> {
        let s = self.string()?;
        let Ok(s) = str::from_utf8(s) else {
            return Err(ParseError(format!("name-list is invalid UTF-8")));
        };
        Ok(s)
    }
}

/// A writer for the SSH wire format.
pub struct Writer(Vec<u8>);

impl Writer {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn u8(&mut self, v: u8) {
        self.raw(&[v]);
    }

    pub fn u32(&mut self, v: u32) {
        self.raw(&u32::to_be_bytes(v));
    }

    pub fn u64(&mut self, v: u64) {
        self.raw(&u64::to_be_bytes(v));
    }

    pub fn raw(&mut self, v: &[u8]) {
        self.0.extend_from_slice(v);
    }

    pub fn array<const N: usize>(&mut self, arr: [u8; N]) {
        self.raw(&arr);
    }

    pub fn name_list(&mut self, list: NameList<'_>) {
        self.string(list.0.as_bytes());
    }

    pub fn mpint<const LIMBS: usize>(&mut self, uint: crypto_bigint::Uint<LIMBS>)
    where
        crypto_bigint::Uint<LIMBS>: crypto_bigint::ArrayEncoding,
    {
        let bytes = crypto_bigint::ArrayEncoding::to_be_byte_array(&uint);
        let (bytes, pad_zero) = fixup_mpint(&bytes);
        let len = bytes.len() + (pad_zero as usize);
        self.u32(len as u32);
        if pad_zero {
            self.u8(0);
        }
        self.raw(bytes);
    }

    pub fn string(&mut self, data: impl AsRef<[u8]>) {
        let data = data.as_ref();
        self.u32(data.len() as u32);
        self.raw(data);
    }

    pub fn bool(&mut self, v: bool) {
        self.u8(v as u8);
    }

    pub fn current_length(&self) -> usize {
        self.0.len()
    }

    pub fn finish(self) -> Vec<u8> {
        self.0
    }
}

/// Returns an array of significant bits for the mpint,
/// and whether a leading 0 needs to be added for padding.
pub fn fixup_mpint(mut int_encoded: &[u8]) -> (&[u8], bool) {
    while int_encoded[0] == 0 {
        int_encoded = &int_encoded[1..];
    }
    // If the first high bit is set, pad it with a zero.
    (int_encoded, (int_encoded[0] & 0b10000000) > 1)
}

#[derive(Clone, Copy)]
pub struct NameList<'a>(pub &'a str);

impl<'a> NameList<'a> {
    pub fn one(item: &'a str) -> Self {
        if item.contains(',') {
            panic!("tried creating name list with comma in item: {item}");
        }
        Self(item)
    }
    pub fn multi(items: &'a str) -> Self {
        Self(items)
    }
    pub fn none() -> NameList<'static> {
        NameList("")
    }
    pub fn contains(&self, name: &str) -> bool {
        self.iter().any(|n| n == name)
    }
    pub fn iter(&self) -> std::str::Split<'a, char> {
        self.0.split(',')
    }
}

impl Debug for NameList<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MpInt<'a>(pub &'a [u8]);
