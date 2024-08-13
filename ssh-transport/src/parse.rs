use core::str;
use std::fmt::Debug;

use crate::Result;

/// A simplified `byteorder` clone that emits client errors when the data is too short.
pub struct Parser<'a>(&'a [u8]);

impl<'a> Parser<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self(data)
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
            return Err(crate::client_error!("packet too short"));
        }
        let result = self.0[..N].try_into().unwrap();
        self.0 = &self.0[N..];
        Ok(result)
    }

    pub fn slice(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.0.len() < len {
            return Err(crate::client_error!("packet too short"));
        }
        if len > 100_000 {
            return Err(crate::client_error!("bytes too long: {len}"));
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
            _ => Err(crate::client_error!("invalid bool: {b}")),
        }
    }

    pub fn name_list(&mut self) -> Result<NameList<'a>> {
        let list = self.utf8_string()?;
        Ok(NameList(list))
    }

    pub fn mpint(&mut self) -> Result<MpInt<'a>> {
        todo!("do correctly")
    }

    pub fn string(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()?;
        let data = self.slice(len.try_into().unwrap())?;
        Ok(data)
    }

    pub fn utf8_string(&mut self) -> Result<&'a str> {
        let s = self.string()?;
        let Ok(s) = str::from_utf8(s) else {
            return Err(crate::client_error!("name-list is invalid UTF-8"));
        };
        Ok(s)
    }
}

/// A simplified `byteorder` clone that emits client errors when the data is too short.
pub struct Writer(Vec<u8>);

impl Writer {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn u8(&mut self, v: u8) {
        self.write(&[v]);
    }

    pub fn u32(&mut self, v: u32) {
        self.write(&u32::to_be_bytes(v));
    }

    pub fn write(&mut self, v: &[u8]) {
        self.0.extend_from_slice(v);
    }

    pub fn array<const N: usize>(&mut self, arr: [u8; N]) {
        self.write(&arr);
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
        self.write(bytes);
    }

    pub fn string(&mut self, data: &[u8]) {
        self.u32(data.len() as u32);
        self.write(data);
    }

    pub fn bool(&mut self, v: bool) {
        self.u8(v as u8);
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
            //panic!("tried creating name list with comma in item: {item}");
        }
        Self(item)
    }
    pub fn none() -> NameList<'static> {
        NameList("")
    }
    pub fn iter(&self) -> std::str::Split<'a, char> {
        self.0.split(',')
    }
}

impl Debug for NameList<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MpInt<'a>(pub &'a [u8]);
