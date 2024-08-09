use core::str;
use std::fmt::Debug;

use crate::Result;

/// A simplified `byteorder` clone that emits client errors when the data is too short.
pub(crate) struct Parser<'a>(&'a [u8]);

impl<'a> Parser<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self(data)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        let arr = self.read_array::<1>()?;
        Ok(arr[0])
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        let arr = self.read_array()?;
        Ok(u32::from_be_bytes(arr))
    }

    pub(crate) fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        if self.0.len() < N {
            return Err(crate::client_error!("packet too short"));
        }
        let result = self.0[..N].try_into().unwrap();
        self.0 = &self.0[N..];
        Ok(result)
    }

    pub(crate) fn read_slice(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.0.len() < len {
            return Err(crate::client_error!("packet too short"));
        }
        let result = &self.0[..len];
        self.0 = &self.0[len..];
        Ok(result)
    }

    pub(crate) fn bool(&mut self) -> Result<bool> {
        let b = self.u8()?;
        match b {
            0 => Ok(false),
            1 => Ok(true),
            _ => return Err(crate::client_error!("invalid bool: {b}")),
        }
    }

    pub(crate) fn name_list(&mut self) -> Result<NameList<'a>> {
        let len = self.u32()?;
        let list = self.read_slice(len.try_into().unwrap())?;
        let Ok(list) = str::from_utf8(list) else {
            return Err(crate::client_error!("name-list is invalid UTF-8"));
        };
        Ok(NameList(list))
    }

    pub(crate) fn mpint(&mut self) -> Result<MpInt<'a>> {
        let len = self.u32()?;
        let data = self.read_slice(len as usize)?;
        Ok(MpInt(data))
    }
}

/// A simplified `byteorder` clone that emits client errors when the data is too short.
pub(crate) struct Writer(Vec<u8>);

impl Writer {
    pub(crate) fn new() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn u8(&mut self, v: u8) {
        self.write(&[v]);
    }

    pub(crate) fn u32(&mut self, v: u32) {
        self.write(&u32::to_be_bytes(v));
    }

    pub(crate) fn write(&mut self, v: &[u8]) {
        self.0.extend_from_slice(v);
    }

    pub(crate) fn name_list(&mut self, list: NameList<'_>) {
        self.string(list.0.as_bytes());
    }

    pub(crate) fn mpint(&mut self, mpint: MpInt<'_>) {
        self.string(mpint.0);
    }

    pub(crate) fn string(&mut self, data: &[u8]) {
        self.u32(data.len() as u32);
        self.write(data);
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.0
    }
}

#[derive(Clone, Copy)]
pub struct NameList<'a>(&'a str);

impl<'a> NameList<'a> {
    pub(crate) fn one(item: &'a str) -> Self {
        if item.contains(',') {
            panic!("tried creating name list with comma in item: {item}");
        }
        Self(item)
    }
    pub(crate) fn none() -> NameList<'static> {
        NameList("")
    }
    pub(crate) fn iter(&self) -> std::str::Split<char> {
        self.0.split(',')
    }
}

impl Debug for NameList<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MpInt<'a>(pub(crate) &'a [u8]);

impl<'a> MpInt<'a> {
    pub(crate) fn to_x25519_public_key(&self) -> Result<x25519_dalek::PublicKey> {
        let Ok(arr) = <[u8; 32]>::try_from(self.0) else {
            return Err(crate::client_error!(
                "invalid x25519 public key length, should be 32, was: {}",
                self.0.len()
            ));
        };
        Ok(x25519_dalek::PublicKey::from(arr))
    }
}
