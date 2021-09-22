use alloc::vec::Vec;

use aes::Aes128;
use aes_gcm::Aes128Gcm;
use aes_gcm::aead::{NewAead, AeadInPlace};
use cipher::BlockCipherKey;
use nom::{
  IResult,
  bytes::streaming::tag,
  number::streaming::{u8, be_u16, be_u32},
  multi::{count, fill},
  combinator::cond,
};

use crate::SecurityControl;

#[derive(Debug, Clone, PartialEq)]
pub struct GeneralGloCiphering {
  system_title: [u8; 8],
  security_control: SecurityControl,
  invocation_counter: Option<u32>,
  payload: Vec<u8>,
}

impl GeneralGloCiphering {
  pub fn decrypt(mut self, key: &BlockCipherKey<Aes128>) -> Result<Vec<u8>, aes_gcm::Error> {
    if self.security_control.encryption() {
      let cipher = Aes128Gcm::new(key);

      let mut iv = [0u8; 12];
      iv[0..8].copy_from_slice(&self.system_title);
      iv[8..].copy_from_slice(&self.invocation_counter.unwrap().to_be_bytes());

      cipher.encrypt_in_place_detached(&iv.into(), &[], &mut self.payload)?;
      self.security_control.set_encryption(false);
    }

    Ok(self.payload)
  }

  pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
    let (input, _) = tag([8])(input)?;
    let mut system_title = [0u8; 8];
    let (input, _) = fill(u8, &mut system_title)(input)?;

    let (input, mut payload_len) = match u8(input)? {
      (input, 0x82) => {
        let (input, len) = be_u16(input)?;
        (input, len as usize)
      },
      (input, len) => (input, len as usize),
    };
    payload_len -= 5;

    // Green Book 9.2.7.2.4.1
    let (input, security_control) = SecurityControl::parse(input)?;

    let (input, invocation_counter) = cond(
      security_control.authentication() || security_control.encryption(),
      be_u32,
    )(input)?;

    let (input, payload) = count(u8, payload_len)(input)?;

    Ok((input, Self {
      system_title,
      security_control,
      invocation_counter,
      payload,
    }))
  }
}
