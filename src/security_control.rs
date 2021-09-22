use core::fmt;

use nom::{IResult, number::complete::u8};

#[derive(Clone, PartialEq)]
pub struct SecurityControl {
  security_control: u8
}

impl fmt::Debug for SecurityControl {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("SecurityControl")
      .field("suite_id", &self.suite_id())
      .field("authentication", &self.authentication())
      .field("encryption", &self.encryption())
      .field("broadcast", &self.broadcast())
      .field("compression", &self.compression())
      .finish()
  }
}

impl SecurityControl {
  pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
    let (input, security_control) = u8(input)?;
    Ok((input, Self { security_control }))
  }
}

impl SecurityControl {
  const COMPRESSION_BIT: u8 =    0b10000000;
  const BROADCAST_BIT: u8 =      0b01000000;
  const ENCRYPTION_BIT: u8 =     0b00100000;
  const AUTHENTICATION_BIT: u8 = 0b00010000;

  pub fn suite_id(&self) -> u8 {
    self.security_control & 0b00001111
  }

  pub fn authentication(&self) -> bool {
    (self.security_control & Self::AUTHENTICATION_BIT) != 0
  }

  pub fn set_authentication(&mut self, authentication: bool) {
    if authentication {
      self.security_control |= Self::AUTHENTICATION_BIT
    } else {
      self.security_control &= !Self::AUTHENTICATION_BIT
    }
  }

  pub fn encryption(&self) -> bool {
    (self.security_control & Self::ENCRYPTION_BIT) != 0
  }

  pub fn set_encryption(&mut self, encryption: bool) {
    if encryption {
      self.security_control |= Self::ENCRYPTION_BIT
    } else {
      self.security_control &= !Self::ENCRYPTION_BIT
    }
  }

  pub fn broadcast(&self) -> bool {
    (self.security_control & Self::BROADCAST_BIT) != 0
  }

  pub fn set_broadcast(&mut self, broadcast: bool) {
    if broadcast {
      self.security_control |= Self::BROADCAST_BIT
    } else {
      self.security_control &= !Self::BROADCAST_BIT
    }
  }

  pub fn compression(&self) -> bool {
    (self.security_control & Self::COMPRESSION_BIT) != 0
  }

  pub fn set_compression(&mut self, compression: bool) {
    if compression {
      self.security_control |= Self::COMPRESSION_BIT
    } else {
      self.security_control &= !Self::COMPRESSION_BIT
    }
  }
}
