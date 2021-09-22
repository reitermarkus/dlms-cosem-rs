#[cfg(feature = "serde")]
use alloc::string::ToString;

use nom::{IResult, sequence::tuple, number::complete::u8};
#[cfg(feature = "serde")]
use serde::{Serialize, Serializer};

use super::*;

#[derive(Clone, PartialEq, PartialOrd, Eq, Ord)]
pub struct ObisCode {
  a: u8,
  b: u8,
  c: u8,
  d: u8,
  e: u8,
  f: u8,
}

impl ObisCode {
  pub const fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
    Self { a, b, c, d, e, f }
  }

  pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
    let (input, (a, b, c, d, e, f)) = tuple((u8, u8, u8, u8, u8, u8))(input)?;
    Ok((input, Self::new(a, b, c, d, e, f)))
  }
}

impl fmt::Display for ObisCode {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}-{}:{}.{}.{}*{}", self.a, self.b, self.c, self.d, self.e, self.f)
  }
}

impl fmt::Debug for ObisCode {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ObisCode(\"{}\")", self)
  }
}

#[cfg(feature = "serde")]
impl Serialize for ObisCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
