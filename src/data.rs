#[cfg(feature = "serde")]
use alloc::string::ToString;
use alloc::{string::String, vec::Vec};
use core::convert::TryFrom;
use core::fmt;

use nom::{
  combinator::fail,
  multi::length_count,
  number::streaming::{be_f32, be_f64, be_i16, be_i32, be_i64, be_u16, be_u32, be_u64, i8, u8},
  sequence::tuple,
  IResult,
};
#[cfg(feature = "serde")]
use serde::{Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[rustfmt::skip]
pub enum DataType {
  Null               =  0,
  Array              =  1,
  Structure          =  2,
  Bool               =  3,
  BitString          =  4,
  DoubleLong         =  5,
  DoubleLongUnsigned =  6,
  OctetString        =  9,
  VisibleString      = 10,
  Utf8String         = 12,
  BinaryCodedDecimal = 13,
  Integer            = 15,
  Long               = 16,
  Unsigned           = 17,
  LongUnsigned       = 18,
  CompactArray       = 19,
  Long64             = 20,
  Long64Unsigned     = 21,
  Enum               = 22,
  Float32            = 23,
  Float64            = 24,
  DateTime           = 25,
  Date               = 26,
  Time               = 27,
}

impl TryFrom<u8> for DataType {
  type Error = u8;

  fn try_from(dt: u8) -> Result<Self, Self::Error> {
    Ok(match dt {
      0x00 => Self::Null,
      0x01 => Self::Array,
      0x02 => Self::Structure,
      0x03 => Self::Bool,
      0x04 => Self::BitString,
      0x05 => Self::DoubleLong,
      0x06 => Self::DoubleLongUnsigned,
      0x09 => Self::OctetString,
      0x0a => Self::VisibleString,
      0x0c => Self::Utf8String,
      0x0d => Self::BinaryCodedDecimal,
      0x0f => Self::Integer,
      0x10 => Self::Long,
      0x11 => Self::Unsigned,
      0x12 => Self::LongUnsigned,
      0x13 => Self::CompactArray,
      0x14 => Self::Long64,
      0x15 => Self::Long64Unsigned,
      0x16 => Self::Enum,
      0x17 => Self::Float32,
      0x18 => Self::Float64,
      0x19 => Self::DateTime,
      0x1a => Self::Date,
      0x1b => Self::Time,
      dt => return Err(dt),
    })
  }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Date {
  pub(crate) year: u16,
  pub(crate) month: u8,
  pub(crate) day_of_month: u8,
  pub(crate) day_of_week: u8,
}

impl Date {
  fn parse(input: &[u8]) -> IResult<&[u8], Self> {
    let (input, year) = be_u16(input)?;
    let (input, month) = u8(input)?;
    let (input, day_of_month) = u8(input)?;
    let (input, day_of_week) = u8(input)?;

    Ok((input, Self { year, month, day_of_month, day_of_week }))
  }
}

impl fmt::Display for Date {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day_of_month)
  }
}

impl fmt::Debug for Date {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Date(\"{}\")", self)
  }
}

#[cfg(feature = "serde")]
impl Serialize for Date {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    serializer.serialize_str(&self.to_string())
  }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Time {
  pub(crate) hour: Option<u8>,
  pub(crate) minute: Option<u8>,
  pub(crate) second: Option<u8>,
  pub(crate) hundredth: Option<u8>,
}

impl Time {
  pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
    let (input, (hour, minute, second, hundredth)) = tuple((u8, u8, u8, u8))(input)?;

    let hour = match hour {
      0xff => None,
      0..=23 => Some(hour),
      _ => return fail(input),
    };
    let minute = match minute {
      0xff => None,
      0..=59 => Some(minute),
      _ => return fail(input),
    };
    let second = match second {
      0xff => None,
      0..=59 => Some(second),
      _ => return fail(input),
    };
    let hundredth = match hundredth {
      0xff => None,
      0..=99 => Some(hundredth),
      _ => return fail(input),
    };

    Ok((input, Self { hour, minute, second, hundredth }))
  }
}

impl fmt::Display for Time {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "{:02}:{:02}:{:02}.{:02}",
      self.hour.unwrap_or(0),
      self.minute.unwrap_or(0),
      self.second.unwrap_or(0),
      self.hundredth.unwrap_or(0),
    )
  }
}

impl fmt::Debug for Time {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Time(\"{}\")", self)
  }
}

#[cfg(feature = "serde")]
impl Serialize for Time {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    serializer.serialize_str(&self.to_string())
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ClockStatus(pub(crate) u8);

impl ClockStatus {
  #[rustfmt::skip]
  const INVALID_VALUE_BIT:   u8 = 0b00000001;
  #[rustfmt::skip]
  const DOUBTFUL_VALUE_BIT:  u8 = 0b00000010;
  #[rustfmt::skip]
  const DIFFERENT_BASE_BIT:  u8 = 0b00000100;
  #[rustfmt::skip]
  const INVALID_STATUS_BIT:  u8 = 0b00001000;
  #[rustfmt::skip]
  const DAYLIGHT_SAVING_BIT: u8 = 0b10000000;

  pub fn invalid_value(&self) -> bool {
    (self.0 & Self::INVALID_VALUE_BIT) != 0
  }

  pub fn doubtful_value(&self) -> bool {
    (self.0 & Self::DOUBTFUL_VALUE_BIT) != 0
  }

  pub fn different_base(&self) -> bool {
    (self.0 & Self::DIFFERENT_BASE_BIT) != 0
  }

  pub fn invalid_status(&self) -> bool {
    (self.0 & Self::INVALID_STATUS_BIT) != 0
  }

  pub fn daylight_saving(&self) -> bool {
    (self.0 & Self::DAYLIGHT_SAVING_BIT) != 0
  }
}

#[derive(Clone, PartialEq, Eq)]
pub struct DateTime {
  pub(crate) date: Date,
  pub(crate) time: Time,
  pub(crate) offset_minutes: Option<i16>,
  pub(crate) clock_status: Option<ClockStatus>,
}

impl DateTime {
  pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
    let (input, date) = Date::parse(input)?;
    let (input, time) = Time::parse(input)?;
    let (input, offset_minutes) = be_i16(input)?;
    let offset_minutes = Some(offset_minutes).filter(|&b| b != 0x8000u16 as i16);
    let (input, clock_status) = u8(input)?;
    let clock_status = Some(clock_status).filter(|&b| b != 0xff).map(ClockStatus);

    Ok((input, Self { date, time, offset_minutes, clock_status }))
  }
}

impl fmt::Display for DateTime {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}T{}", self.date, self.time)?;

    if let Some(offset_minutes) = self.offset_minutes {
      if offset_minutes >= 0 {
        '-'.fmt(f)?;
      } else {
        '+'.fmt(f)?;
      };
      let offset_minutes = offset_minutes.abs();
      write!(f, "{:02}:{:02}", offset_minutes / 60, offset_minutes % 60)?;
    }

    Ok(())
  }
}

impl fmt::Debug for DateTime {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "DateTime(\"{}\")", self)
  }
}

#[cfg(feature = "serde")]
impl Serialize for DateTime {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    serializer.serialize_str(&self.to_string())
  }
}

#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(untagged))]
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Data {
  Null,
  OctetString(Vec<u8>),
  Utf8String(String),
  Integer(i8),
  Unsigned(u8),
  Long(i16),
  LongUnsigned(u16),
  DoubleLong(i32),
  DoubleLongUnsigned(u32),
  Long64(i64),
  Long64Unsigned(u64),
  Float32(f32),
  Float64(f64),
  DateTime(DateTime),
  Date(Date),
  Time(Time),
  Structure(Vec<Data>),
  Enum(u8),
}

impl Data {
  pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
    let (input, data_type) = u8(input)?;
    let data_type = DataType::try_from(data_type)
      .map_err(|_| nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Fail)))?;
    Ok(match data_type {
      DataType::DateTime => {
        let (input, date_time) = DateTime::parse(input)?;
        (input, Data::DateTime(date_time))
      },
      DataType::Date => {
        let (input, date) = Date::parse(input)?;
        (input, Data::Date(date))
      },
      DataType::Time => {
        let (input, time) = Time::parse(input)?;
        (input, Data::Time(time))
      },
      DataType::Null => (input, Data::Null),
      DataType::Structure => {
        let (input, structure) = length_count(u8, Self::parse)(input)?;
        (input, Data::Structure(structure))
      },
      DataType::OctetString => {
        let (input, bytes) = length_count(u8, u8)(input)?;
        (input, Data::OctetString(bytes))
      },
      DataType::Float32 => {
        let (input, n) = be_f32(input)?;
        (input, Data::Float32(n))
      },
      DataType::Float64 => {
        let (input, n) = be_f64(input)?;
        (input, Data::Float64(n))
      },
      DataType::Integer => {
        let (input, n) = i8(input)?;
        (input, Data::Integer(n))
      },
      DataType::Long => {
        let (input, n) = be_i16(input)?;
        (input, Data::Long(n))
      },
      DataType::DoubleLong => {
        let (input, n) = be_i32(input)?;
        (input, Data::DoubleLong(n))
      },
      DataType::Long64 => {
        let (input, n) = be_i64(input)?;
        (input, Data::Long64(n))
      },
      DataType::Enum => {
        let (input, n) = u8(input)?;
        (input, Data::Enum(n))
      },
      DataType::LongUnsigned => {
        let (input, n) = be_u16(input)?;
        (input, Data::LongUnsigned(n))
      },
      DataType::DoubleLongUnsigned => {
        let (input, n) = be_u32(input)?;
        (input, Data::DoubleLongUnsigned(n))
      },
      DataType::Long64Unsigned => {
        let (input, n) = be_u64(input)?;
        (input, Data::Long64Unsigned(n))
      },
      dt => unimplemented!("decoding data type {:?}", dt),
    })
  }
}
