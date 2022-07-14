#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_debug_implementations)]

extern crate alloc;
use alloc::borrow::Cow;
use alloc::collections::btree_map::BTreeMap;

use core::borrow::Borrow;
use core::convert::TryFrom;
use core::fmt;
use core::mem;
use core::num::NonZeroUsize;
use core::ops::{Deref, DerefMut};

use aes::Aes128;
use cipher::Key;
use nom::{
  branch::alt,
  combinator::{all_consuming, complete, fail},
  multi::fold_many0,
  number::streaming::u8,
  Finish, IResult,
};
#[cfg(feature = "serde")]
use serde::{ser::SerializeMap, Serialize, Serializer};

mod control_information;
mod data;
pub use data::*;
mod data_notification;
use data_notification::*;
mod general_glo_ciphering;
use general_glo_ciphering::GeneralGloCiphering;
mod obis_code;
pub use obis_code::ObisCode;
mod security_control;
pub use security_control::SecurityControl;
mod unit;
pub use unit::Unit;
#[cfg(feature = "hdlcparse")]
pub mod hdlc;
#[cfg(feature = "mbusparse")]
pub mod mbus;

#[derive(Debug, Clone)]
pub enum Error {
  InvalidFormat,
  Incomplete(Option<NonZeroUsize>),
  DecryptionFailed,
  ChecksumMismatch,
}

impl fmt::Display for Error {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::InvalidFormat => write!(f, "invalid format"),
      Self::Incomplete(_) => write!(f, "incomplete"),
      Self::DecryptionFailed => write!(f, "decryption failed"),
      Self::ChecksumMismatch => write!(f, "checksum mismatch"),
    }
  }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl<I> nom::error::ParseError<I> for Error {
  fn from_error_kind(_input: I, _kind: nom::error::ErrorKind) -> Self {
    Error::InvalidFormat
  }

  fn append(_input: I, _kind: nom::error::ErrorKind, other: Self) -> Self {
    other
  }
}

pub trait DlmsDataLinkLayer<'i, I> {
  fn next_frame(input: I) -> Result<(I, Cow<'i, [u8]>), Error>;
}

#[derive(Debug)]
pub struct Dlms {
  key: Key<Aes128>,
}

impl Dlms {
  pub fn new(key: impl Into<Key<Aes128>>) -> Self {
    Dlms { key: key.into() }
  }

  pub fn decrypt<'i, Dll, I>(&self, input: I) -> Result<(I, ObisMap), Error>
  where
    Dll: DlmsDataLinkLayer<'i, I> + ?Sized,
  {
    let (output, apdu) = self.decrypt_apdu::<Dll, _>(input)?;

    let (_, obis) = ObisMap::parse(&apdu).map_err(|_| Error::InvalidFormat)?;

    Ok((output, obis))
  }

  pub fn decrypt_apdu<'i, Dll, I>(&self, input: I) -> Result<(I, Apdu), Error>
  where
    Dll: DlmsDataLinkLayer<'i, I> + ?Sized,
  {
    let (output, frame) = Dll::next_frame(input)?;
    let (_, apdu) = map_nom_error(all_consuming(complete(|input| {
      Apdu::parse_encrypted(input, &self.key)
    }))(frame.borrow()))?;

    Ok((output, apdu))
  }
}

fn map_nom_error<I, O>(result: IResult<I, O, Error>) -> Result<(I, O), Error> {
  result
    .map_err(|err| match err {
      nom::Err::Incomplete(needed) => nom::Err::Failure(Error::Incomplete(match needed {
        nom::Needed::Unknown => None,
        nom::Needed::Size(size) => Some(size),
      })),
      err => err,
    })
    .finish()
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Apdu {
  DataNotification(DataNotification),
  GeneralGloCiphering(GeneralGloCiphering),
}

impl Apdu {
  pub fn parse_encrypted<'i>(input: &'i [u8], key: &Key<Aes128>) -> IResult<&'i [u8], Self, Error> {
    let (input, apdu) = Self::parse(input).map_err(|_| nom::Err::Failure(Error::InvalidFormat))?;

    let apdu = match apdu {
      Apdu::GeneralGloCiphering(ciphering) => {
        let payload = ciphering.decrypt(key)
          .map_err(|_| nom::Err::Failure(Error::DecryptionFailed))?;

        let (_, apdu) = all_consuming(complete(Apdu::parse))(&payload)
          .map_err(|_| nom::Err::Failure(Error::InvalidFormat))?;
        apdu
      },
      apdu => apdu,
    };

    Ok((input, apdu))
  }

  pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
    let (input, tag) = u8(input)?;
    match tag {
      15 => {
        let (input, data_notification) = DataNotification::parse(input)?;
        Ok((input, Self::DataNotification(data_notification)))
      },
      219 => {
        let (input, general_glo_ciphering) = GeneralGloCiphering::parse(input)?;
        Ok((input, Self::GeneralGloCiphering(general_glo_ciphering)))
      },
      tag => unimplemented!("parsing APDU type {}", tag),
    }
  }
}

#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct Register {
  obis_code: ObisCode,
  value: Data,
  unit: Option<Unit>,
}

impl Register {
  pub fn obis_code(&self) -> &ObisCode {
    &self.obis_code
  }

  pub fn value(&self) -> &Data {
    &self.value
  }

  pub fn unit(&self) -> Option<&Unit> {
    self.unit.as_ref()
  }

  fn parse_obis_code(input: &[Data]) -> IResult<&[Data], ObisCode> {
    if let Some(data) = input.get(0) {
      match data {
        Data::OctetString(obis_code) => {
          let (_, code) = all_consuming(ObisCode::parse)(obis_code)
            .map_err(|e| e.map_input(|_| input))?;
          Ok((&input[1..], code))
        },
        _ => fail(input),
      }
    } else {
      Err(nom::Err::Incomplete(nom::Needed::new(1)))
    }
  }

  fn parse_value(input: &[Data]) -> IResult<&[Data], Data> {
    if let Some(data) = input.get(0) {
      Ok((&input[1..], data.clone()))
    } else {
      Err(nom::Err::Incomplete(nom::Needed::new(1)))
    }
  }

  fn parse_scaler_unit(input: &[Data]) -> IResult<&[Data], (i8, u8)> {
    if let Some(data) = input.get(0) {
      match data {
        Data::Structure(data) if data.len() == 2 => {
          if let (Data::Integer(ref scaler), Data::Enum(ref unit)) = (&data[0], &data[1]) {
            if *scaler != 0x00 || *unit != 0xff {
              return Ok((&input[1..], (*scaler, *unit)))
            }
          }
        },
        _ => (),
      }

      fail(input)
    } else {
      Err(nom::Err::Incomplete(nom::Needed::new(1)))
    }
  }

  fn parse_inner_nested(input: &[Data]) -> IResult<&[Data], (ObisCode, Data, Option<Unit>)> {
    if let Some(data) = input.get(0) {
      if let Data::Structure(ref data) = data {
        let (_, inner) = complete(Self::parse_inner)(data)?;
        return Ok((&input[1..], inner))
      }

      fail(input)
    } else {
      Err(nom::Err::Incomplete(nom::Needed::new(1)))
    }
  }

  fn parse_inner(input: &[Data]) -> IResult<&[Data], (ObisCode, Data, Option<Unit>)> {
    let (input, obis_code) = Self::parse_obis_code(input)?;
    let (input, mut value) = Self::parse_value(input)?;

    let (input, unit) = if let Ok((input, (scaler, unit))) = Self::parse_scaler_unit(input) {
      macro_rules! scale {
        ($value:expr, $scaler:expr, $ty:ident) => {{
          let factor = (0..($scaler.abs() as usize)).fold(1, |f, _| f * 10);

          if $scaler < 0 {
            $value as $ty / factor as $ty
          } else {
            $value as $ty * factor as $ty
          }
        }}
      }

      value = match value {
        Data::LongUnsigned(value) => Data::Float32(scale!(value, scaler, f32)),
        Data::DoubleLongUnsigned(value) => Data::Float64(scale!(value, scaler, f64)),
        value => value,
      };

      let unit = match Unit::try_from(unit) {
        Ok(unit) => unit,
        Err(_) => return fail(input),
      };

      (input, Some(unit))
    } else {
      (input, None)
    };

    Ok((input, (obis_code, value, unit)))
  }

  fn parse(input: &[Data]) -> IResult<&[Data], Self> {
    let (input, (obis_code, value, unit)) =
      alt((complete(Self::parse_inner), complete(Self::parse_inner_nested)))(input)?;

      Ok((input, Self { obis_code, value, unit }))
  }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ObisMap {
  map: BTreeMap<ObisCode, Register>,
}

impl Deref for ObisMap {
  type Target = BTreeMap<ObisCode, Register>;

  fn deref(&self) -> &Self::Target {
      &self.map
  }
}

impl DerefMut for ObisMap {
  fn deref_mut(&mut self) -> &mut Self::Target {
      &mut self.map
  }
}

impl ObisMap {
  /// Convert the `Data` for a given `ObisCode` using the given function.
  pub fn convert(&mut self, code: &ObisCode, mut f: impl FnMut(Data) -> Data) {
    if let Some(reg) = self.map.get_mut(code) {
      let value = &mut reg.value;
      *value = f(mem::replace(value, Data::Null));
    }
  }

  pub fn parse(input: &Apdu) -> IResult<(), Self> {
    let data = match input {
      Apdu::DataNotification(DataNotification { notification_body: Data::Structure(data), .. }) => data.as_slice(),
      _ => return fail(())
    };

    let (_, values) = all_consuming(fold_many0(
      Register::parse,
      BTreeMap::new,
      |mut values, reg| {
        values.insert(reg.obis_code.clone(), reg);
        values
      }
    ))(data).map_err(|e| e.map_input(|_| ()))?;

    Ok(((), Self { map: values }))
  }
}

#[cfg(feature = "serde")]
impl Serialize for ObisMap {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
      S: Serializer,
  {
    #[derive(Serialize)]
    struct Entry<'a> {
      value: &'a Data,
      #[serde(skip_serializing_if = "Option::is_none")]
      unit: Option<&'a str>
    }

    let mut map = serializer.serialize_map(Some(self.map.len()))?;
    for (k, v) in self.map.iter() {

        map.serialize_entry(k, &Entry {
          value: v.value(),
          unit: v.unit().and_then(|u| u.as_str()),
        })?;
    }
    map.end()
  }
}

#[cfg(test)]
mod test {
  use super::*;

  use alloc::vec;

  #[test]
  fn parse_apdu() {
    let payload: [u8; 72] = [
      // APDU
      0x0F, // Type (Data Notification)
        // Invoke ID & Priority
        0x00, 0x00, 0x55, 0x39,
        // Date & Time (Octet String)
        0x0C, // Length
          0x07, 0xE0, // Year
          0x09, // Month
          0x08, // Day of Month
          0x04, // Day of Week
          0x13, // Hour
          0x0D, // Minute
          0x19, // Second
          0x00, // Hundredth
          0xFF, 0xC4, // Clock Offset in Minutes
          0x80, // Clock Status
        // Notification Body
        0x02, // Type (Structure)
          0x07, // Length
            0x09, // Type (Octet String)
              0x0C, // Length
                0x07, 0xE0, 0x09, 0x08, 0x04, 0x13, 0x0D, 0x19, 0x00, 0x00, 0x00, 0x80, // Octet String
            0x09, // Type (Octet String)
              0x06, // Length
                0x01, 0x00, 0x01, 0x08, 0x00, 0xFF, // Octet String
            0x06, // Type (Double Long Unsigned)
              0x00, 0x00, 0x00, 0x00, // Long Unsigned Int
            0x02, // Type (Structure)
              0x02, // Length
                0x0F, // Type (Integer)
                  0x00, // Integer
                0x16, // Type (Enum)
                  0x1E, // Enum
            0x09, // Type (Octet String)
              0x06, // Length
                0x01, 0x00, 0x03, 0x08, 0x00, 0xFF, // Octet String
            0x06, // Type (Double Long Unsigned)
              0x00, 0x00, 0x00, 0x00, // Double Long Unsigned
            0x02, // Type (Structure)
              0x02, // Length
                0x0F, // Type (Integer)
                  0x00, // Integer
                0x16, // Type (Enum)
                  0x20, // Enum
    ];

    assert_eq!(
      Apdu::parse(&payload).unwrap().1,
      Apdu::DataNotification(
        DataNotification {
          long_invoke_id_and_priority: LongInvokeIdAndPriority(21817),
          date_time: DateTime {
            date: Date {
              year: 2016,
              month: 9,
              day_of_month: 8,
              day_of_week: 4,
            },
            time: Time {
              hour: Some(19),
              minute: Some(13),
              second: Some(25),
              hundredth: Some(0),
            },
            offset_minutes: Some(-60),
            clock_status: Some(ClockStatus(128)),
          },
          notification_body: Data::Structure(vec![
            Data::OctetString(vec![7, 224, 9, 8, 4, 19, 13, 25, 0, 0, 0, 128]),
            Data::OctetString(vec![1, 0, 1, 8, 0, 255]),
            Data::DoubleLongUnsigned(0),
            Data::Structure(vec![
              Data::Integer(0),
              Data::Enum(30),
            ]),
            Data::OctetString(vec![1, 0, 3, 8, 0, 255]),
            Data::DoubleLongUnsigned(0),
            Data::Structure(vec![
              Data::Integer(0),
              Data::Enum(32),
            ]),
          ]),
        },
      ),
    );
  }

  const KEY: [u8; 16] = 0xdeafbeefcafebabedeafbeefcafebabeu128.to_be_bytes();

  const ENCRYPTED_MESSAGE: [u8; 354] = [
    0xdb, // Tag
    0x08, 0x4b, 0x46, 0x4d, 0x10, 0x20, 0x01, 0x12, 0xa9, // System Title
    0x82, 0x01, 0x55, // Payload Length
    0x21, // Security Control
    0x00, 0x02, 0xbc, 0x66, // Invocation Counter
    0xf4, 0x50, 0xb5, 0x97, 0xb1, 0x1f, 0x09, 0x45, 0x0a, 0x68, 0x03, 0x63, 0xe7, 0x18, 0x41, 0xc4,
    0x09, 0x82, 0x9a, 0xab, 0xe0, 0x8b, 0x44, 0x3f, 0x6c, 0x9a, 0x70, 0x73, 0xbc, 0xc4, 0x5c, 0xdb,
    0x8b, 0x57, 0x48, 0x85, 0x11, 0x80, 0x42, 0x0c, 0x79, 0xd9, 0x0e, 0x26, 0xf1, 0x26, 0x15, 0xbe,
    0xed, 0x5f, 0xea, 0x7d, 0xc8, 0x54, 0x26, 0xaf, 0x38, 0x9c, 0x8c, 0x92, 0x02, 0x9f, 0xf3, 0x64,
    0x63, 0xf7, 0xbf, 0x1b, 0x9e, 0x56, 0xa3, 0x88, 0x75, 0x69, 0xf6, 0x1a, 0x5a, 0x86, 0x23, 0x9a,
    0xd6, 0x2f, 0xda, 0x85, 0x48, 0xb3, 0xf6, 0x22, 0x61, 0x25, 0x3f, 0xe5, 0xcd, 0x0e, 0x06, 0xb7,
    0x14, 0xad, 0x5c, 0x26, 0x85, 0xc8, 0x45, 0x57, 0x70, 0x8d, 0x57, 0xde, 0xba, 0x10, 0xca, 0xc0,
    0x8d, 0xeb, 0xba, 0xcc, 0xc5, 0x66, 0x2b, 0x45, 0x50, 0x14, 0xbc, 0x8b, 0x44, 0x17, 0x48, 0x1d,
    0x2b, 0x9a, 0xf1, 0x66, 0x22, 0x07, 0x1f, 0xbe, 0xef, 0x5e, 0xce, 0xaf, 0x1e, 0x39, 0xf7, 0x99,
    0x6c, 0xa9, 0x98, 0x27, 0x68, 0x31, 0xe6, 0x84, 0xe0, 0x70, 0x44, 0x57, 0xd4, 0xcd, 0x64, 0x96,
    0xca, 0xd4, 0xdb, 0xd9, 0x03, 0x35, 0x98, 0x11, 0x13, 0x5e, 0x7e, 0x70, 0xb4, 0x06, 0x30, 0x4c,
    0x8e, 0x7e, 0xce, 0x20, 0x90, 0xcd, 0x74, 0x3a, 0x08, 0x2d, 0xa6, 0x2e, 0xd6, 0x20, 0x83, 0xb3,
    0xd3, 0xf1, 0x21, 0xf9, 0x97, 0x2d, 0xd6, 0x48, 0x78, 0x86, 0xf6, 0xaf, 0x2c, 0x5c, 0x76, 0x39,
    0x81, 0xa2, 0xe1, 0xa1, 0x28, 0x3c, 0x52, 0x12, 0xa8, 0x15, 0x77, 0x84, 0x7d, 0x40, 0xf7, 0x64,
    0xba, 0x93, 0x6d, 0x26, 0xc6, 0x33, 0xec, 0x73, 0xb0, 0x1b, 0xc7, 0x1a, 0xfd, 0x6d, 0x4c, 0x10,
    0xbb, 0xcb, 0xea, 0x96, 0x86, 0xf0, 0x3d, 0x40, 0x84, 0x99, 0xee, 0x7f, 0x16, 0x35, 0x69, 0xea,
    0x7d, 0xb6, 0xf5, 0x23, 0xea, 0xbd, 0xfe, 0x5d, 0x31, 0xb5, 0xb2, 0x34, 0xf3, 0x09, 0xc5, 0x71,
    0xbc, 0xec, 0x4f, 0x3f, 0xae, 0x4c, 0xe9, 0xab, 0xce, 0x92, 0x62, 0x4a, 0x37, 0xeb, 0x62, 0x0d,
    0x2c, 0x2a, 0xdd, 0xf6, 0x0c, 0xd5, 0xaa, 0x65, 0xd1, 0xe2, 0xe4, 0x5c, 0xe2, 0x13, 0x4f, 0x0e,
    0x4c, 0x2f, 0x70, 0xe1, 0x9d, 0x93, 0x6f, 0x84, 0x5c, 0x6f, 0x36, 0x91, 0xb3, 0x26, 0x00, 0x5d,
    0x43, 0x9c, 0xe6, 0x46, 0x27, 0x53, 0x92, 0xf6, 0x0b, 0x3b, 0x69, 0x90, 0x3f, 0x82, 0x84, 0x78,
  ];

  const DECRYPTED_MESSAGE: [u8; 336] = [
    0x0f, 0x00, 0x02, 0xb5, 0xe4, 0x0c, 0x07, 0xe5, 0x09, 0x0b, 0x06, 0x09, 0x0d, 0x14, 0x00, 0xff,
    0x88, 0x80, 0x02, 0x10, 0x09, 0x06, 0x00, 0x00, 0x01, 0x00, 0x00, 0xff, 0x09, 0x0c, 0x07, 0xe5,
    0x09, 0x0b, 0x06, 0x09, 0x0d, 0x14, 0x00, 0xff, 0x88, 0x80, 0x02, 0x02, 0x09, 0x06, 0x00, 0x00,
    0x60, 0x01, 0x00, 0xff, 0x09, 0x0e, 0x31, 0x4b, 0x46, 0x4d, 0x30, 0x32, 0x30, 0x30, 0x30, 0x37,
    0x30, 0x33, 0x31, 0x33, 0x02, 0x02, 0x09, 0x06, 0x00, 0x00, 0x2a, 0x00, 0x00, 0xff, 0x09, 0x10,
    0x4b, 0x46, 0x4d, 0x31, 0x32, 0x30, 0x30, 0x32, 0x30, 0x30, 0x30, 0x37, 0x30, 0x33, 0x31, 0x33,
    0x02, 0x03, 0x09, 0x06, 0x01, 0x00, 0x20, 0x07, 0x00, 0xff, 0x12, 0x09, 0x20, 0x02, 0x02, 0x0f,
    0xff, 0x16, 0x23, 0x02, 0x03, 0x09, 0x06, 0x01, 0x00, 0x34, 0x07, 0x00, 0xff, 0x12, 0x09, 0x04,
    0x02, 0x02, 0x0f, 0xff, 0x16, 0x23, 0x02, 0x03, 0x09, 0x06, 0x01, 0x00, 0x48, 0x07, 0x00, 0xff,
    0x12, 0x09, 0x0d, 0x02, 0x02, 0x0f, 0xff, 0x16, 0x23, 0x02, 0x03, 0x09, 0x06, 0x01, 0x00, 0x1f,
    0x07, 0x00, 0xff, 0x12, 0x01, 0x6d, 0x02, 0x02, 0x0f, 0xfe, 0x16, 0x21, 0x02, 0x03, 0x09, 0x06,
    0x01, 0x00, 0x33, 0x07, 0x00, 0xff, 0x12, 0x03, 0x0e, 0x02, 0x02, 0x0f, 0xfe, 0x16, 0x21, 0x02,
    0x03, 0x09, 0x06, 0x01, 0x00, 0x47, 0x07, 0x00, 0xff, 0x12, 0x02, 0x62, 0x02, 0x02, 0x0f, 0xfe,
    0x16, 0x21, 0x02, 0x03, 0x09, 0x06, 0x01, 0x00, 0x01, 0x07, 0x00, 0xff, 0x06, 0x00, 0x00, 0x0f,
    0x5e, 0x02, 0x02, 0x0f, 0x00, 0x16, 0x1b, 0x02, 0x03, 0x09, 0x06, 0x01, 0x00, 0x02, 0x07, 0x00,
    0xff, 0x06, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x0f, 0x00, 0x16, 0x1b, 0x02, 0x03, 0x09, 0x06,
    0x01, 0x00, 0x01, 0x08, 0x00, 0xff, 0x06, 0x00, 0x51, 0x00, 0x15, 0x02, 0x02, 0x0f, 0x00, 0x16,
    0x1e, 0x02, 0x03, 0x09, 0x06, 0x01, 0x00, 0x02, 0x08, 0x00, 0xff, 0x06, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x02, 0x0f, 0x00, 0x16, 0x1e, 0x02, 0x03, 0x09, 0x06, 0x01, 0x00, 0x03, 0x08, 0x00, 0xff,
    0x06, 0x00, 0x00, 0x34, 0x65, 0x02, 0x02, 0x0f, 0x00, 0x16, 0x20, 0x02, 0x03, 0x09, 0x06, 0x01,
    0x00, 0x04, 0x08, 0x00, 0xff, 0x06, 0x00, 0x08, 0xa3, 0xbc, 0x02, 0x02, 0x0f, 0x00, 0x16, 0x20,
  ];

  #[test]
  fn test_parse_mbus() {
    let decrypted = Apdu::parse_encrypted(&ENCRYPTED_MESSAGE, &KEY.into()).unwrap().1;
    let expected = Apdu::parse(&DECRYPTED_MESSAGE).unwrap().1;

    assert_eq!(decrypted, expected);
  }
}
