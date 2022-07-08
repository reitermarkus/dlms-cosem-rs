use core::convert::TryFrom;

use crate::{
  control_information::{ControlInformation, HeaderType},
  map_nom_error, DlmsDataLinkLayer, Error,
};

use alloc::vec::Vec;
use mbusparse::Telegram;
use nom::{sequence::tuple, IResult};

#[derive(Debug)]
pub struct MBusDataLinkLayer {}

impl Default for MBusDataLinkLayer {
  fn default() -> Self {
    Self {}
  }
}

impl<'i> MBusDataLinkLayer {
  fn parse_mbus(&self, input: &'i [Telegram<'i>]) -> IResult<&'i [Telegram<'i>], Vec<u8>, Error> {
    let mut payload = Vec::new();
    let mut current_segment = 0;
    let mut len = 0;

    for telegram in input {
      match telegram {
        Telegram::LongFrame {
          control_information,
          user_data,
          ..
        } => {
          use nom::number::complete::u8;

          let user_data: &[u8] = *user_data;

          let control_information = ControlInformation::try_from(*control_information)
            .map_err(|_| nom::Err::Failure(Error::InvalidFormat))?;

          let (user_data, last_segment) = match control_information {
            ControlInformation::Segmented {
              segment,
              last_segment,
            } => {
              if current_segment != segment {
                return Err(nom::Err::Failure(Error::ChecksumMismatch));
              }
              current_segment = current_segment.wrapping_add(1);

              (user_data, last_segment)
            }
            ControlInformation::Unsegmented { header, .. } => {
              let (user_data, _ala) = if header == HeaderType::Long {
                let (user_data, (m_id, ver, dt)) = tuple((u8, u8, u8))(user_data)?;
                (user_data, Some((m_id, ver, dt)))
              } else {
                (user_data, None)
              };

              let (user_data, (_acc, _sts, _cfg)) = tuple((u8, u8, u8))(user_data)?;

              (user_data, true)
            }
          };

          let (user_data, (_stsap, _dtsap)) = tuple((u8, u8))(user_data)?;

          payload.extend(user_data);
          len += 1;

          if last_segment {
            return Ok((&input[len..], payload));
          }
        }
        _ => return Err(nom::Err::Failure(Error::InvalidFormat)),
      }
    }

    Err(nom::Err::Incomplete(nom::Needed::Unknown))
  }
}

impl<'i> DlmsDataLinkLayer<'i> for MBusDataLinkLayer {
  type Input = &'i [Telegram<'i>];
  type Output = &'i [Telegram<'i>];
  type FrameOutput = Vec<u8>;

  fn next_frame(&self, input: &'i [Telegram<'i>]) -> Result<(&'i [Telegram<'i>], Vec<u8>), Error> {
    map_nom_error(self.parse_mbus(input))
  }
}
