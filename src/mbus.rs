use core::convert::TryFrom;

use crate::{
  control_information::{ControlInformation, HeaderType},
  map_nom_error, DlmsDataLinkLayer, Error,
};

use alloc::{borrow::Cow, vec::Vec};
use mbusparse::Telegram;
use nom::{sequence::tuple, IResult};

#[derive(Debug)]
pub enum MBusDataLinkLayer {}

fn parse_mbus<'i, 'f>(input: &'f [Telegram<'i>]) -> IResult<&'f [Telegram<'i>], Cow<'i, [u8]>, Error> {
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

            return Ok((&input[len..], Cow::from(user_data)));
          }
        };

        let (user_data, (_stsap, _dtsap)) = tuple((u8, u8))(user_data)?;

        payload.extend(user_data);
        len += 1;

        if last_segment {
          return Ok((&input[len..], Cow::from(payload)));
        }
      }
      _ => return Err(nom::Err::Failure(Error::InvalidFormat)),
    }
  }

  Err(nom::Err::Incomplete(nom::Needed::Unknown))
}

impl<'i, 'f> DlmsDataLinkLayer<'i, &'f [Telegram<'i>]> for MBusDataLinkLayer {
  fn next_frame(input: &'f [Telegram<'i>]) -> Result<(&'f [Telegram<'i>], Cow<'i, [u8]>), Error> {
    map_nom_error(parse_mbus(input))
  }
}
