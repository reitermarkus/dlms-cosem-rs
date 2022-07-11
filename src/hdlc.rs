use alloc::borrow::Cow;
use hdlcparse::type3::HdlcFrame;
use nom::{bytes::complete::tag, number::complete::u8, sequence::tuple};

use crate::{DlmsDataLinkLayer, Error};

enum MessageType {
  Command,
  Response,
  Broadcast,
}

struct LlcHeader {
  message_type: MessageType,
  quality: u8,
}

pub fn parse_llc_header<'a>(input: &'a [u8]) -> Option<(&'a [u8], LlcHeader)> {
  let (input, (_, src_lsap, quality)) = tuple::<_, _, (), _>((tag([0xE6]), u8, u8))(input).ok()?;
  let message_type = match src_lsap {
    0xE6 => MessageType::Command,
    0xE7 => MessageType::Response,
    0xFF => MessageType::Broadcast,
    _ => None?,
  };
  Some((
    input,
    LlcHeader {
      message_type,
      quality,
    },
  ))
}

#[derive(Debug)]
pub enum HdlcDataLinkLayer {}

fn validate_llc(llc: LlcHeader) -> bool {
  llc.quality == 0x00
}

impl<'i, 'f> DlmsDataLinkLayer<'i, &'f [HdlcFrame<'i>]> for HdlcDataLinkLayer {
  fn next_frame(
    frames: &'f [HdlcFrame<'i>],
  ) -> Result<(&'f [HdlcFrame<'i>], Cow<'i, [u8]>), Error> {
    if frames.is_empty() {
      Err(Error::Incomplete(None))
    } else if !frames[0].segmented {
      let information = frames[0].information;
      let (information, llc) = parse_llc_header(information).ok_or(Error::Incomplete(None))?;
      if validate_llc(llc) {
        Ok((&frames[1..], Cow::from(information)))
      } else {
        Err(Error::InvalidFormat)
      }
    } else {
      let mut done = false;
      let mut len = 0;
      let (information, llc) = parse_llc(frames[0].information).ok_or(Error::Incomplete(None))?;
      if !validate_llc(llc) {
        return Err(Error::InvalidFormat);
      }
      let mut information = information.to_owned();
      for frame in &frames[1..] {
        information.extend(frame.information);
        len += 1;
        if !frame.segmented {
          done = true;
          break;
        }
      }
      if done {
        Ok((&frames[len..], Cow::from(information)))
      } else {
        Err(Error::Incomplete(None))
      }
    }
  }
}
