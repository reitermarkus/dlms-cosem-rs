use alloc::borrow::Cow;
use hdlcparse::type3::HdlcFrame;
use nom::{number::complete::u8, sequence::tuple};

use crate::{DlmsDataLinkLayer, Error};

enum Destination {
  Unicast,
  Broadcast,
}

enum MessageType {
  Command,
  Response,
}

#[allow(unused)]
struct LlcHeader {
  destination: Destination,
  message_type: MessageType,
  quality: u8,
}

fn parse_llc_header(input: &[u8]) -> Result<(&[u8], LlcHeader), Error> {
  let (input, (dest_lsap, src_lsap, quality)) =
    tuple::<_, _, (), _>((u8, u8, u8))(input).map_err(|_| Error::InvalidFormat)?;
  if quality != 0x00 {
    return Err(Error::InvalidFormat)
  }
  let destination = match dest_lsap {
    0xE6 => Destination::Unicast,
    0xFF => Destination::Broadcast,
    _ => return Err(Error::InvalidFormat),
  };
  let message_type = match src_lsap {
    0xE6 => MessageType::Command,
    0xE7 => MessageType::Response,
    _ => return Err(Error::InvalidFormat),
  };

  Ok((input, LlcHeader { destination, message_type, quality }))
}

#[derive(Debug)]
pub enum HdlcDataLinkLayer {}

impl<'i, 'f> DlmsDataLinkLayer<'i, &'f [HdlcFrame<'i>]> for HdlcDataLinkLayer {
  fn next_frame(frames: &'f [HdlcFrame<'i>]) -> Result<(&'f [HdlcFrame<'i>], Cow<'i, [u8]>), Error> {
    if frames.is_empty() {
      Err(Error::Incomplete(None))
    } else if !frames[0].segmented {
      let information = frames[0].information;
      let (information, _) = parse_llc_header(information)?;
      Ok((&frames[1..], Cow::from(information)))
    } else {
      let mut done = false;
      let mut len = 0;
      let (information, _) = parse_llc_header(frames[0].information)?;
      let mut information = information.to_owned();
      for frame in &frames[1..] {
        information.extend(frame.information);
        len += 1;
        if !frame.segmented {
          done = true;
          break
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
