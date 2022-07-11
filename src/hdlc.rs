use alloc::borrow::Cow;
use hdlcparse::type3::HdlcFrame;
use nom::{branch::alt, bytes::complete::tag, sequence::tuple};

use crate::{DlmsDataLinkLayer, Error};

fn parse_llc_header(input: &[u8]) -> Option<&[u8]> {
  let (input, _) = tuple::<_, _, (), _>((
    tag([0xE6]),
    alt((tag([0xE6]), tag([0xE7]), tag([0xFF]))),
    tag([0x00]),
  ))(input)
  .ok()?;
  Some(input)
}

#[derive(Debug)]
pub enum HdlcDataLinkLayer {}

impl<'i, 'f> DlmsDataLinkLayer<'i, &'f [HdlcFrame<'i>]> for HdlcDataLinkLayer {
  fn next_frame(
    frames: &'f [HdlcFrame<'i>],
  ) -> Result<(&'f [HdlcFrame<'i>], Cow<'i, [u8]>), Error> {
    if frames.is_empty() {
      Err(Error::Incomplete(None))
    } else if !frames[0].segmented {
      let information = frames[0].information;
      let information = parse_llc_header(information).ok_or(Error::InvalidFormat)?;
      Ok((&frames[1..], Cow::from(information)))
    } else {
      let mut done = false;
      let mut len = 0;
      let information = parse_llc_header(frames[0].information).ok_or(Error::InvalidFormat)?;
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
