use alloc::borrow::{Cow, ToOwned};
use hdlcparse::{
  llc::{parse_llc, Llc},
  type3::HdlcFrame,
};

use crate::{DlmsDataLinkLayer, Error};

#[derive(Debug, Default)]
pub struct HdlcDataLinkLayer {
  is_server: bool,
}

impl HdlcDataLinkLayer {
  pub fn new(is_server: bool) -> Self {
    Self { is_server }
  }
  fn validate_llc(&self, llc: Llc) -> bool {
    llc.dest_sap == 0xE6
      && (llc.src_sap == if self.is_server { 0xE6 } else { 0xE7 })
      && llc.control == 0x00
  }
}

impl<'i> DlmsDataLinkLayer<&'i [HdlcFrame<'i>], &'i [HdlcFrame<'i>], Cow<'i, [u8]>>
  for HdlcDataLinkLayer
{
  fn next_frame(&self, frames: &'i [HdlcFrame<'i>]) -> Result<(&'i [HdlcFrame<'i>], Cow<'i, [u8]>), Error> {
    if frames.is_empty() {
      Err(Error::Incomplete(None))
    } else if !frames[0].segmented {
      let information = frames[0].information;
      let (information, llc) = parse_llc(information).ok_or(Error::Incomplete(None))?;
      if self.validate_llc(llc) {
        Ok((&frames[1..], Cow::from(information)))
      } else {
        Err(Error::InvalidFormat)
      }
    } else {
      let mut done = false;
      let mut len = 0;
      let (information, llc) = parse_llc(frames[0].information).ok_or(Error::Incomplete(None))?;
      if !self.validate_llc(llc) {
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
