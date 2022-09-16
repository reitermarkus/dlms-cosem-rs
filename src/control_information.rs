use core::convert::TryFrom;

#[derive(Debug, Clone, PartialEq)]
pub enum HeaderType {
  Short,
  Long,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Direction {
  MasterSlave,
  SlaveMaster,
}

/// M-Bus control information.
#[derive(Debug, Clone)]
pub enum ControlInformation {
  Segmented { segment: u8, last_segment: bool },
  Unsegmented { header: HeaderType, direction: Direction },
}

impl TryFrom<u8> for ControlInformation {
  type Error = u8;

  fn try_from(control_information: u8) -> Result<Self, Self::Error> {
    use {Direction::*, HeaderType::*};

    Ok(match control_information {
      0x00..=0x1f => {
        let segment = control_information & 0b1111;
        let last_segment = (control_information & 0b10000) != 0;

        Self::Segmented { segment, last_segment }
      },
      0x60 => Self::Unsegmented { header: Long, direction: MasterSlave },
      0x61 => Self::Unsegmented { header: Short, direction: MasterSlave },
      0x7c => Self::Unsegmented { header: Long, direction: SlaveMaster },
      0x7d => Self::Unsegmented { header: Short, direction: SlaveMaster },
      _ => return Err(control_information),
    })
  }
}
