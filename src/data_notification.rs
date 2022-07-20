use nom::{
  IResult,
  number::streaming::{u8, be_u32},
  multi::length_value,
};

use crate::{DateTime, Data};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LongInvokeIdAndPriority(pub(crate) u32);

impl LongInvokeIdAndPriority {
  pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
    let (input, id) = be_u32(input)?;
    Ok((input, Self(id)))
  }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Priority {
  Normal,
  High,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ServiceClass {
  Confirmed,
  Unconfirmed,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProcessingOption {
  ContinueOnError,
  BreakOnError,
}

impl LongInvokeIdAndPriority {
  pub fn priority(&self) -> Priority {
    if (self.0 & (1 << 31)) == 0 {
      Priority::Normal
    } else {
      Priority::High
    }
  }

  pub fn processing_option(&self) -> ProcessingOption {
    if (self.0 & (1 << 29)) == 0 {
      ProcessingOption::ContinueOnError
    } else {
      ProcessingOption::BreakOnError
    }
  }

  pub fn self_descriptive(&self) -> bool {
    (self.0 & (1 << 28)) != 0
  }

  pub fn service_class(&self) -> ServiceClass {
    if (self.0 & (1 << 30)) == 0 {
      ServiceClass::Unconfirmed
    } else {
      ServiceClass::Confirmed
    }
  }

  pub fn invoke_id(&self) -> u32 {
    self.0 & 0x00ffffff
  }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DataNotification {
  pub(crate) long_invoke_id_and_priority: LongInvokeIdAndPriority,
  pub(crate) date_time: DateTime,
  pub(crate) notification_body: Data,
}

impl DataNotification {
  pub fn priority(&self) -> Priority {
    self.long_invoke_id_and_priority.priority()
  }

  pub fn self_descriptive(&self) -> bool {
    self.long_invoke_id_and_priority.self_descriptive()
  }

  pub fn processing_option(&self) -> ProcessingOption {
    self.long_invoke_id_and_priority.processing_option()
  }

  pub fn service_class(&self) -> ServiceClass {
    self.long_invoke_id_and_priority.service_class()
  }

  pub fn invoke_id(&self) -> u32 {
    self.long_invoke_id_and_priority.invoke_id()
  }

  pub fn body(&self) -> &Data {
    &self.notification_body
  }

  pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
    let (input, long_invoke_id_and_priority) = LongInvokeIdAndPriority::parse(input)?;
    let (input, date_time) = length_value(u8, DateTime::parse)(input)?;
    let (input, notification_body) = Data::parse(input)?;
    Ok((input, Self { long_invoke_id_and_priority, date_time, notification_body }))
  }
}
