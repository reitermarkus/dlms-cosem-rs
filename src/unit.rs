use core::fmt;

use derive_try_from_primitive::TryFromPrimitive;
#[cfg(feature = "serde")]
use serde::{Serialize, Serializer};

#[derive(Debug, Clone, Copy, PartialEq, TryFromPrimitive)]
#[repr(u8)]
#[non_exhaustive]
pub enum Unit {
  Year = 1,
  Month = 2,
  Week = 3,
  Day = 4,
  Hour = 5,
  Minute = 6,
  Second = 7,
  Degree = 8,
  DegreeCelsius = 9,
  Currency = 10,
  Meter = 11,
  MeterPerSecond = 12,
  CubicMeter = 13,
  CubicMeterCorrected = 14,
  CubicMeterPerHour = 15,
  CubicMeterPerHourCorrected = 16,
  CubicMeterPerDay = 17,
  CubicMeterPerDayCorrected = 18,
  Liter = 19,
  Kilogramm = 20,
  Newton = 21,
  Newtonmeter = 22,
  Pascal = 23,
  Bar = 24,
  Joule = 25,
  JoulePerHour = 26,
  Watt = 27,
  VoltAmpere = 28,
  Var = 29,
  WattHour = 30,
  VoltAmpereHour = 31,
  VarHour = 32,
  Ampere = 33,
  Coulomb = 34,
  Volt = 35,
  VoltPerMeter = 36,
  Farad = 37,
  Ohm = 38,
  OhmMeter = 39,
  Weber = 40,
  Tesla = 41,
  AmperePerMeter = 42,
  Henry = 43,
  Hertz = 44,
  InverseWattHour = 45,
  InverseVarHour = 46,
  InverseVoltAmpereHour = 47,
  VoltSquaredHour = 48,
  AmpereSquaredHour = 49,
  KilogrammPerSecond = 50,
  Siemens = 51,
  Kelvin = 52,
  InverseVoltSquaredHour = 53,
  InverseAmpereSquaredHour = 54,
  InverseCubicMeter = 55,
  Percent = 56,
  AmpereHour = 57,
  // 58-59 reserved
  WattHourPerCubicMeter = 60,
  JoulePerCubicMeter = 61,
  MolePercent = 62,
  GrammPerCubicMeter = 63,
  PascalSecond = 64,
  JoulePerKilogramm = 65,
  GramPerSquareCentimeter = 66,
  Atmosphere = 67,
  // 68-69 reserved
  DezibelMilliwatt = 70,
  DezibelMicrovolt = 71,
  Dezibel = 72,
  // 73-127 reserved
  // 128-174 non-SI-units
  // 175-252 reserved
  // 253 extended table of units
  Other = 254,
  Count = 255,
}

impl Unit {
  pub fn as_str(&self) -> Option<&'static str> {
    Some(match self {
      Self::Year => "a",
      Self::Month => "mo",
      Self::Week => "wk",
      Self::Day => "d",
      Self::Hour => "h",
      Self::Minute => "min",
      Self::Second => "s",
      Self::Degree => "°",
      Self::DegreeCelsius => "°C",
      Self::Currency => "currency",
      Self::Meter => "m",
      Self::MeterPerSecond => "m/s",
      Self::CubicMeter => "m³",
      Self::CubicMeterCorrected => "m³",
      Self::CubicMeterPerHour => "m³/h",
      Self::CubicMeterPerHourCorrected => "m³/h",
      Self::CubicMeterPerDay => "m³/d",
      Self::CubicMeterPerDayCorrected => "m³/d",
      Self::Liter => "l",
      Self::Kilogramm => "kg",
      Self::Newton => "N",
      Self::Newtonmeter => "Nm",
      Self::Pascal => "Pa",
      Self::Bar => "bar",
      Self::Joule => "J",
      Self::JoulePerHour => "J/h",
      Self::Watt => "W",
      Self::VoltAmpere => "VA",
      Self::Var => "var",
      Self::WattHour => "Wh",
      Self::VoltAmpereHour => "VAh",
      Self::VarHour => "varh",
      Self::Ampere => "A",
      Self::Coulomb => "C",
      Self::Volt => "V",
      Self::VoltPerMeter => "V/m",
      Self::Farad => "F",
      Self::Ohm => "Ω",
      Self::OhmMeter => "Ωm",
      Self::Weber => "Wb",
      Self::Tesla => "T",
      Self::AmperePerMeter => "A/m",
      Self::Henry => "H",
      Self::Hertz => "Hz",
      Self::InverseWattHour => "1/(Wh)",
      Self::InverseVarHour => "1/(varh)",
      Self::InverseVoltAmpereHour => "1/(VAh)",
      Self::VoltSquaredHour => "V²h",
      Self::AmpereSquaredHour => "A²h",
      Self::KilogrammPerSecond => "kg/s",
      Self::Siemens => "S",
      Self::Kelvin => "K",
      Self::InverseVoltSquaredHour => "1/(V²h)",
      Self::InverseAmpereSquaredHour => "1/(A²h)",
      Self::InverseCubicMeter => "1/m³",
      Self::Percent => "%",
      Self::AmpereHour => "Ah",
      Self::WattHourPerCubicMeter => "Wh/m³",
      Self::JoulePerCubicMeter => "J/m³",
      Self::MolePercent => "Mol %",
      Self::GrammPerCubicMeter => "g/m³",
      Self::PascalSecond => "Pa s",
      Self::JoulePerKilogramm => "J/kg",
      Self::GramPerSquareCentimeter => "g/cm²",
      Self::Atmosphere => "atm",
      Self::DezibelMilliwatt => "dBm",
      Self::DezibelMicrovolt => "dBµV",
      Self::Dezibel => "dB",
      Self::Other | Self::Count => return None,
    })
  }
}

impl fmt::Display for Unit {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    if let Some(s) = self.as_str() {
      s.fmt(f)
    } else {
      Ok(())
    }
  }
}

#[cfg(feature = "serde")]
impl Serialize for Unit {
  fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
    if let Some(s) = self.as_str() {
      serializer.serialize_str(s)
    } else {
      serializer.serialize_none()
    }
  }
}
