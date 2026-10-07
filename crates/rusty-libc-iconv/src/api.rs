use crate::conv::{Converter, Error, OpenError};
use alloc::vec::Vec;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ConvertError {
    pub kind: Error,
    pub consumed: usize,
}

impl Converter {
    pub fn convert(&mut self, input: &[u8], output: &mut Vec<u8>) -> Result<usize, ConvertError> {
        let mut ip = 0;
        let irr = 0;
        loop {
            let start = output.len();
            let room = (input.len() - ip).max(16) * 2 + 64;
            output.resize(start + room, 0);
            let mut op = 0;
            let r = self.convert_raw(input, &mut ip, &mut output[start..], &mut op);
            output.truncate(start + op);
            match r {
                Ok(n) => return Ok(irr + n),
                Err(Error::E2big) => continue,
                Err(kind) => return Err(ConvertError { kind, consumed: ip }),
            }
        }
    }

    pub fn finish(&mut self, output: &mut Vec<u8>) -> Result<(), Error> {
        let start = output.len();
        output.resize(start + 64, 0);
        let mut op = 0;
        let r = self.flush_raw(Some((&mut output[start..], &mut op)));
        output.truncate(start + op);
        r.map(|_| ())
    }

    pub fn convert_all(to: &str, from: &str, input: &[u8]) -> Result<Vec<u8>, OneShotError> {
        let mut c = Converter::new(to, from).map_err(OneShotError::Open)?;
        let mut out = Vec::new();
        c.convert(input, &mut out).map_err(OneShotError::Convert)?;
        c.finish(&mut out).map_err(|kind| OneShotError::Convert(ConvertError { kind, consumed: input.len() }))?;
        Ok(out)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OneShotError {
    Open(OpenError),
    Convert(ConvertError),
}
