//! Implementation of the Serial Line IP (SLIP) protocol from [RFC 1055] for `no_std`.
//!
//! # Example
//!
//! ## Decoding SLIP
//!
//! ```rust
//! # use hexlit::hex;
//! # use slippers::{SlipDecoder, SlipError};
//! # fn main() -> Result<(), SlipError> {
//! let encoded = hex!("012345C06789ABC0");
//! let encoded = SlipDecoder::new(&encoded[..]);
//! let mut buffer = [0u8; 128];
//!
//! // Decoding the first frame.
//! let mut len = 0;
//! for (d, b) in encoded.iter().zip(buffer.iter_mut()) {
//!     *b = d;
//!     len += 1;
//! }
//!
//! let result = &buffer[..len];
//! assert_eq!(result, hex!("012345"));
//!
//! let encoded = encoded.next_frame()?;
//!
//! // Decoding the second frame.
//! let mut len= 0;
//! for (d, b) in encoded.iter().zip(buffer.iter_mut()) {
//!     *b = d;
//!     len += 1;
//! }
//!
//! let result = &buffer[..len];
//! assert_eq!(result, hex!("6789AB"));
//! assert_eq!(encoded.next_frame(), Err(SlipError::ReachedEnd));
//! # Ok(())
//! # }
//! ```
//! # Encoding SLIP
//!
//! ```rust
//! # use hexlit::hex;
//! # use slippers::SlipEncoder;
//! # fn main() -> Result<(), SlipError> {
//! let data = hex!("00112233445566");
//! let expected = hex!("00112233445566C0");
//! let slip = SlipEncoder::new(&data);
//! let mut buffer = [0u8; 128];
//!
//! let mut len = 0;
//! for (i, (v, b)) in slip.iter().zip(buffer.iter_mut()).enumerate() {
//!     *b = v;
//!     len = i;
//! }
//!
//! assert_eq!(&buffer[..len + 1], &expected);
//! # }
//! ```
//!
//! [RFC 1055]: https://datatracker.ietf.org/doc/html/rfc1055

#![no_std]

/// A SLIP decoder.
///
/// # Example
///
/// ```rust
/// # use hexlit::hex;
/// # use slippers::SlipDecoder;
/// # use slippers::SlipError;
/// let data = hex!("AADBDD55C0");
/// let result = hex!("AADB55");
///
/// let slip = SlipDecoder::new(&data);
/// for (b, exp) in slip.iter().zip(result.iter()) {
///     assert_eq!(b, *exp);
/// }
///
/// assert_eq!(slip.next_frame(), Err(SlipError::ReachedEnd));
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SlipDecoder<'a> {
    buffer: &'a [u8],
}

impl<'a> SlipDecoder<'a> {
    /// Create a new SLIP decoder by passing a slice with the encoded values to it.
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer }
    }

    /// Return a new SLIP decoder for the next frame in the encoded buffer.
    pub fn next_frame(mut self) -> Result<SlipDecoder<'a>, SlipError> {
        if self.buffer.is_empty() {
            return Err(SlipError::ReachedEnd);
        } else {
            let mut slip_state = SlipState::None;
            while !self.buffer.is_empty() {
                let c = self.buffer[0];
                match slip_state {
                    SlipState::None => match c {
                        slip_values::ESC => {
                            self.buffer = &self.buffer[1..];
                            slip_state = SlipState::Escaped;
                        }
                        slip_values::END => {
                            self.buffer = &self.buffer[1..];
                            break;
                        }
                        _ => self.buffer = &self.buffer[1..],
                    },
                    SlipState::Escaped => match c {
                        slip_values::ESC_END => {
                            self.buffer = &self.buffer[1..];
                            slip_state = SlipState::None;
                        }
                        slip_values::ESC_ESC => {
                            self.buffer = &self.buffer[1..];
                            slip_state = SlipState::None;
                        }
                        _ => return Err(SlipError::UnexpectedAfterEscaped),
                    },
                }
            }
        }

        if self.buffer.is_empty() || (self.buffer.len() == 1 && self.buffer[0] == slip_values::END)
        {
            Err(SlipError::ReachedEnd)
        } else {
            Ok(SlipDecoder::new(self.buffer))
        }
    }

    /// Return an iterator returning the decoded values until the END byte is reached.
    pub fn iter(&self) -> SlipDecoderIterator {
        SlipDecoderIterator::from(self.buffer)
    }
}

/// An iterator over a buffer that emits the decoded package.
#[derive(Debug, Copy, Clone)]
pub struct SlipDecoderIterator<'a> {
    buffer: &'a [u8],
    state: SlipState,
}

impl<'a> Iterator for SlipDecoderIterator<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buffer.is_empty() {
            None
        } else {
            let c = self.buffer[0];
            match self.state {
                SlipState::None => match c {
                    slip_values::ESC => {
                        self.buffer = &self.buffer[1..];
                        self.state = SlipState::Escaped;
                        self.next()
                    }
                    slip_values::END => {
                        if self.buffer.len() == 1 {}
                        None
                    }
                    _ => {
                        let c = self.buffer[0];
                        self.buffer = &self.buffer[1..];
                        Some(c)
                    }
                },
                SlipState::Escaped => match c {
                    slip_values::ESC_END => {
                        self.buffer = &self.buffer[1..];
                        self.state = SlipState::None;
                        Some(slip_values::END)
                    }
                    slip_values::ESC_ESC => {
                        self.buffer = &self.buffer[1..];
                        self.state = SlipState::None;
                        Some(slip_values::ESC)
                    }
                    _ => None,
                },
            }
        }
    }
}

impl<'a> From<&'a [u8]> for SlipDecoderIterator<'a> {
    fn from(val: &'a [u8]) -> Self {
        SlipDecoderIterator {
            buffer: val,
            state: SlipState::None,
        }
    }
}

/// Checks if the encoded package contains errors.
/// _Note_: it only checks until the end of the first encoded frame.
pub fn check_for_errors(buffer: &[u8]) -> Result<(), SlipError> {
    let mut state = SlipState::None;
    for b in buffer {
        match state {
            SlipState::None => match *b {
                slip_values::ESC => state = SlipState::Escaped,
                slip_values::END => break,
                _ => (),
            },
            SlipState::Escaped => match *b {
                slip_values::ESC_END | slip_values::ESC_ESC => state = SlipState::None,
                _ => return Err(SlipError::UnexpectedAfterEscaped),
            },
        }
    }

    Ok(())
}

/// Decode SLIP in place.
///
/// # Errors
///
pub fn decode_in_place(
    buffer: &mut [u8],
) -> Result<(&[u8], Option<core::ops::RangeFrom<usize>>), SlipError> {
    // TODO(thvdveld): use the SLIP decoder struct instead of re-implementing the decoding here.
    if buffer.is_empty() {
        return Ok((&[], None));
    }

    let mut state = SlipState::None;
    let mut i = 0;
    let mut ctr = 0;

    while ctr < buffer.len() {
        match state {
            SlipState::None => match buffer[ctr] {
                slip_values::END => {
                    ctr += 1;
                    return Ok((
                        &buffer[..i],
                        if ctr == buffer.len() {
                            None
                        } else {
                            Some(ctr..)
                        },
                    ));
                }
                slip_values::ESC => {
                    ctr += 1;
                    state = SlipState::Escaped;
                }
                _ => {
                    buffer[i] = buffer[ctr];
                    ctr += 1;
                    i += 1;
                }
            },
            SlipState::Escaped => match buffer[ctr] {
                slip_values::ESC_END => {
                    buffer[i] = slip_values::END as u8;
                    state = SlipState::None;
                    ctr += 1;
                    i += 1;
                }
                slip_values::ESC_ESC => {
                    buffer[i] = slip_values::ESC as u8;
                    state = SlipState::None;
                    ctr += 1;
                    i += 1;
                }
                _ => return Err(SlipError::UnexpectedAfterEscaped),
            },
        }
    }

    Err(SlipError::ReachedEnd)
}

/// A SLIP encoder.
///
/// # Example
///
/// ```rust
/// # use hexlit::hex;
/// # use slippers::SlipEncoder;
/// # fn main() -> Result<(), SlipError> {
/// let data = hex!("00112233445566");
/// let expected = hex!("00112233445566C0");
/// let slip = SlipEncoder::new(&data);
/// let mut buffer = [0u8; 128];
///
/// let mut len = 0;
/// for (i, (v, b)) in slip.iter().zip(buffer.iter_mut()).enumerate() {
///     *b = v;
///     len = i;
/// }
///
/// assert_eq!(&buffer[..len + 1], &expected);
/// # }
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SlipEncoder<'a> {
    buffer: &'a [u8],
}

impl<'a> SlipEncoder<'a> {
    /// Create a new SLIP decoder by passing a slice with the encoded values to it.
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer }
    }

    /// Return an iterator returning the decoded values until the END byte is reached.
    pub fn iter(&self) -> SlipEncoderIterator {
        SlipEncoderIterator::from(self.buffer)
    }
}

/// An iterator over a buffer that emits the decoded package.
#[derive(Debug, Copy, Clone)]
pub struct SlipEncoderIterator<'a> {
    buffer: &'a [u8],
    escaped: Option<u8>,
    done: bool,
}

impl<'a> Iterator for SlipEncoderIterator<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            None
        } else if self.buffer.is_empty() {
            self.done = true;
            Some(slip_values::END)
        } else {
            match self.escaped {
                Some(c) => {
                    self.escaped = None;
                    Some(c)
                }
                None => {
                    let c = self.buffer[0];
                    match c {
                        slip_values::END => {
                            self.buffer = &self.buffer[1..];
                            self.escaped = Some(slip_values::ESC_END);
                            Some(slip_values::ESC)
                        }
                        slip_values::ESC => {
                            self.buffer = &self.buffer[1..];
                            self.escaped = Some(slip_values::ESC_ESC);
                            Some(slip_values::ESC)
                        }
                        _ => {
                            self.buffer = &self.buffer[1..];
                            Some(c)
                        }
                    }
                }
            }
        }
    }
}

impl<'a> From<&'a [u8]> for SlipEncoderIterator<'a> {
    fn from(val: &'a [u8]) -> Self {
        SlipEncoderIterator {
            buffer: val,
            escaped: None,
            done: false,
        }
    }
}

pub(crate) mod slip_values {
    pub const END: u8 = 0xc0;
    pub const ESC: u8 = 0xdb;
    pub const ESC_END: u8 = 0xdc;
    pub const ESC_ESC: u8 = 0xdd;
}

#[derive(Debug, Copy, Clone)]
enum SlipState {
    None,
    Escaped,
}

#[derive(Debug, PartialEq)]
pub enum SlipError {
    UnexpectedAfterEscaped,
    ReachedEnd,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexlit::hex;

    #[test]
    fn encode_empty() {
        let data = [];
        let expected = [slip_values::END];
        let slip = SlipEncoder::new(&data);
        let mut buffer = [0u8; 128];

        let mut len = 0;
        for (i, (v, b)) in slip.iter().zip(buffer.iter_mut()).enumerate() {
            *b = v;
            len = i;
        }

        assert_eq!(&buffer[..len + 1], &expected);
    }

    #[test]
    fn decode_empty_iter() {
        let data = [];
        let slip = SlipDecoder::new(&data);

        let mut slip_iter = slip.iter();
        assert_eq!(slip_iter.next(), None);

        // Make sure that there is no next frame in the buffer.
        assert_eq!(slip.next_frame(), Err(SlipError::ReachedEnd));
    }

    #[test]
    fn decode_empty() {
        let mut data = [];
        let (decoded, rest) = decode_in_place(&mut data[..]).unwrap();

        assert_eq!(decoded, []);
        assert_eq!(rest, None);
    }

    #[test]
    fn encode_one_packet() {
        let data = hex!("00112233445566");
        let expected = hex!("00112233445566C0");
        let slip = SlipEncoder::new(&data);
        let mut buffer = [0u8; 128];

        let mut len = 0;
        for (i, (v, b)) in slip.iter().zip(buffer.iter_mut()).enumerate() {
            *b = v;
            len = i;
        }

        assert_eq!(&buffer[..len + 1], &expected);
    }

    #[test]
    fn decode_one_packet_iter() {
        let data = hex!("00112233445566C0");
        let result = hex!("00112233445566");

        let slip = SlipDecoder::new(&data);
        for (b, exp) in slip.iter().zip(result.iter()) {
            assert_eq!(b, *exp);
        }

        assert_eq!(slip.next_frame(), Err(SlipError::ReachedEnd));
    }

    #[test]
    fn decode_one_packet() {
        let mut data = hex!("00112233445566C0");
        check_for_errors(&data).unwrap();

        let (decoded, rest) = decode_in_place(&mut data[..]).unwrap();
        assert_eq!(decoded, hex!("00112233445566"));
        assert_eq!(rest, None);
    }

    #[test]
    fn encode_two_packets() {
        let data1 = hex!("012345");
        let data2 = hex!("6789AB");
        let expected = hex!("012345C06789ABC0");
        let mut buffer = [0u8; 128];

        let mut len = 0;
        let slip = SlipEncoder::new(&data1);
        for (i, (b, v)) in buffer.iter_mut().zip(slip.iter()).enumerate() {
            *b = v;
            len = i;
        }
        len += 1;

        let mut len2 = 0;
        let slip = SlipEncoder::new(&data2);
        for (i, (b, v)) in buffer[len..].iter_mut().zip(slip.iter()).enumerate() {
            *b = v;
            len2 = i;
        }
        len2 += 1;
        let total_len = len + len2;

        assert_eq!(&buffer[..total_len], &expected);
    }

    #[test]
    fn decode_two_packets_iter() {
        let data = hex!("012345C06789ABC0");
        let first_result = hex!("012345");
        let second_result = hex!("6789AB");

        let slip = SlipDecoder::new(&data);
        for (b, exp) in slip.iter().zip(first_result.iter()) {
            assert_eq!(b, *exp);
        }

        let slip = slip.next_frame().unwrap();

        for (b, exp) in slip.iter().zip(second_result.iter()) {
            assert_eq!(b, *exp);
        }

        assert_eq!(slip.next_frame(), Err(SlipError::ReachedEnd));
    }

    #[test]
    fn decode_two_packets() {
        let mut data = hex!("012345C06789ABC0");
        check_for_errors(&data).unwrap();

        let (decoded, rest) = decode_in_place(&mut data[..]).unwrap();
        assert_eq!(decoded, hex!("012345"));
        assert_eq!(rest, Some(4..));

        let (decoded, rest) = decode_in_place(&mut data[rest.unwrap()]).unwrap();
        assert_eq!(decoded, hex!("6789AB"));
        assert_eq!(rest, None);
    }

    #[test]
    fn encode_with_escaped_end() {
        let data = hex!("00C0FF");
        let expected = hex!("00DBDCFFC0");
        let slip = SlipEncoder::new(&data);
        let mut buffer = [0u8; 128];

        let mut len = 0;
        for (i, (v, b)) in slip.iter().zip(buffer.iter_mut()).enumerate() {
            *b = v;
            len = i;
        }

        assert_eq!(&buffer[..len + 1], &expected);
    }

    #[test]
    fn decode_with_escaped_end_iter() {
        let data = hex!("00DBDCFFC0");
        let result = hex!("00C0FF");

        let slip = SlipDecoder::new(&data);
        for (b, exp) in slip.iter().zip(result.iter()) {
            assert_eq!(b, *exp);
        }

        assert_eq!(slip.next_frame(), Err(SlipError::ReachedEnd));
    }

    #[test]
    fn decode_with_escaped_end() {
        let mut data = hex!("00DBDCFFC0");
        check_for_errors(&data).unwrap();

        let (decoded, rest) = decode_in_place(&mut data[..]).unwrap();
        assert_eq!(decoded, hex!("00C0FF"));
        assert_eq!(rest, None);
    }

    #[test]
    fn encode_with_escaped_esc() {
        let data = hex!("AADB55");
        let expected = hex!("AADBDD55C0");

        let slip = SlipEncoder::new(&data);
        let mut buffer = [0u8; 128];

        let mut len = 0;
        for (i, (v, b)) in slip.iter().zip(buffer.iter_mut()).enumerate() {
            *b = v;
            len = i;
        }

        assert_eq!(&buffer[..len + 1], &expected);
    }

    #[test]
    fn decode_with_escaped_esc_iter() {
        let data = hex!("AADBDD55C0");
        let result = hex!("AADB55");

        let slip = SlipDecoder::new(&data);
        for (b, exp) in slip.iter().zip(result.iter()) {
            assert_eq!(b, *exp);
        }

        assert_eq!(slip.next_frame(), Err(SlipError::ReachedEnd));
    }

    #[test]
    fn decode_with_escaped_esc() {
        let mut data = hex!("AADBDD55C0");
        check_for_errors(&data).unwrap();

        let (decoded, rest) = decode_in_place(&mut data[..]).unwrap();
        assert_eq!(decoded, hex!("AADB55"));
        assert_eq!(rest, None);
    }

    #[test]
    fn decode_with_escape_error_iter() {
        let data = hex!("00DBAA11C0");
        let result = hex!("00");

        let slip = SlipDecoder::new(&data);
        for (b, exp) in slip.iter().zip(result.iter()) {
            assert_eq!(b, *exp);
        }

        assert_eq!(slip.next_frame(), Err(SlipError::UnexpectedAfterEscaped));
    }

    #[test]
    fn decode_with_escape_error() {
        let mut data = hex!("00DBAA11C0");
        assert_eq!(
            check_for_errors(&data),
            Err(SlipError::UnexpectedAfterEscaped)
        );

        assert_eq!(
            decode_in_place(&mut data[..]),
            Err(SlipError::UnexpectedAfterEscaped)
        );
    }
}
