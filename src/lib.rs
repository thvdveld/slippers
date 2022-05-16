const END: u8 = 0xc0;
const ESC: u8 = 0xdb;
const ESC_END: u8 = 0xdc;
const ESC_ESC: u8 = 0xdd;

#[derive(Debug)]
enum SlipState {
    None,
    Escaped,
}

#[derive(Debug, PartialEq)]
pub enum SlipError {
    UnexpectedAfterEscaped,
    ReachedEnd,
}

pub fn decode(
    buffer: &mut [u8],
) -> Result<(&[u8], Option<core::ops::RangeFrom<usize>>), SlipError> {
    println!("{}", buffer.len());
    if buffer.is_empty() {
        return Ok((&[], None));
    }

    let mut state = SlipState::None;
    let mut i = 0;
    let mut ctr = 0;

    while ctr < buffer.len() {
        match state {
            SlipState::None => match buffer[ctr] {
                END => {
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
                ESC => {
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
                ESC_END => {
                    buffer[i] = END;
                    state = SlipState::None;
                    ctr += 1;
                    i += 1;
                }
                ESC_ESC => {
                    buffer[i] = ESC;
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

#[cfg(test)]
mod tests {
    use super::*;
    use hexlit::hex;

    #[test]
    fn decode_empty() {
        let mut data = [];
        let (decoded, rest) = decode(&mut data[..]).unwrap();

        assert_eq!(decoded, []);
        assert_eq!(rest, None);
    }

    #[test]
    fn decode_one_packet() {
        let mut data = hex!("00112233445566C0");

        let (decoded, rest) = decode(&mut data[..]).unwrap();
        assert_eq!(decoded, hex!("00112233445566"));
        assert_eq!(rest, None);
    }

    #[test]
    fn decode_two_packets() {
        let mut data = hex!("012345C06789ABC0");

        let (decoded, rest) = decode(&mut data[..]).unwrap();
        assert_eq!(decoded, hex!("012345"));
        assert_eq!(rest, Some(4..));

        let (decoded, rest) = decode(&mut data[rest.unwrap()]).unwrap();
        assert_eq!(decoded, hex!("6789AB"));
        assert_eq!(rest, None);
    }

    #[test]
    fn decode_with_escaped_end() {
        let mut data = hex!("00DBDCFFC0");

        let (decoded, rest) = decode(&mut data[..]).unwrap();
        assert_eq!(decoded, hex!("00C0FF"));
        assert_eq!(rest, None);
    }

    #[test]
    fn decode_with_escaped_esc() {
        let mut data = hex!("AADBDD55C0");

        let (decoded, rest) = decode(&mut data[..]).unwrap();
        assert_eq!(decoded, hex!("AADB55"));
        assert_eq!(rest, None);
    }

    #[test]
    fn decode_with_escape_error() {
        let mut data = hex!("00DBAA11C0");

        assert_eq!(
            decode(&mut data[..]),
            Err(SlipError::UnexpectedAfterEscaped)
        );
    }
}
