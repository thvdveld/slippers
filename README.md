# Slippers

Implementation of the Serial Line IP (SLIP) protocol from [RFC 1055] for `no_std`.

## Example

### Decoding SLIP

```rust
let encoded = hex!("012345C06789ABC0");
let encoded = SlipDecoder::new(&encoded[..]);
let mut buffer = [0u8; 128];

// Decoding the first frame.
let mut len = 0;
for (d, b) in encoded.iter().zip(buffer.iter_mut()) {
    *b = d;
    len += 1;
}

let result = &buffer[..len];
assert_eq!(result, hex!("012345"));

let encoded = encoded.next_frame()?;

// Decoding the second frame.
let mut len= 0;
for (d, b) in encoded.iter().zip(buffer.iter_mut()) {
    *b = d;
    len += 1;
}

let result = &buffer[..len];
assert_eq!(result, hex!("6789AB"));
assert_eq!(encoded.next_frame(), Err(SlipError::ReachedEnd));
```
## Encoding SLIP

```rust
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
```

[RFC 1055]: https://datatracker.ietf.org/doc/html/rfc1055

License: MIT OR Apache-2.0
