extern crate byteorder;
use serialization::byteorder::{NetworkEndian, WriteBytesExt};

use structures::{HandshakeMessage, TLSPlaintext};

pub trait TLSToBytes {
	fn as_bytes(&self) -> Vec<u8>;
}

// FIXME: These need to be implemented
impl<'a> TLSToBytes for &'a TLSPlaintext {
	fn as_bytes(&self) -> Vec<u8> {
    	let mut ret : Vec<u8> = Vec::new();

    	// Content type
    	ret.push(self.ctype as u8);

    	// Protocol version
    	ret.write_u16::<NetworkEndian>(self.legacy_record_version).unwrap();

    	// Data length
    	ret.write_u16::<NetworkEndian>(self.length).unwrap();

    	// Data
		ret.extend(self.fragment.clone());

		ret
	}
}

impl<'a> TLSToBytes for &'a HandshakeMessage {
	fn as_bytes(&self) -> Vec<u8> {
		Vec::new()
	}
}
