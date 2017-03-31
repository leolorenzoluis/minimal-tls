use structures::{HandshakeMessage, TLSPlaintext};

pub trait TLSToBytes {
	fn to_bytes(self) -> Vec<u8>;
}

// FIXME: These need to be implemented
impl<'a> TLSToBytes for &'a TLSPlaintext {
	fn to_bytes(self) -> Vec<u8> {
		Vec::new()
	}
}

impl<'a> TLSToBytes for &'a HandshakeMessage {
	fn to_bytes(self) -> Vec<u8> {
		Vec::new()
	}
}
