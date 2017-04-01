use structures::{HandshakeMessage, TLSPlaintext};

pub trait TLSToBytes {
	fn to_bytes(self) -> Vec<u8>;
}

// FIXME: These need to be implemented
impl<'a> TLSToBytes for &'a TLSPlaintext {
	fn to_bytes(self) -> Vec<u8> {
		/*
		    pub ctype : ContentType,
    pub legacy_record_version : ProtocolVersion,
    pub length : u16, // MUST not exceed 2^14 bytes, otherwise record_overflow error
    pub fragment : Vec<u8>,
    */
    	let ret : Vec<u8> = Vec::new();

    	// Content type
    	ret.push(self.ctype);

    	// Protocol version
    	ret.push()

    	// Data length

    	// Data

		ret
	}
}

impl<'a> TLSToBytes for &'a HandshakeMessage {
	fn to_bytes(self) -> Vec<u8> {
		Vec::new()
	}
}
