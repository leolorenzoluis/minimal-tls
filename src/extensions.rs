use std::slice::Iter;
use structures::{Extension, TLSError, ProtocolVersion};
use structures::{Cookie, NamedGroup, NamedGroupList, SignatureScheme, SignatureSchemeList, SupportedVersions};

impl Extension {

	pub fn parse_supported_groups<'a>(iter: &mut Iter<'a, u8>) -> Result<Extension, TLSError> {
		let first = iter.next().unwrap();
		let second = iter.next().unwrap();

		let length = ((*first as u16) << 8) | (*second as u16);

        if length == 0 {
            return Err(TLSError::InvalidHandshakeError)
        }

		let mut ret : Vec<NamedGroup> = Vec::new();
		for x in 1..(length/2) {

			let first = iter.next();
			let second = iter.next();
			if first.is_none() || second.is_none() {
				return Err(TLSError::InvalidHandshakeError)
			}

			ret.push(match ((*first.unwrap() as u16) << 8) | (*second.unwrap() as u16) {
                0x0017 => NamedGroup::secp256r1,
                0x0018 => NamedGroup::secp384r1,
                0x0019 => NamedGroup::secp521r1,
                0x001d => NamedGroup::x25519,
                0x001e => NamedGroup::x448,
                0x0100 => NamedGroup::ffdhe2048,
                0x0101 => NamedGroup::ffdhe3072,
                0x0102 => NamedGroup::ffdhe4096,
                0x0103 => NamedGroup::ffdhe6144,
                0x0104 => NamedGroup::ffdhe8192,
                _ => return Err(TLSError::InvalidHandshakeError)
            });
		}

        Ok(Extension::SupportedGroups(NamedGroupList{named_group_list : ret}))
	}

	pub fn parse_signature_algorithms<'a>(iter: &mut Iter<'a, u8>) -> Result<Extension, TLSError> {
		let first = iter.next().unwrap();
		let second = iter.next().unwrap();

		let length = ((*first as u16) << 8) | (*second as u16);

        if length == 0 || length > 2^16 - 2{
            return Err(TLSError::InvalidHandshakeError)
        }

		let mut ret : Vec<SignatureScheme> = Vec::new();
		for _ in 1..(length/2) {

			let first = iter.next();
			let second = iter.next();
			if first.is_none() || second.is_none() {
				return Err(TLSError::InvalidHandshakeError)
			}

			ret.push(match ((*first.unwrap() as u16) << 8) | (*second.unwrap() as u16) {
				/* RSASSA-PKCS1-v1_5 algorithms */
				0x0201 => SignatureScheme::rsa_pkcs1_sha1,
				0x0401 => SignatureScheme::rsa_pkcs1_sha256,
				0x0501 => SignatureScheme::rsa_pkcs1_sha384,
				0x0601 => SignatureScheme::rsa_pkcs1_sha512,

				/* ECDSA algorithms */
				0x0403 => SignatureScheme::ecdsa_secp256r1_sha256,
				0x0503 => SignatureScheme::ecdsa_secp384r1_sha384,
				0x0603 => SignatureScheme::ecdsa_secp521r1_sha512,

				/* RSASSA-PSS algorithms */
				0x0804 => SignatureScheme::rsa_pss_sha256,
				0x0805 => SignatureScheme::rsa_pss_sha384,
				0x0806 => SignatureScheme::rsa_pss_sha512,

				/* EdDSA algorithms */
				0x0807 => SignatureScheme::ed25519,
				0x0808 => SignatureScheme::ed448,
                _ => return Err(TLSError::InvalidHandshakeError)
            });
		}

        Ok(Extension::SignatureAlgorithms(SignatureSchemeList{supported_signature_algorithms : ret}))
	}

	pub fn parse_keyshare<'a>(iter: &mut Iter<'a, u8>) -> Result<Extension, TLSError> {
		Err(TLSError::InvalidHandshakeError)
	}

	pub fn parse_preshared_key<'a>(iter: &mut Iter<'a, u8>) -> Result<Extension, TLSError> {
		Err(TLSError::InvalidHandshakeError)
	}

	pub fn parse_earlydata<'a>(iter: &mut Iter<'a, u8>) -> Result<Extension, TLSError> {
		Err(TLSError::InvalidHandshakeError)
	}

	pub fn parse_supported_versions<'a>(iter: &mut Iter<'a, u8>) -> Result<Extension, TLSError> {
		// TODO: Is it possible for these to ever panic?
		let first = iter.next().unwrap();
		let second = iter.next().unwrap();

		let length = ((*first as u16) << 8) | (*second as u16);
        if length < 2 || length > 254 {
            return Err(TLSError::InvalidHandshakeError)
        }
		let mut ret : Vec<ProtocolVersion> = Vec::new();
		for _ in 1..(length/2) {

			let first = iter.next();
			let second = iter.next();
			if first.is_none() || second.is_none() {
				return Err(TLSError::InvalidHandshakeError)
			}

			ret.push(((*first.unwrap() as u16) << 8) | (*second.unwrap() as u16));
		}

        Ok(Extension::SupportedVersions(SupportedVersions{versions: ret}))
	}

	pub fn parse_cookie<'a>(iter: &mut Iter<'a, u8>) -> Result<Extension, TLSError> {
		let first = iter.next().unwrap();
		let second = iter.next().unwrap();

		let length = ((*first as u16) << 8) | (*second as u16);
        if length < 1 {
            return Err(TLSError::InvalidHandshakeError)
        }
		let ret : Vec<u8> = iter.take(length as usize).map(|&x| x).collect();
        Ok(Extension::Cookie(Cookie{cookie : ret}))
	}

	pub fn parse_psk_key_exchange_modes<'a>(iter: &mut Iter<'a, u8>) -> Result<Extension, TLSError> {
		Err(TLSError::InvalidHandshakeError)
	}

	pub fn parse_certificate_authorities<'a>(iter: &mut Iter<'a, u8>) -> Result<Extension, TLSError> {
		Err(TLSError::InvalidHandshakeError)
	}

	pub fn parse_oldfilters<'a>(iter: &mut Iter<'a, u8>) -> Result<Extension, TLSError> {
		Err(TLSError::InvalidHandshakeError)
	}
}
