#[allow(dead_code)]
#[allow(unused_parens)]

type ProtocolVersion = u16;
type Random = [u8; 32];

// This is our list of valid TLS state machine states
// https://tlswg.github.io/tls13-spec/#rfc.appendix.A.2

#[derive(PartialEq)]
pub enum TLSState {
    Start,
    RecievedClientHello,
    Negotiated,
    WaitEndOfEarlyData,
    WaitFlight2,
    WaitCert,
    WaitCertificateVerify,
    WaitFinished,
    Connected
}

// This is a list of possible errors
pub enum TLSError {
    InvalidState,
    InvalidMessage
}

pub enum CipherSuite {
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    TLS_AES_128_CCM_SHA256 = 0x1304,
    TLS_AES_128_CCM_8_SHA256 = 0x1305
}

pub enum ContentType {
    InvalidReserved = 0,
    ChangeCipherSpecReserved = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

pub struct TLSPlaintext {
    pub ctype : ContentType,
    pub legacy_record_version : ProtocolVersion,
    pub length : u16, // MUST not exceed 2^14 bytes, otherwise record_overflow error
    pub fragment : Vec<u8>,
}

pub struct TLSInnerPlaintext {
    content : Vec<u8>,
    ctype : ContentType,
    zeros: Vec<u8> // length_of_padding
}

pub struct TLSCiphertext {
    opaque_type : ContentType, // = ContentType::ApplicationData,
    legacy_record_version : ProtocolVersion, //= ContentType::TLSv13,
    length : u16,
    encrypted_record : Vec<u8> // max length is 'length'
}

pub enum AlertLevel {
    Warning = 1,
    Fatal = 2,
}

pub enum AlertDescription {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    DecryptionFailedReserved = 21,
    RecordOverflow = 22,
    DecompressionFailureReserved = 30,
    HandshakeFailure = 40,
    NoCertificateReserved = 41,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnkonwn = 46,
    IllegalParameter = 47,
    UnknownCa = 48,
    AccessDenied = 49,
    DecodeError = 50,
    DecryptError = 51,
    ExportRestrictionReserved = 60,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    InappropriateFallback = 86,
    UserCanceled = 90,
    NoRenegotiationReserved = 100,
    MissingExtensino = 109,
    UnsupportedExtension = 110,
    CertificateUnobtainable = 111,
    UnrecognnizedName = 112,
    BadCertificateStatusResponse = 113,
    BadCertificateHashValue = 114,
    UnknownPskIdentity = 115,
    CertificateRequired = 116
}

pub struct Alert {
    level : AlertLevel,
    description : AlertDescription
}

pub enum HandshakeType {
    HelloRequestReserved = 0,
    ClientHello = 1,
    ServerHello = 2,
    HelloVerifyRequestReserved = 3,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    HelloRetryRequest = 6,
    EncryptedExtensions = 8,
    Certificate = 11,
    ServerKeyExchangeReserved = 12,
    CertificateRequest = 13,
    ServerHelloDoneReserved = 14,
    CertificateVerify = 15,
    ClientKeyExchangeReserved = 16,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
}

pub enum HandshakeMessage {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    EndOfEarlyData(EndOfEarlyData),
    HelloRetryRequest(HelloRetryRequest),
    EncryptedExtensions(EncryptedExtensions),
    CertificateRequest(CertificateRequest),
    Certificate(Certificate),
    CertificateVerify(CertificateVerify),
    Finished(Finished),
    NewSessionTicket(NewSessionTicket),
    KeyUpdate(KeyUpdate)
}

pub struct Handshake {
    msg_type : HandshakeType,
    length : u32, // IMPORTANT: This is supposed to be a u24, rust has no u24 so we use u32
    body : HandshakeMessage
}

pub struct ClientHello {
    legacy_version : u16, // 0x0303,
    random: Random,
    legacy_session_id : [u8; 32], // <0..32>
    cipher_suites : Vec<CipherSuite>,
    legacy_compression_methods: [u8; 255],
    extensions: Vec<Extension> // <8..2^16-2>
}

pub struct ServerHello {
    version : ProtocolVersion,
    random : Random,
    cipher_suite : CipherSuite,
    extensions : Vec<Extension> // <6..2^16-2>
}

pub struct HelloRetryRequest {
    server_version : ProtocolVersion,
    cipher_suite : CipherSuite,
    extensions : Vec<Extension> // <2..2^16-1>
}

pub struct Extension {
    extension_type : ExtensionType,
    extension_data : Vec<u8> // <0..2^16-1>
}

// TODO: We must ensure that this value is be 2 bytes long!
pub enum ExtensionType {
    SupportedGroups = 10,
    SignatureAlgorithms = 13,
    KeyShare = 40,
    PreSharedKey = 41,
    EarlyData = 42,
    SupportedVersions = 43,
    Cookie = 44,
    PskKeyExchangeModes = 45,
    CertificateAuthorities = 47,
    OldFilters = 48,
}

pub struct KeyShareEntry {
    group : NamedGroup,
    key_exchange : Vec<u8> // <1..2^16-1>
}

pub struct KeyShare {
/*
   pub struct {
       select (Handshake.msg_type) {
           case client_hello:
               KeyShareEntry client_shares<0..2^16-1>;

           case hello_retry_request:
               NamedGroup selected_group;

           case server_hello:
               KeyShareEntry server_share;
       };
   } KeyShare;
*/
}

pub enum PskKeyExchangeMode {
    PskKe = 0,
    PskDheKe = 1,
}

pub struct PskKeyExchangeModes {
    ke_modes : Vec<PskKeyExchangeMode> // <1..255>
}

pub struct Empty {}

pub enum EarlyDataIndicationOptions {
    NewSessionTicket(u32), // max_early_data_size,
    ClientHello(Empty),
    EncryptedExtensions(Empty)
}

pub struct EarlyDataIndication {
    value : EarlyDataIndicationOptions
}

pub struct PskIdentity {
        identity : Vec<u8>, // <1..2^16-1>
        obfuscated_ticket_age : u32
}

type PskBinderEntry = Vec<u8>; // <32..255>

pub enum PreSharedKeyExtensionOptions {
    ClientHello(Vec<PskIdentity>, Vec<PskBinderEntry>), // identities<7..2^16-1> and binders<33..2^16-1>
    ServerHello(u16)
}

pub struct PreSharedKeyExtension {
    msg : PreSharedKeyExtensionOptions,
}


pub struct SupportedVersions {
    versions : [ProtocolVersion], // <2..254>
}

pub struct Cookie {
    cookie : Vec<u8> // <1..2^16-1>
}

// Should be 2 bytes, u16
pub enum SignatureScheme {
    /* RSASSA-PKCS1-v1_5 algorithms */
    rsa_pkcs1_sha1 = 0x0201,
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,

    /* ECDSA algorithms */
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,

    /* RSASSA-PSS algorithms */
    rsa_pss_sha256 = 0x0804,
    rsa_pss_sha384 = 0x0805,
    rsa_pss_sha512 = 0x0806,

    /* EdDSA algorithms */
    ed25519 = 0x0807,
    ed448 = 0x0808,
}


pub struct SignatureSchemeList {
    supported_signature_algorithms : [SignatureScheme], // <2..2^16-2>
}

pub enum NamedGroup {
    /* Elliptic Curve Groups (ECDHE) */
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    secp521r1 = 0x0019,
    x25519 = 0x001d,
    x448 = 0x001e,

    /* Finite Field Groups (DHE) */
    ffdhe2048 = 0x0100,
    ffdhe3072 = 0x0101,
    ffdhe4096 = 0x0102,
    ffdhe6144 = 0x0103,
    ffdhe8192 = 0x0104,

}

pub struct NamedGroupList {
    named_group_list : [NamedGroup] // <2..2^16-1>
}

type DistinguishedName = Vec<u8>; // <1..2^16-1>

pub struct CertificateAuthoritiesExtension {
    authorities : [DistinguishedName] //<3..2^16-1>;
}

pub struct EncryptedExtensions {
    extensions : Vec<Extension> //<0..2^16-1>;
}

pub struct CertificateRequest {
    certificate_request_context : Vec<u8>, // <0..2^8-1>;
    extensions : Vec<Extension> //<2..2^16-1>;
}

pub struct OIDFilter {
    certificate_extension_oid : Vec<u8>, //<1..2^8-1>;
    certificate_extension_values : Vec<u8>, //<0..2^16-1>;
}

pub struct OIDFilterExtension {
    filters : Vec<u8>, //<0..2^16-1>;
}

type ASN1Cert = Vec<u8>; //<1..2^24-1>;

pub struct CertificateEntry {
    cert_data : ASN1Cert,
    extensions : Vec<Extension> //<0..2^16-1>;
}

pub struct Certificate {
    certificate_request_context : Vec<u8>, //<0..2^8-1>;
    certificate_list : Vec<CertificateEntry> //<0..2^24-1>;
}

pub struct CertificateVerify {
    algorithm : SignatureScheme,
    signature : Vec<u8> //<0..2^16-1>;
}

pub struct Finished {
    verify_data : Vec<u8> //[Hash.length];
}

pub struct NewSessionTicket {
    ticket_lifetime : u32,
    ticket_age_add : u32,
    ticket : Vec<u8>, //<1..2^16-1>;
    extensions : Vec<Extension>, //<0..2^16-2>;
}

pub struct EndOfEarlyData {}

pub enum KeyUpdateRequest {
    update_not_requested = 0,
    update_requested = 1,
}

pub struct KeyUpdate {
    request_update : KeyUpdateRequest,
}
