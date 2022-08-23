package us.q3q.fido2;

/**
 * Pre-packed CBOR objects for convenience and speed
 */
public abstract class CannedCBOR {
    // Parameters for canned responses
    static final byte[] U2F_V2_RESPONSE = {
            0x55, 0x32, 0x46, 0x5F, 0x56, 0x32
          //   U     2     F     _     V     2
    };
    static final byte[] FIDO_2_RESPONSE = {
            0x46, 0x49, 0x44, 0x4F, 0x5F, 0x32, 0x5F, 0x30
          //   F     I     D     O     _     2     _     0
    };
    static final byte[] HMAC_SECRET_EXTENSION_ID = {
            0x68, 0x6D, 0x61, 0x63, 0x2D, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, // hmac-secret
    };
    static final byte[] CRED_PROTECT_EXTENSION_ID = {
            0x63, 0x72, 0x65, 0x64, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74, // credProtect
    };
    static final byte[] AUTH_INFO_RESPONSE = {
            FIDOConstants.CTAP2_OK,
            (byte) 0xA9, // Map - nine keys
                0x01, // map key: versions
                    (byte) 0x82, // array - two items
                        0x68, // string - eight bytes long
                        0x46, 0x49, 0x44, 0x4F, 0x5F, 0x32, 0x5F, 0x30, // FIDO_2_0
                        0x68, // string - eight bytes long
                        0x46, 0x49, 0x44, 0x4F, 0x5F, 0x32, 0x5F, 0x31, // FIDO_2_1
            0x02, // map key: extensions
                    (byte) 0x82, // array - two items
                        0x6B, // string - eleven bytes long
                            0x63, 0x72, 0x65, 0x64, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74, // credProtect
                        0x6B, // string - eleven bytes long
                            0x68, 0x6D, 0x61, 0x63, 0x2D, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, // hmac-secret
                    0x03, // map key: aaguid
                        0x50, // byte string, 16 bytes long
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // aaguid
                0x04, // map key: options
                    (byte) 0xA7, // map: seven entries
                        0x62, // string: two bytes long
                            0x72, 0x6B, // rk
                            (byte) 0xF5, // true
                        0x62, // string: two bytes long
                            0x75, 0x70, // up
                            (byte) 0xF5, // true
                        0x68, // string - eight bytes long
                            0x61, 0x6c, 0x77, 0x61, 0x79, 0x73, 0x55, 0x76, // alwaysUv
                            (byte) 0xF5, // true
                        0x68, // string - eight bytes long
                            0x63, 0x72, 0x65, 0x64, 0x4d, 0x67, 0x6d, 0x74, // credMgmt
                            (byte) 0xF5, // true
                        0x69, // string: nine bytes long
                            0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x50, 0x69, 0x6e, // clientPin
    };
    static final byte[] MAKE_CRED_UV_NOT_REQD = {
            0x6D, 0x61, 0x6B, 0x65, 0x43, 0x72, 0x65, 0x64, 0x55, 0x76, 0x4E, 0x6F, 0x74, 0x52, 0x71, 0x64
    };
    static final byte[] PIN_UV_AUTH_TOKEN = {
            0x70, 0x69, 0x6E, 0x55, 0x76, 0x41, 0x75, 0x74, 0x68, 0x54, 0x6F, 0x6B, 0x65, 0x6E
    };
    static final byte[] MAKE_CREDENTIAL_RESPONSE_PREAMBLE = {
            0x00, // status - OK!
            (byte) 0xA3, // Map - three keys
                0x01, // map key: fmt
                    0x66, // string - six bytes long
                    0x70, 0x61, 0x63, 0x6B, 0x65, 0x64, // packed
                0x02, // map key: authData
    };
    static final byte[] PUBLIC_KEY_ALG_PREAMBLE = {
            (byte) 0xA5, // map - five entries
                0x01, // map key: kty
                    0x02, // integer (2) - means EC2, a two-point elliptic curve key
                0x03, // map key: alg
                    0x26, // integer (-7) - means ES256 algorithm
                0x20, // map key: crv
                    0x01, // integer (1) - means P256 curve
                0x21, // map key: x-point
                    0x58, // byte string with one-byte length next
                        0x20 // 32 bytes long
    };
    static final byte[] PUBLIC_KEY_DH_ALG_PREAMBLE = {
                0x01, // map key: kty
                    0x02, // integer (2) - means EC2, a two-point elliptic curve key
                0x03, // map key: alg
                    0x38, 0x18, // integer (-25) - means ECDH with SHA256 hash algorithm
                0x20, // map key: crv
                    0x01, // integer (1) - means P256 curve
                0x21, // map key: x-point
                    0x58, // byte string with one-byte length next
                        0x20 // 32 bytes long
    };
    static final byte[] ATTESTATION_STATEMENT_PREAMBLE = {
            0x03, // map key: attestation statement
            (byte) 0xA2, // map - two entries
                    0x63, // string - three bytes long
                        0x61, 0x6C, 0x67, // alg
                        0x26, // integer (-7) - means ES256 algorithm
            0x63, // string: three characters
                        0x73, 0x69, 0x67, // sig
                        0x58, // byte string with one-byte length
    };
    static final byte[] SINGLE_ID_MAP_PREAMBLE = {
            (byte) 0xA1, // map: one entry
                0x62, // string - two bytes long
                    0x69, 0x64, // id
    };

    static final byte[] PUBLIC_KEY_TYPE = {
            0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0x2D, 0x6B, 0x65, 0x79
          //   p     u     b     l     i     c     -     k     e     y
    };
}
