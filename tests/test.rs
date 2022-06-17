extern crate cobs;
extern crate quickcheck;

use quickcheck::{quickcheck, TestResult};
use cobs::{max_encoding_length, encode, decode, encode_vec, decode_vec};
use cobs::{encode_vec_with_sentinel, decode_vec_with_sentinel};
use cobs::{CobsEncoder, CobsDecoder};

fn test_pair(source: Vec<u8>, encoded: Vec<u8>) {
    let mut test_encoded = encoded.clone();
    let mut test_decoded = source.clone();

    // Mangle data to ensure data is re-populated correctly
    test_encoded.iter_mut().for_each(|i| *i = 0x80);
    encode(&source[..], &mut test_encoded[..]);

    // Mangle data to ensure data is re-populated correctly
    test_decoded.iter_mut().for_each(|i| *i = 0x80);
    decode(&encoded[..], &mut test_decoded[..]).unwrap();

    assert_eq!(encoded, test_encoded);
    assert_eq!(source, test_decoded);
}

fn test_roundtrip(source: Vec<u8>) {
    let encoded = encode_vec(&source);
    let decoded = decode_vec(&encoded).expect("decode_vec");
    assert_eq!(source, decoded);
}

#[test]
fn decode_malforemd() {
    let malformed_buf: [u8;32] = [68, 69, 65, 68, 66, 69, 69, 70, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut dest_buf : [u8;32] = [0;32];
    if let Err(()) = decode(&malformed_buf, &mut dest_buf){
        return;
    } else {
        assert!(false, "invalid test result.");
    }
}

#[test]
fn stream_roundtrip() {
    for ct in 1..=1000 {
        let source: Vec<u8> = (ct..2*ct)
            .map(|x: usize| (x & 0xFF) as u8)
            .collect();

        let mut dest = vec![0u8; max_encoding_length(source.len())];

        let sz_en = {
            let mut ce = CobsEncoder::new(&mut dest);

            for c in source.chunks(17) {
                ce.push(c).unwrap();
            }
            let sz = ce.finalize().unwrap();
            sz
        };

        let mut decoded = source.clone();
        decoded.iter_mut().for_each(|i| *i = 0x80);
        let sz_de = {
            let mut cd = CobsDecoder::new(&mut decoded);

            for c in dest[0..sz_en].chunks(11) {
                cd.push(c).unwrap();
            }
            let sz_msg = cd.feed(0).unwrap().unwrap();
            sz_msg
        };

        assert_eq!(sz_de, source.len());
        assert_eq!(source, decoded);
    }

}

#[test]
fn test_max_encoding_length() {
    assert_eq!(max_encoding_length(253), 254);
    assert_eq!(max_encoding_length(254), 255);
    assert_eq!(max_encoding_length(255), 257);
    assert_eq!(max_encoding_length(254 * 2), 255 * 2);
    assert_eq!(max_encoding_length(254 * 2 + 1), 256 * 2);
}

#[test]
fn test_encode_1() {
    test_pair(vec![10, 11, 0, 12], vec![3, 10, 11, 2, 12])
}

#[test]
fn test_encode_2() {
    test_pair(vec![0, 0, 1, 0], vec![1, 1, 2, 1, 1])
}

#[test]
fn test_encode_3() {
    test_pair(vec![255, 0], vec![2, 255, 1])
}

#[test]
fn test_encode_4() {
    test_pair(vec![1], vec![2, 1])
}

#[test]
fn test_encode_all_nonzero_253() {
    test_pair(
        // 253 bytes, all non-zero.
        vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
            47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68,
            69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
            91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109,
            110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126,
            127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
            144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160,
            161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177,
            178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194,
            195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211,
            212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228,
            229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245,
            246, 247, 248, 249, 250, 251, 252, 253,
        ],
        vec![
            254, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67,
            68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89,
            90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108,
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
            126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142,
            143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,
            160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176,
            177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193,
            194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210,
            211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227,
            228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244,
            245, 246, 247, 248, 249, 250, 251, 252, 253,
        ],
    )
}

#[test]
fn test_encode_all_nonzero_254() {
    test_pair(
        // 254 bytes, all non-zero.
        // This is an edge-case for COBS encoding. A naive encoder might encode it with a final
        // unnecessary 0x01 length byte, which would be a valid encoding but non-optimal.
        vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
            47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68,
            69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
            91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109,
            110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126,
            127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
            144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160,
            161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177,
            178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194,
            195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211,
            212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228,
            229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245,
            246, 247, 248, 249, 250, 251, 252, 253, 254,
        ],
        vec![
            255, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67,
            68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89,
            90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108,
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
            126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142,
            143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,
            160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176,
            177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193,
            194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210,
            211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227,
            228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244,
            245, 246, 247, 248, 249, 250, 251, 252, 253, 254,
        ],
    )
}

#[test]
fn test_encode_all_nonzero_255() {
    test_pair(
        // 255 bytes, all non-zero.
        vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
            47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68,
            69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
            91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109,
            110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126,
            127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
            144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160,
            161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177,
            178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194,
            195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211,
            212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228,
            229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245,
            246, 247, 248, 249, 250, 251, 252, 253, 254, 255,
        ],
        vec![
            255, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67,
            68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89,
            90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108,
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
            126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142,
            143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,
            160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176,
            177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193,
            194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210,
            211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227,
            228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244,
            245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 2, 255,
        ],
    )
}

#[test]
fn test_decode_non_optimal_nonzero_254() {
    // 254 bytes, all non-zero.
    // This is an edge-case for COBS encoding. A naive encoder might encode it with a final
    // unnecessary 0x01 length byte, which would be a valid encoding but non-optimal.
    // The decoded should still properly decode such a non-optimal encoding.
    let source = vec![
        1_u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70,
        71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93,
        94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112,
        113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130,
        131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148,
        149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166,
        167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184,
        185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202,
        203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220,
        221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238,
        239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254,
    ];
    let non_optimal_encoded = vec![
        255_u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
        47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69,
        70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92,
        93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
        112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129,
        130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147,
        148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165,
        166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183,
        184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201,
        202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219,
        220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237,
        238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 1,
    ];
    let mut test_decoded = vec![0x80_u8; 254];

    decode(&non_optimal_encoded[..], &mut test_decoded[..]).unwrap();

    assert_eq!(source, test_decoded);
}

#[test]
fn test_roundtrip_1() {
    test_roundtrip(vec![1,2,3]);
}

#[test]
fn test_roundtrip_2() {
    for i in 0..5usize {
        let mut v = Vec::new();
        for j in 0..252+i {
            v.push(j as u8);
        }
        test_roundtrip(v);
    }
}

fn identity(source: Vec<u8>, sentinel: u8) -> TestResult {
    let encoded = encode_vec_with_sentinel(&source[..], sentinel);

    // Check that the sentinel doesn't show up in the encoded message
    for x in encoded.iter() {
        if *x == sentinel {
            return TestResult::error("Sentinel found in encoded message.");
        }
    }

    // Check that the decoding the encoded message returns the original message
    match decode_vec_with_sentinel(&encoded[..], sentinel) {
        Ok(decoded) => {
            if source == decoded {
                TestResult::passed()
            } else {
                TestResult::failed()
            }
        }
        Err(_) => TestResult::error("Decoding Error"),
    }
}

#[test]
fn test_encode_decode_with_sentinel() {
    quickcheck(identity as fn(Vec<u8>, u8) -> TestResult);
}

#[test]
fn test_encode_decode() {
    fn identity_default_sentinel(source: Vec<u8>) -> TestResult {
        identity(source, 0)
    }
    quickcheck(identity_default_sentinel as fn(Vec<u8>) -> TestResult);
}

#[test]
fn wikipedia_ex_6() {
    let mut unencoded: Vec<u8> = vec![];

    (1..=0xFE).for_each(|i| unencoded.push(i));

    // NOTE: trailing 0x00 is implicit
    let mut encoded: Vec<u8> = vec![];
    encoded.push(0xFF);
    (1..=0xFE).for_each(|i| encoded.push(i));

    test_pair(unencoded, encoded);
}

#[test]
fn wikipedia_ex_7() {
    let mut unencoded: Vec<u8> = vec![];

    (0..=0xFE).for_each(|i| unencoded.push(i));

    // NOTE: trailing 0x00 is implicit
    let mut encoded: Vec<u8> = vec![];
    encoded.push(0x01);
    encoded.push(0xFF);
    (1..=0xFE).for_each(|i| encoded.push(i));

    test_pair(unencoded, encoded);
}

#[test]
fn wikipedia_ex_8() {
    let mut unencoded: Vec<u8> = vec![];

    (1..=0xFF).for_each(|i| unencoded.push(i));

    // NOTE: trailing 0x00 is implicit
    let mut encoded: Vec<u8> = vec![];
    encoded.push(0xFF);
    (1..=0xFE).for_each(|i| encoded.push(i));
    encoded.push(0x02);
    encoded.push(0xFF);

    test_pair(unencoded, encoded);
}

#[test]
fn wikipedia_ex_9() {
    let mut unencoded: Vec<u8> = vec![];

    (2..=0xFF).for_each(|i| unencoded.push(i));
    unencoded.push(0x00);

    // NOTE: trailing 0x00 is implicit
    let mut encoded: Vec<u8> = vec![];
    encoded.push(0xFF);
    (2..=0xFF).for_each(|i| encoded.push(i));
    encoded.push(0x01);
    encoded.push(0x01);

    test_pair(unencoded, encoded);
}

#[test]
fn wikipedia_ex_10() {
    let mut unencoded: Vec<u8> = vec![];

    (3..=0xFF).for_each(|i| unencoded.push(i));
    unencoded.push(0x00);
    unencoded.push(0x01);

    // NOTE: trailing 0x00 is implicit
    let mut encoded: Vec<u8> = vec![];
    encoded.push(0xFE);
    (3..=0xFF).for_each(|i| encoded.push(i));
    encoded.push(0x02);
    encoded.push(0x01);

    test_pair(unencoded, encoded);
}

#[test]
fn issue_15() {
    // Reported: https://github.com/awelkie/cobs.rs/issues/15

    let my_string_buf = b"\x00\x11\x00\x22";
    let max_len = cobs::max_encoding_length(my_string_buf.len());
    assert!(max_len < 128);
    let mut buf = [0u8; 128];

    let len = cobs::encode_with_sentinel(
        my_string_buf,
        &mut buf,
        b'\x00');

    let cobs_buf = &buf[0..len];

    let mut decoded_dest_buf = [0u8; 128];
    let new_len = cobs::decode_with_sentinel(
        cobs_buf,
        &mut decoded_dest_buf,
        b'\x00').unwrap();
    let decoded_buf = &decoded_dest_buf[0..new_len];

    println!("{:?}  {:?}  {:?}", my_string_buf, cobs_buf, decoded_buf);
    assert_eq!(my_string_buf, decoded_buf);
}
