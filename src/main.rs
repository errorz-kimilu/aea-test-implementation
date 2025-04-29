use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Cursor, Read, Seek, Write},
};

use binrw::{BinRead, BinWrite};

use der::Decode;
use hmac::Mac;
use p256::ecdsa::{self, signature::Verifier};

mod crypto;
mod file_structures;

use crypto::KeyGenerator;
use file_structures::{AEAPrologue, ClusterHeader, RootHeader};

fn main() {
    let filename = "vectors/vector.0.aea";
    //let filename = "ota.aea";
    let mut aea_reader = BufReader::new(File::open(filename).unwrap());
    let mut output = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open("output")
            .unwrap(),
    );
    let mut prologue: AEAPrologue = BinRead::read(&mut aea_reader).unwrap();

    println!("profile_id: {}", prologue.profile_id.0);
    //dbg!(der::AnyRef::from_der(&prologue.prologue_signature[..]).unwrap());
    //println!("signature: {:X?}", prologue.prologue_signature);
    let key;

    let ikm = if prologue.profile_id.0 == 0 {
        &prologue.encryption_data
    } else {
        let keyfile = "vectors/test_symm";
        //let keyfile = "ota.key";
        key = fs::read(keyfile).unwrap();
        if let Some(key_hex) = key.strip_prefix(b"hex:") {
            &hex::decode(key_hex.strip_suffix(b"\n").unwrap_or(key_hex)).unwrap()
        } else if let Some(key_base64) = key.strip_prefix(b"base64:") {
            println!("{}", String::from_utf8_lossy(key_base64));
            &base64::decode(key_base64.strip_suffix(b"\n").unwrap_or(key_base64)).unwrap()
        } else {
            &key
        }
    };
    assert_eq!(ikm.len(), 32);

    let public_key = if matches!(prologue.profile_id.0, 0 | 2) {
        let encoded_key = std::fs::read_to_string("vectors/test_asymm.pub").unwrap();
        let public_key = ssh_key::PublicKey::from_openssh(&encoded_key).unwrap();
        let ecdsa_key = public_key.key_data().ecdsa().unwrap();
        let point = match ecdsa_key {
            ssh_key::public::EcdsaPublicKey::NistP256(point) => point,
            _ => panic!("didn't provide a p256 public key!"),
        };
        Some(point.clone())
        //Some(ecdsa_key.clone())
    } else {
        None
    };

    if let Some(pk) = public_key {
        let mut prologue_signature = vec![0; prologue.prologue_signature.len()];
        std::mem::swap(&mut prologue.prologue_signature, &mut prologue_signature);

        let mut signed_prologue_bytes =
            Vec::with_capacity(aea_reader.stream_position().unwrap() as usize);
        prologue
            .write(&mut Cursor::new(&mut signed_prologue_bytes))
            .unwrap();

        match prologue.profile_id.0 {
            0 => {
                // This is kinda yucky, and stems from this library not allowing trailing bytes.
                // Probably more secure in any situation where you aren't dealing with variable
                // length signatures in a fixed length field. Meanwhile, Apple's probably trying
                // not to leak the length of the signature when working with encrypted signatures.
                let err = der::AnyRef::from_der(&prologue_signature).unwrap_err();
                if let der::ErrorKind::TrailingData { decoded, .. } = err.kind() {
                    let decoded: u32 = decoded.into();
                    let prologue_signature =
                        ecdsa::Signature::from_der(&prologue_signature[..decoded as usize])
                            .unwrap();
                    ecdsa::VerifyingKey::from_encoded_point(&pk)
                        .unwrap()
                        .verify(&signed_prologue_bytes, &prologue_signature)
                        .unwrap();
                } else {
                    panic!("Failed to parse DER: {err}");
                }
            }
            2 => {
                // From a brief glance at libNeoAppleArchive, the signature appears to be encrypted.
                // Let's hold off on implementing until the wiki gains documentation for this,
                // given the purpose of this implementation.
            }
            _ => {}
        }
    }

    let public_key_bytes = public_key.as_ref().map(|pk| pk.as_bytes()).unwrap_or(&[]);

    let generator = KeyGenerator::new(prologue.profile_id.0, prologue.salt, ikm, public_key_bytes);

    let root_header_key = generator.root_header();

    let root_header = root_header_key.decrypt(
        &prologue.root_header,
        &[&prologue.first_cluster_hmac.0, &prologue.auth_data],
        &prologue.root_hmac.0,
    );

    let root_header: RootHeader = BinRead::read(&mut Cursor::new(&root_header)).unwrap();

    println!(
        "compression_algo: {}",
        root_header.compression_algorithm as char
    );

    let cluster_count = root_header.cluster_count();

    let mut next_cluster_hmac = prologue.first_cluster_hmac.0;
    for cluster_index in 0..cluster_count {
        println!("cluster_hmac: {next_cluster_hmac:x?}");
        let cluster_generator = generator.cluster(cluster_index);
        let cluster_header_key = cluster_generator.cluster_header();

        let cluster_header: ClusterHeader =
            BinRead::read_args(&mut aea_reader, (&root_header,)).unwrap();

        let segment_info = cluster_header
            .segment_info(&cluster_header_key, &next_cluster_hmac, &root_header)
            .unwrap();

        for (idx, info) in segment_info.iter().enumerate() {
            //println!("segment_hmac: {:x?}", cluster_header.segment_hmac(idx));
            if info.compressed_size == 0 {
                // TODO: what are the segment HMACs for empty segments?
                continue;
            }

            let segment_key = cluster_generator.segment(idx as u32);

            let mut segment_buf = vec![0u8; info.compressed_size as usize];
            aea_reader.read_exact(&mut segment_buf).unwrap();

            let mut segment_buf =
                segment_key.decrypt(&segment_buf, &[], cluster_header.segment_hmac(idx));

            assert_eq!(root_header.compression_algorithm, b'e');

            //dbg!(&segment_buf[..4]);

            if info.compressed_size != info.decompressed_size {
                let mut decoder = lzfse_rust::LzfseDecoder::default();
                let mut decompressed_buf = Vec::with_capacity(info.decompressed_size as usize);
                decoder
                    .decode_bytes(&segment_buf, &mut decompressed_buf)
                    .unwrap();

                segment_buf = decompressed_buf.into();
            }

            assert_eq!(segment_buf.len(), info.decompressed_size as usize);

            output.write_all(&segment_buf).unwrap();
        }

        // setup for next cluster
        next_cluster_hmac = cluster_header.next_cluster_hmac().clone();
    }

    // verify the padding at the end of the file.
    let mut padding = vec![];
    aea_reader.read_to_end(&mut padding).unwrap();

    println!("padding_len: {}", padding.len());

    println!("last_cluster_hmac: {next_cluster_hmac:x?}");

    if prologue.profile_id.0 != 0 {
        generator
            .trailing_padding()
            .chain_update(&padding)
            .verify(&next_cluster_hmac)
            .unwrap();
    } else {
        // TODO: what is the last cluster HMAC on profile id 0?
    }
}
