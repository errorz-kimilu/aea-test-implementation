use std::io::Cursor;

use binrw::{
    binrw,
    helpers::{read_u24, write_u24},
    BinRead, BinResult,
};

use sha2::Digest;

use crate::crypto::{HmacDigest, KeyMaterial};

struct ProfileParams {
    prologue_signature_len: usize,
    encryption_data_len: usize,
}

impl ProfileParams {
    fn from_profile_id(profile_id: u32) -> Result<Self, &'static str> {
        Ok(match profile_id {
            0 => ProfileParams {
                prologue_signature_len: 128,
                encryption_data_len: 32,
            },
            1 => ProfileParams {
                prologue_signature_len: 0,
                encryption_data_len: 0,
            },
            2 => ProfileParams {
                prologue_signature_len: 160,
                encryption_data_len: 0,
            },
            3 => ProfileParams {
                prologue_signature_len: 0,
                encryption_data_len: 65,
            },
            4 => ProfileParams {
                prologue_signature_len: 160,
                encryption_data_len: 65,
            },
            5 => ProfileParams {
                prologue_signature_len: 0,
                encryption_data_len: 0,
            },
            _ => return Err("Unknown Profile"),
        })
    }
}

#[allow(non_camel_case_types)]
#[binrw]
#[derive(Debug)]
pub struct u24(
    #[br(parse_with = read_u24)]
    #[bw(write_with = write_u24)]
    pub u32,
);

#[binrw]
#[derive(Debug)]
pub struct HmacTag(
    #[br(map = |h: [u8; 32]| h.into())]
    #[bw(map = |h| h.as_slice())]
    pub HmacDigest,
);

#[binrw]
#[brw(magic = b"AEA1", little)]
#[derive(Debug)]
pub struct AEAPrologue {
    pub profile_id: u24,

    #[br(temp, try_calc = ProfileParams::from_profile_id(profile_id.0))]
    #[bw(ignore)]
    profile: ProfileParams,
    pub scrypt_hardness: u8,
    #[br(temp)]
    #[bw(try_calc = auth_data.len().try_into())]
    pub auth_data_len: u32,
    #[br(args { count: auth_data_len as usize })]
    pub auth_data: Vec<u8>,

    #[br(args { count: profile.prologue_signature_len })]
    pub prologue_signature: Vec<u8>,
    #[br(args { count: profile.encryption_data_len })]
    pub encryption_data: Vec<u8>,

    pub salt: [u8; 32],
    pub root_hmac: HmacTag,
    pub root_header: [u8; 48], // encrypted if profile != 0
    pub first_cluster_hmac: HmacTag,
}

#[binrw]
#[brw(repr = u8)]
#[repr(u8)]
#[derive(Debug)]
pub enum ChecksumAlgorithm {
    None = 0,
    MurMurHash2 = 1, // lol
    Sha256 = 2,
}

impl ChecksumAlgorithm {
    pub fn output_size(&self) -> usize {
        match self {
            Self::None => 0,
            Self::MurMurHash2 => todo!(),
            Self::Sha256 => sha2::Sha256::output_size(),
        }
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct RootHeader {
    pub raw_size: u64,
    pub container_size: u64,
    pub segment_size: u32,         // default: 0x100000
    pub segments_per_cluster: u32, // default: 256
    pub compression_algorithm: u8,
    pub checksum_algorithm: ChecksumAlgorithm,
    #[brw(assert(padding.eq(&[0u8; 22])))]
    padding: [u8; 22],
}

impl RootHeader {
    pub fn cluster_count(&self) -> u32 {
        self.container_size
            .div_ceil(self.segment_size as u64 * self.segments_per_cluster as u64) as u32
    }

    pub fn encrypted_segment_info_size(&self) -> usize {
        (self.checksum_algorithm.output_size() + 8) * self.segments_per_cluster as usize
    }
}

#[binrw]
#[br(little, import(root_header: &RootHeader))]
pub struct ClusterHeader {
    #[br(args { count: root_header.encrypted_segment_info_size() })]
    encrypted_segment_info: Vec<u8>,
    #[br(args { count: root_header.segments_per_cluster as usize + 1 })]
    hmacs: Vec<[u8; 32]>,
}

impl ClusterHeader {
    pub fn next_cluster_hmac(&self) -> &HmacDigest {
        //self.hmacs[0].as_ref()
        HmacDigest::from_slice(&self.hmacs[0])
    }

    pub fn segment_hmac(&self, idx: usize) -> &HmacDigest {
        //&self.hmacs[1..][idx].as_ref()
        HmacDigest::from_slice(&self.hmacs[1..][idx])
    }

    pub fn segment_info(
        &self,
        key: &KeyMaterial,
        expected_hmac: &HmacDigest,
        root_header: &RootHeader,
    ) -> BinResult<Vec<SegmentInfo>> {
        let buf = key.decrypt(
            &self.encrypted_segment_info,
            &[self.hmacs.as_flattened()],
            expected_hmac,
        );

        Vec::<SegmentInfo>::read_args(
            &mut Cursor::new(&buf),
            binrw::args! {
                count: root_header.segments_per_cluster as usize,
                inner: (root_header.checksum_algorithm.output_size(),)
            },
        )
    }
}

#[binrw]
#[brw(little, import(checksum_size: usize))]
#[derive(Debug)]
pub struct SegmentInfo {
    pub decompressed_size: u32,
    pub compressed_size: u32,
    #[br(args { count: checksum_size })]
    #[bw(assert(checksum.len() == checksum_size))]
    pub checksum: Vec<u8>,
}
