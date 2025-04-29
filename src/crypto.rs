use aes::cipher::{KeyIvInit, StreamCipher};
use hmac::Mac;
use static_slicing::StaticRangeIndex as SRI;
use std::{borrow::Cow, marker::PhantomData};

pub type Hkdf = hkdf::Hkdf<sha2::Sha256>;
pub type AesCtr = ctr::Ctr64BE<aes::Aes256>;
pub type HmacSha256 = hmac::Hmac<sha2::Sha256>;
pub type HmacDigest = hmac::digest::Output<HmacSha256>;

pub struct MainGenerator;
pub struct ClusterGenerator;

pub struct KeyGenerator<T> {
    hkdf: Hkdf,
    profile_id: u32,
    _phantom: PhantomData<T>,
}

impl<T> KeyGenerator<T> {
    fn expand(&self, info: &[&[u8]]) -> KeyMaterial {
        let mut material = [0u8; 80];
        let mut material_ref = material.as_mut_slice();
        if self.profile_id == 0 {
            material_ref = &mut material_ref[..32];
        }

        self.hkdf
            .expand_multi_info(info, material_ref)
            .expect("HKDF should be able to generate enough key material.");

        KeyMaterial {
            hmac_key: material[SRI::<0, 32>],
            aes_key: material[SRI::<32, 32>].into(),
            aes_iv: material[SRI::<64, 16>].into(),
            profile_id: self.profile_id,
        }
    }
}

impl KeyGenerator<MainGenerator> {
    pub fn new(profile_id: u32, salt: [u8; 32], ikm: &[u8], public_key: &[u8]) -> Self {
        let mut main_key = [0u8; 32];
        Hkdf::new(Some(&salt), ikm)
            .expand_multi_info(
                &[b"AEA_AMK", profile_id.to_le_bytes().as_slice(), public_key],
                &mut main_key,
            )
            .expect("HKDF should be able to generate enough key material.");

        KeyGenerator {
            hkdf: Hkdf::new(None, &main_key),
            //hkdf: Hkdf::from_prk(&main_key).unwrap(),
            profile_id,
            _phantom: PhantomData,
        }
    }

    pub fn root_header(&self) -> KeyMaterial {
        self.expand(&[b"AEA_RHEK"])
    }

    pub fn cluster(&self, cluster_index: u32) -> KeyGenerator<ClusterGenerator> {
        let mut cluster_key = [0u8; 32];
        self.hkdf
            .expand_multi_info(&[b"AEA_CK", &cluster_index.to_le_bytes()], &mut cluster_key)
            .expect("HKDF should be able to generate enough key material.");

        KeyGenerator {
            hkdf: Hkdf::new(None, &cluster_key),
            profile_id: self.profile_id,
            _phantom: PhantomData,
        }
    }

    pub fn trailing_padding(&self) -> HmacSha256 {
        let mut padding_auth_key = [0u8; 32];
        self.hkdf
            .expand(b"AEA_PAK", &mut padding_auth_key)
            .expect("HKDF should be able to generate enough key material.");
        HmacSha256::new_from_slice(&padding_auth_key).unwrap()
    }
}

impl KeyGenerator<ClusterGenerator> {
    pub fn cluster_header(&self) -> KeyMaterial {
        self.expand(&[b"AEA_CHEK"])
    }

    pub fn segment(&self, segment_index: u32) -> KeyMaterial {
        self.expand(&[b"AEA_SK", &segment_index.to_le_bytes()])
    }
}

pub struct KeyMaterial {
    hmac_key: [u8; 32],
    aes_key: aes::cipher::Key<AesCtr>,
    aes_iv: aes::cipher::Iv<AesCtr>,
    profile_id: u32,
}

impl KeyMaterial {
    pub fn decrypt<'a>(
        &self,
        ciphertext: &'a [u8],
        ad: &[&[u8]],
        expected_hmac: &hmac::digest::Output<HmacSha256>,
    ) -> Cow<'a, [u8]> {
        let mut hmac = HmacSha256::new_from_slice(&self.hmac_key).unwrap();
        let authenticated_len: u64 = ad
            .iter()
            .map(|d| d.len())
            .sum::<usize>()
            .try_into()
            .unwrap();
        for data in ad {
            hmac.update(data);
        }
        hmac.chain_update(ciphertext)
            .chain_update(authenticated_len.to_le_bytes().as_slice())
            .verify(expected_hmac)
            .unwrap();
        if self.profile_id != 0 {
            let mut plaintext = vec![0; ciphertext.len()];
            let mut state = AesCtr::new(&self.aes_key, &self.aes_iv);
            state
                .apply_keystream_b2b(&ciphertext, &mut plaintext)
                .unwrap();
            plaintext.into()
        } else {
            ciphertext.into()
        }
    }
}
