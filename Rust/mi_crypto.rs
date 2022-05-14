use pretty_hex::*;
use ccm::{Ccm, consts::{U4, U12}};
use ccm::aead::{Aead, NewAead, generic_array::GenericArray};
use aes::Aes128;
use ccm::aead::Payload;
use sha2::Sha256;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::{PublicKey, ecdh::EphemeralSecret};
use rand_core::{OsRng, RngCore};
use anyhow::Result;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;
type AesCcm = Ccm<Aes128, U4, U12>;

#[derive(Error, Debug)]
pub enum MiCryptoError {
  #[error("Header for message is invalid")]
  InvalidHeader,
  #[error("Error when tried decrypt uart message: {0}")]
  DecryptUart(ccm::aead::Error),
  #[error("Crypto Failure: {0}")]
  Other(anyhow::Error)
}

impl From<anyhow::Error> for MiCryptoError {
  fn from(other: anyhow::Error) -> Self {
    MiCryptoError::Other(other)
  }
}

const NONCE : [u8; 12] = [
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
  0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b
];

fn encrypt_did(key: &[u8], did: &[u8]) -> Vec<u8> {
  let aad = b"devID";
  tracing::debug!("Encrypting Did");
  tracing::debug!("  key: {:?}", key.hex_dump());
  tracing::debug!("  did: {:?}", did.hex_dump());
  tracing::debug!("  aad: {:?}", aad.hex_dump());

  let nonce = GenericArray::from_slice(&NONCE);
  let key = GenericArray::from_slice(key);

  let aes_ccm = AesCcm::new(key);

  aes_ccm.encrypt(&nonce, Payload {
    msg: did,
    aad: aad
  }).expect("Could not encrypt did")// output 48 bytes
}

fn derive_key(secret: &[u8], salt: Option<&[u8]>) -> [u8; 64] {
  let mut info = b"mible-setup-info";

  if salt.is_some() {
    info = b"mible-login-info";
  }

  let hk = Hkdf::<Sha256>::new(salt, secret);
  let mut okm = [0u8; 64];

  hk.expand(info, &mut okm)
    .expect("64 is a valid length for Sha256 to output");
  tracing::debug!("Derive: {:?}", okm.hex_dump());

  okm
}

pub type Hash = [u8; 32];
fn hash(secret : &[u8], data: &[u8]) -> Hash {
  tracing::debug!("Hash:");
  tracing::debug!("  secret: {:?}", secret.hex_dump());
  tracing::debug!("  data: {:?}", data.hex_dump());

  let mut mac = HmacSha256::new_from_slice(secret)
    .expect("HMAC can take key of any size");
  mac.update(&data);
  let result = mac.finalize();

  tracing::debug!("result= {:?}", result.clone().into_bytes().hex_dump());

  result.into_bytes()[0..32].try_into().unwrap()
}

pub type AuthToken = [u8; 12];

pub fn calc_did(my_secret_key: &EphemeralSecret, remote_key_bytes: &[u8], remote_info: &[u8]) -> (Vec<u8>, AuthToken) {
  let key_bytes = remote_key_bytes;
  tracing::debug!("Calculating did with remote key: {:?}", key_bytes.hex_dump());

  let remote_public_key = PublicKey::from_sec1_bytes(&key_bytes).expect("Key sent by scooter is invalid");

  let secret = my_secret_key.diffie_hellman(&remote_public_key);
  tracing::debug!("  eShareKey: {}", secret.as_bytes().hex_dump());

  let derived_key = derive_key(secret.as_bytes(), None); // HKDF!
  tracing::debug!("  Derived Key: {:?}", derived_key.hex_dump());

  let token    = &derived_key[0..12];
  let bind_key = &derived_key[12..28];
  let a        = &derived_key[28..44];

  tracing::debug!("  Token:      {:?}", token.hex_dump());
  tracing::debug!("  BindKey:    {:?}", bind_key.hex_dump());
  tracing::debug!("  A:          {:?}", a.hex_dump());
  tracing::debug!("  RemoteInfo: {:?}", remote_info.hex_dump());

  let did_ct = encrypt_did(a, &remote_info[4..]);
  tracing::debug!("  AES did CT: {:?}", did_ct.hex_dump());

  let mut final_token = [0u8; 12];
  final_token.copy_from_slice(token);

  return (did_ct, final_token)
}

#[derive(Clone)]
pub struct EncryptionKey {
  pub key: [u8; 16],
  pub iv: [u8; 4],
}

/**
 * List of keys used for encrypting uart communication
 */
#[derive(Clone)]
pub struct LoginKeychain {
  pub dev: EncryptionKey,
  pub app: EncryptionKey
}

pub fn calc_login_did(rand_key : &mut [u8], remote_info: &mut [u8], auth_token: &AuthToken) -> (Hash, Hash, LoginKeychain) {
  let mut salt : Vec<u8> = Vec::new();

  salt.extend_from_slice(rand_key);
  salt.extend_from_slice(remote_info);
  tracing::debug!("Salt: {:?}", salt.hex_dump());

  let mut salt_inv : Vec<u8> = Vec::new();

  salt_inv.extend_from_slice(remote_info);
  salt_inv.extend_from_slice(rand_key);
  tracing::debug!("Inv Salt: {:?}", salt_inv.hex_dump());

  let derived_key = derive_key(auth_token, Some(salt.as_slice()));

  let dev_key = &derived_key[0..16];
  let app_key = &derived_key[16..32];
  let dev_iv = &derived_key[32..36];
  let app_iv = &derived_key[36..40];

  tracing::debug!("  DevKey:      {:?}", dev_key.hex_dump());
  tracing::debug!("  AppKey:      {:?}", app_key.hex_dump());
  tracing::debug!("  DevIv:       {:?}", dev_iv.hex_dump());
  tracing::debug!("  AppIv:       {:?}", app_iv.hex_dump());

  let keys = LoginKeychain {
    dev: EncryptionKey {
      key: dev_key.try_into().unwrap(),
      iv: dev_iv.try_into().unwrap(),
    },

    app: EncryptionKey {
      key: app_key.try_into().unwrap(),
      iv: app_iv.try_into().unwrap(),
    },
  };

  let info = hash(app_key, &salt);
  let expected_remote_info = hash(dev_key, &salt_inv);

  tracing::debug!("  Info:      {:?}", info.hex_dump());
  tracing::debug!("  Expected:  {:?}", expected_remote_info.hex_dump());

  (info, expected_remote_info, keys)
}

/**
 * Generate private and public key
 */
pub fn gen_key_pair() -> (EphemeralSecret, PublicKey) {
  let secret = EphemeralSecret::random(&mut OsRng);
  let public = secret.public_key();

  (secret, public)
}

pub type RandKey = [u8; 16];

/**
 * Generate rand key used for login
 */
pub fn gen_rand_key() -> RandKey {
  let mut data : RandKey = [0u8; 16];
  OsRng::fill_bytes(&mut OsRng, &mut data);

  data
}

const HEADER : [u8; 2] = [0x55, 0xab];

pub fn encrypt_uart(encryption_key: &EncryptionKey, msg: &[u8], it : u32, rand: Option<[u8; 4]>) -> Vec<u8> {
  tracing::debug!("Encrypting UART");

  let it = it.to_be_bytes();

  let rand = rand.or_else(|| {
    let mut rand : [u8; 4] = [0u8; 4];
    OsRng::fill_bytes(&mut OsRng, &mut rand);
    Some(rand)
  }).unwrap();

  tracing::debug!("  rand: {:?}", rand.hex_dump());
  tracing::debug!("  it: {:?}", it.hex_dump());
  tracing::debug!("  message: {:?}", msg.hex_dump());
  tracing::debug!("  iv: {:?}", encryption_key.iv.hex_dump());
  tracing::debug!("  key: {:?}", encryption_key.key.hex_dump());

  let size : &[u8] = &msg[0..1];
  tracing::debug!("  size: {:?}", size.hex_dump());

  let mut data : Vec<u8> = Vec::new();
  data.extend_from_slice(&msg[1..]);
  tracing::debug!("  data: {:?}", data.hex_dump());
  data.extend_from_slice(&rand);
  tracing::debug!("  data with rand: {:?}", data.hex_dump());

  let mut nonce : Vec<u8> = Vec::new();
  nonce.extend_from_slice(&encryption_key.iv);
  for _ in 0..4 { nonce.push(0); }
  nonce.extend_from_slice(&it);
  tracing::debug!("  nonce: {:?}", nonce.hex_dump());

  let key = GenericArray::from_slice(&encryption_key.key);
  let nonce = GenericArray::from_slice(&nonce);
  let aes_ccm = AesCcm::new(&key);

  let ct = aes_ccm.encrypt(&nonce, data.as_slice())
    .expect("Could not encrypt uart");// output 48 bytes

  tracing::debug!("  CT: {:?}", ct.hex_dump());

  let mut send_data : Vec<u8> = Vec::new();
  send_data.extend_from_slice(size);
  send_data.extend_from_slice(&it[0..2]);
  send_data.extend_from_slice(ct.as_slice());
  tracing::debug!("  Send data: {:?}", send_data.hex_dump());

  let crc = crc16(send_data.as_slice()); // new checksum
  tracing::debug!("  CRC: {:?}", crc.hex_dump());

  send_data.insert(0, HEADER[1]); // second header
  send_data.insert(0, HEADER[0]); // new header starts here
  send_data.extend_from_slice(&crc);

  tracing::debug!("  Final data: {:?}", send_data.hex_dump());

  send_data
}

pub fn crc16(bytes: &[u8]) -> [u8; 2] {
  let mut sum : i16 = 0;
  for byte in bytes {
    sum += *byte as i16;
  }

  let mut res = (-(sum) - 1).to_be_bytes();
  res.reverse();
  res
}

pub fn decrypt_uart(encryption_key: &EncryptionKey, msg: &[u8]) -> Result<Vec<u8>, MiCryptoError> {
  tracing::debug!("  Decrypting data: {:?}", msg.hex_dump());
  let header = &msg[0..2];

  if header != HEADER {
    tracing::error!("Invalid header: {:?}", header.hex_dump());
    return Err(MiCryptoError::InvalidHeader)
  }

  let it = &msg[3..5];
  let ct = &msg[5..msg.len() - 2];

  tracing::debug!("  it: {:?}", it.hex_dump());
  tracing::debug!("  ct: {:?}", ct.hex_dump());
  tracing::debug!("  key: {:?}", encryption_key.key.hex_dump());

  let mut nonce : Vec<u8> = Vec::new();
  nonce.extend_from_slice(&encryption_key.iv);
  for _ in 0..4 { nonce.push(0); }
  nonce.extend_from_slice(it);
  for _ in 0..2 { nonce.push(0); }
  tracing::debug!("  nonce: {:?}", nonce.hex_dump());

  let key = GenericArray::from_slice(&encryption_key.key);
  let nonce = GenericArray::from_slice(&nonce);
  let aes_ccm = AesCcm::new(key);

  tracing::debug!("Decrypting...");

  let data = match aes_ccm.decrypt(nonce, Payload {
    msg: ct,
    aad: &[], //of course returned aad is empty array, because fuck you thats why...
  }) {
    Ok(data) => data,
    Err(err) => {
      tracing::error!("Decryption error: {}", err);
      return Err(MiCryptoError::DecryptUart(err))
    }
  };

  tracing::debug!("  Decrypted data: {:?}", data.hex_dump());

  Ok(data)
}
