use hpke::{
    Deserializable, Kem, OpModeR, OpModeS, Serializable, aead::AesGcm256,
    hybrid_array::typenum::Unsigned, kdf::HkdfSha256, kem::XWing, single_shot_open,
    single_shot_seal,
};
use magnus::{Error, Module, RString, Ruby, function, prelude::*};

// ----------------------------------------------------------------------------
fn generate_key_pair(ruby: &Ruby) -> (RString, RString) {
    let (private_key, public_key) = XWing::gen_keypair();
    (
        ruby.str_from_slice(&private_key.to_bytes()),
        ruby.str_from_slice(&public_key.to_bytes()),
    )
}

// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
fn seal(ruby: &Ruby, data: RString, public_key: RString, info: RString) -> Result<RString, Error> {
    let data = unsafe { data.as_slice() }.to_vec();
    let public_key = unsafe { public_key.as_slice() }.to_vec();
    let info = unsafe { info.as_slice() }.to_vec();

    let pk = <XWing as Kem>::PublicKey::from_bytes(&public_key).map_err(|e| {
        Error::new(ruby.exception_runtime_error(), format!("parsing x-wing public key: {e}"))
    })?;

    let (enc, ciphertext) = single_shot_seal::<AesGcm256, HkdfSha256, XWing>(
        &OpModeS::Base,
        &pk,
        &info,
        &data,
        b"",
    )
    .map_err(|e| Error::new(ruby.exception_runtime_error(), format!("sealing hpke box: {e}")))?;

    let mut sealed = enc.to_bytes().to_vec();
    sealed.extend_from_slice(&ciphertext);
    Ok(ruby.str_from_slice(&sealed))
}

// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
fn open(ruby: &Ruby, sealed: RString, private_key: RString, info: RString) -> Result<RString, Error> {
    let sealed = unsafe { sealed.as_slice() }.to_vec();
    let private_key = unsafe { private_key.as_slice() }.to_vec();
    let info = unsafe { info.as_slice() }.to_vec();

    let sk = <XWing as Kem>::PrivateKey::from_bytes(&private_key).map_err(|e| {
        Error::new(ruby.exception_runtime_error(), format!("parsing x-wing private key: {e}"))
    })?;

    let enc_len = <<XWing as Kem>::EncappedKey as Serializable>::OutputSize::USIZE;
    let (enc, ciphertext) = sealed.split_at_checked(enc_len).ok_or_else(|| {
        Error::new(ruby.exception_runtime_error(), "opening hpke box: sealed data too short")
    })?;

    let enc = <XWing as Kem>::EncappedKey::from_bytes(enc)
        .map_err(|e| Error::new(ruby.exception_runtime_error(), format!("opening hpke box: {e}")))?;

    let opened = single_shot_open::<AesGcm256, HkdfSha256, XWing>(
        &OpModeR::Base,
        &sk,
        &enc,
        &info,
        ciphertext,
        b"",
    )
    .map_err(|e| Error::new(ruby.exception_runtime_error(), format!("opening hpke box: {e}")))?;

    Ok(ruby.str_from_slice(&opened))
}

// ----------------------------------------------------------------------------

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    let krypto = ruby.define_module("Krypto")?;
    let hpke = krypto.define_module("HPKE")?;
    hpke.define_singleton_method("generate_key_pair", function!(generate_key_pair, 0))?;
    hpke.define_singleton_method("seal", function!(seal, 3))?;
    hpke.define_singleton_method("open", function!(open, 3))?;
    Ok(())
}
