use futures::executor::block_on;
use magnus::{Error, Module, RString, Ruby, function, prelude::*};
use op_crypto_internal_hpke::{
    KemPublic, OpenMode, SealMode, Suite, XWingPublic, generate_keypair,
    open as hpke_open, seal as hpke_seal,
};
use op_crypto_internal_provider::Platform;

const SUITE: Suite = Suite::XWingHkdfSha256Aes256Gcm;
const ENC_LEN: usize = 1120;

// ----------------------------------------------------------------------------
fn generate_key_pair(ruby: &Ruby) -> (RString, RString) {
    let (private_key, public_key) = block_on(generate_keypair::<Platform>(SUITE));
    (ruby.str_from_slice(&private_key), ruby.str_from_slice(&public_key))
}

// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
fn seal(ruby: &Ruby, data: RString, public_key: RString, info: RString) -> Result<RString, Error> {
    let data = unsafe { data.as_slice() }.to_vec();
    let public_key = unsafe { public_key.as_slice() }.to_vec();
    let info = unsafe { info.as_slice() }.to_vec();

    let pk = XWingPublic::parse(&public_key).ok_or_else(|| {
        Error::new(ruby.exception_runtime_error(), "parsing x-wing public key")
    })?;

    let mut enc = Vec::new();
    let ciphertext = block_on(hpke_seal::<Platform>(
        SUITE,
        &KemPublic::XWing(pk),
        SealMode::Base,
        &info,
        &data,
        |e| {
            enc = e.to_vec();
            Vec::new()
        },
    ))
    .map_err(|e| Error::new(ruby.exception_runtime_error(), format!("sealing hpke box: {e:?}")))?;

    enc.extend_from_slice(&ciphertext);
    Ok(ruby.str_from_slice(&enc))
}

// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
fn open(ruby: &Ruby, sealed: RString, private_key: RString, info: RString) -> Result<RString, Error> {
    let sealed = unsafe { sealed.as_slice() }.to_vec();
    let private_key = unsafe { private_key.as_slice() }.to_vec();
    let info = unsafe { info.as_slice() }.to_vec();

    let (enc, ciphertext) = sealed.split_at_checked(ENC_LEN).ok_or_else(|| {
        Error::new(ruby.exception_runtime_error(), "opening hpke box: sealed data too short")
    })?;

    let opened = block_on(hpke_open::<Platform>(
        SUITE,
        &private_key,
        OpenMode::Base,
        enc,
        &info,
        b"",
        ciphertext,
    ))
    .map_err(|e| Error::new(ruby.exception_runtime_error(), format!("opening hpke box: {e:?}")))?;

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