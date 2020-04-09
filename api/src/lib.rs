extern crate jni;

use algebra::{fields::{
    mnt4753::Fr,
    mnt4753::Fq as Fs,
}, curves::{
    mnt4753::MNT4 as PairingCurve,
    mnt6753::{G1Projective, G1Affine},
}, bytes::{FromBytes, ToBytes},
              AffineCurve, ProjectiveCurve, UniformRand,
};

use primitives::{
    signature::{
        FieldBasedSignatureScheme,
        schnorr::field_based_schnorr::{
            FieldBasedSchnorrSignature, FieldBasedSchnorrSignatureScheme
        },
    },
    crh::{
        FieldBasedHash, MNT4PoseidonHash as FrHash,
    },
};

use proof_systems::groth16::{Proof, verifier::verify_proof, prepare_verifying_key, VerifyingKey};

use rand::rngs::OsRng;
use std::fs::File;


mod ginger_calls;

//Sig types
type SchnorrSig = FieldBasedSchnorrSignature<Fr>;
type SchnorrSigScheme = FieldBasedSchnorrSignatureScheme<Fr, G1Projective, FrHash>;


// ************CONSTANTS******************

const FR_SIZE: usize = 96;
const FS_SIZE: usize = FR_SIZE; // 96
const G1_SIZE: usize = 193;
const G2_SIZE: usize = 385;

const HASH_SIZE:        usize = FR_SIZE;                // 96
const SIG_SIZE:         usize = 2 * FR_SIZE;            // 192
const GROTH_PROOF_SIZE: usize = 2 * G1_SIZE + G2_SIZE;  // 771

// ***********UTILITY FUNCTIONS*************

/// Reads a raw Fr from a [u8; FR_SIZE].
fn read_fr(from: &[u8; FR_SIZE]) -> Option<Fr> {
    match Fr::read(&from[..]) {
        Ok(f) => Some(f),
        Err(_) => None,
    }
}

/// Reads a raw Fs from a [u8; FS_SIZE].
fn read_fs(from: &[u8; FS_SIZE]) -> Option<Fs> {
    match Fs::read(&from[..]) {
        Ok(f) => Some(f),
        Err(_) => None,
    }
}

/// Reads as many FrReprs as FR_SIZE-byte chunks contained in `from`
/// TODO: Probably there is a smarter way to pass a vector of field elements
fn read_frs_from_slice(from: &[u8]) -> Option<Vec<Fr>> {
    let mut fes = vec![];
    for chunk in from.chunks(FR_SIZE) {

        //Pad to reach expected field's number of bytes
        let mut chunk = chunk.to_vec();
        let len = chunk.len();
        for _ in len..FR_SIZE {
            chunk.push(0u8);
        }

        //Read Fr
        let mut const_chunk = [0u8; FR_SIZE];
        chunk.write(&mut const_chunk[..]).expect("Should be able to write fe bytes into a slice");
        match read_fr(&const_chunk) {
            Some(fe) => fes.push(fe),
            None => return None,
        };
    }
    Some(fes)
}

/// Reads as many G1 Affine points as G1_SIZE-byte chunks contained in `from`
/// TODO: Probably there is a smarter way to pass a vector of curve points
fn read_points_from_slice(from: &[u8]) -> Option<Vec<G1Affine>>
{
    let mut points = vec![];
    for chunk in from.chunks(G1_SIZE) {

        //Pad to reach expected point's number of bytes
        let mut chunk = chunk.to_vec();
        let len = chunk.len();
        for _ in len..G1_SIZE {
            chunk.push(0u8);
        }

        //Read Fr
        match G1Affine::read(chunk.as_slice()) {
            Ok(p) => points.push(p),
            Err(_) => return None,
        };
    }
    Some(points)
}

fn read_vk(vk_path: &str) -> VerifyingKey<PairingCurve>
{
    // Load vk from file
    let mut vk_fs = File::open(vk_path)
        .expect("couldn't load vk file");

    VerifyingKey::<PairingCurve>::read(&mut vk_fs)
        .expect("couldn't deserialize vk file")
}

use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jbyteArray, jboolean};
use jni::sys::{JNI_TRUE, JNI_FALSE};

#[no_mangle]
pub extern "system" fn Java_com_horizen_snarknative_SnarkProof_nativeVerify(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _key_path: JString,
    _message: jbyteArray,
    _proof: jbyteArray
) -> jboolean {

    let vkp = _env.get_string(_key_path)
        .expect("Verification key path is invalid.");
    let verification_key_path = vkp.to_str()
        .expect("Verification key path is invalid.");

    //Load Vk
    let vk = read_vk(verification_key_path);
    let pvk = prepare_verifying_key(&vk);

    //Read public inputs
    let public_inputs_raw = _env.convert_byte_array(_message)
        .expect("Message is invalid.");
    let public_inputs = match read_frs_from_slice(&public_inputs_raw) {
        Some(public_inputs) => public_inputs,
        None => return JNI_FALSE,
    };

    // Deserialize the proof
    let zkp_raw = _env.convert_byte_array(_proof)
        .expect("Proof is invalid.");
    let zkp = match Proof::<PairingCurve>::read(&(unsafe { &*zkp_raw })[..]) {
        Ok(zkp) => zkp,
        Err(_) => return JNI_FALSE,
    };

    // Verify the proof
    match verify_proof(&pvk, &zkp, &public_inputs) {
        // No error, and proof verification successful
        Ok(true) => JNI_TRUE,
        // Any other case
        _ => JNI_FALSE,
    }
}

//S

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrKeyGenerator_nativeGenerate(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _skResult: jbyteArray,
    _pkResult: jbyteArray,
) -> jboolean
{

    let sk_result: &mut [u8; FS_SIZE] = &mut [0; FS_SIZE];
    let pk_result: &mut [u8; G1_SIZE] = &mut [0; G1_SIZE];

    //Generate a random (pk, sk) pair
    let mut rng = OsRng::default();
    let (pk, sk) = SchnorrSigScheme::keygen(&mut rng);

    // Write out the pk in affine coordinates
    if (pk.into_affine().write(&mut (unsafe { &mut *pk_result })[..]).is_err()) {
        _env.throw(("java/lang/Exception", "Exception during public key generation."));
        return  JNI_FALSE
    }


    //Write out the sk
    if (sk.write(&mut (unsafe { &mut *sk_result })[..]).is_err()) {
        _env.throw(("java/lang/Exception", "Exception during public key generation."));
        return  JNI_FALSE
    }

    if (_env.set_byte_array_region(_skResult, 0, unsafe{ slice::from_raw_parts(sk_result.as_ptr() as *const i8, sk_result.len()) }).is_err()) {
        _env.throw(("java/lang/Exception", "Exception during write secret key."));
        return  JNI_FALSE
    }

    if (_env.set_byte_array_region(_pkResult, 0, unsafe{ slice::from_raw_parts(pk_result.as_ptr() as *const i8, pk_result.len()) }).is_err()) {
        _env.throw(("java/lang/Exception", "Exception during write public key."));
        return  JNI_FALSE
    }

    JNI_TRUE

}

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrPublicKey_nativeVerifyKey(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _pk: jbyteArray,
) -> jboolean
{

    //Read pk
    let pk_raw = match _env.convert_byte_array(_pk) {
        Ok(pk_raw) => pk_raw,
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Key is invalid."));
            return JNI_FALSE
        },
    };
    let pk = match G1Affine::read(&(unsafe { &*pk_raw })[..]) {

        Ok(pk) => pk.into_projective(),
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Key is invalid."));
            return JNI_FALSE
        },
    };

    if SchnorrSigScheme::keyverify(&pk) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrSecretKey_nativeSignMessage(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _publicKey: jbyteArray,
    _secretKey: jbyteArray,
    _message: jbyteArray
) -> jbyteArray {

    //Read sk
    let sk_raw = match _env.convert_byte_array(_secretKey) {
        Ok(sk_raw) => sk_raw,
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Secret key is invalid."));
            return _env.new_byte_array(0).unwrap()
        },
    };
    let sk = match Fs::read(unsafe { &*sk_raw }) {
        Ok(sk) => sk,
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Secret key is invalid."));
            return _env.new_byte_array(0).unwrap()
        },
    };

    //Read pk
    let pk_raw = match _env.convert_byte_array(_publicKey) {
        Ok(pk_raw) => pk_raw,
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Public key is invalid."));
            return _env.new_byte_array(0).unwrap()
        },
    };
    let pk = match G1Affine::read(&(unsafe { &*pk_raw })[..]) {
        Ok(pk) => pk.into_projective(),
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Public key is invalid."));
            return _env.new_byte_array(0).unwrap()
        },
    };

    //Read message as an array of Fr elements
    let message = match _env.convert_byte_array(_message) {
        Ok(message) => message,
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Message is invalid."));
            return _env.new_byte_array(0).unwrap()
        },
    };
    let fes = match read_frs_from_slice(&message) {
        Some(fes) => fes,
        None => { _env.throw(("java/lang/IllegalArgumentException", "Message is invalid."));
            return _env.new_byte_array(0).unwrap()
        },
    };

    //Sign message
    let mut rng = OsRng::default();
    let sig = match SchnorrSigScheme::sign(&mut rng, &pk, &sk, fes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => { _env.throw(("java/lang/Exception", "Error during proof creation."));
            return _env.new_byte_array(0).unwrap()
        },
    };

    // Write out signature
    let result: &mut [u8; SIG_SIZE] = &mut [0; SIG_SIZE];
    if (sig.write(&mut (unsafe { &mut *result })[..])).is_err() {
        _env.throw(("java/lang/Exception", "Cannot write proof."));
        return _env.new_byte_array(0).unwrap()
    }

    match _env.byte_array_from_slice(result.as_ref()) {
        Ok(result) => result,
        Err(_) => { _env.throw(("java/lang/Exception", "Cannot write proof.")) ;
            return _env.new_byte_array(0).unwrap()
        },
    }
}


#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrPublicKey_nativeVerifySignature(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _key: jbyteArray,
    _message: jbyteArray,
    _signature: jbyteArray
) -> jboolean {

    //Read pk
    let pk_raw = match _env.convert_byte_array(_key) {
        Ok(pk_raw) => pk_raw,
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Key is invalid."));
            return JNI_FALSE
        },
    };
    let pk = match G1Affine::read(&(unsafe { &*pk_raw })[..]) {
        Ok(pk) => pk.into_projective(),
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Key is invalid."));
            return JNI_FALSE
        },
    };

    //Read message as an array of Fr elements
    let message = match _env.convert_byte_array(_message) {
        Ok(message) => message,
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Message is invalid."));
            return JNI_FALSE
        },
    };
    let fes = match read_frs_from_slice(&message) {
        Some(fes) => fes,
        None => { _env.throw(("java/lang/IllegalArgumentException", "Message is invalid."));
            return JNI_FALSE
        },
    };

    //Read signature
    let signature_raw = match _env.convert_byte_array(_signature) {
        Ok(signature_raw) => signature_raw,
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Signature is invalid."));
            return JNI_FALSE
        },
    };

    //Read sig
    let sig = match SchnorrSig::read(&(unsafe { &*signature_raw })[..]) {
        Ok(sig) => sig,
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Signature is invalid."));
            return JNI_FALSE
        },
    };


    match SchnorrSigScheme::verify(&pk, fes.as_slice(), &sig) {
        Ok(result) => if result {
                JNI_TRUE
            } else {
                JNI_FALSE
            },
        Err(_) => return JNI_FALSE,
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_poseidonnative_PoseidonHash_nativeComputeHash(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _input: jbyteArray,
) -> jbyteArray
{
    //Read message as an array of Fr elements
    let input_raw = match _env.convert_byte_array(_input) {
        Ok(input_raw) => input_raw,
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Input is invalid."));
            return return _env.new_byte_array(0).unwrap()
        },
    };
    let fes = match read_frs_from_slice(&input_raw) {
        Some(fes) => fes,
        None => { _env.throw(("java/lang/IllegalArgumentException", "Input is invalid."));
            return return _env.new_byte_array(0).unwrap()
        },
    };

    //Compute hash
    let hash = match FrHash::evaluate(fes.as_slice()) {
        Ok(hash) => hash,
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Input is invalid."));
            return return _env.new_byte_array(0).unwrap()
        },
    };

    // Write out hash
    let result: &mut [u8; HASH_SIZE] = &mut [0; HASH_SIZE];
    if (hash.write(&mut (unsafe { &mut *result })[..])).is_err() {
        _env.throw(("java/lang/Exception", "Cannot write hash."));
        return _env.new_byte_array(0).unwrap()
    }

    match _env.byte_array_from_slice(result.as_ref()) {
        Ok(result) => result,
        Err(_) => { _env.throw(("java/lang/Exception", "Cannot write hash.")) ;
            return _env.new_byte_array(0).unwrap()
        },
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_poseidonnative_PoseidonHash_nativeComputeKeysHashCommitment(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _pks: jbyteArray,
) -> jbyteArray
{
    //Read message as an array of Fr elements
    let pks_raw = match _env.convert_byte_array(_pks) {
        Ok(pks_raw) => pks_raw,
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Pks is invalid."));
            return return _env.new_byte_array(0).unwrap()
        },
    };

    let pks_x = match read_points_from_slice(&pks_raw) {
        Some(pks) => pks.iter().map(|pk| pk.x).collect::<Vec<_>>(),
        None => { _env.throw(("java/lang/IllegalArgumentException", "Pks is invalid."));
            return return _env.new_byte_array(0).unwrap()
        },
    };

    //Compute hash
    let hash = match FrHash::evaluate(pks_x.as_slice()) {
        Ok(hash) => hash,
        Err(_) => return { _env.throw(("java/lang/IllegalArgumentException", "Pks is invalid."));
            return return _env.new_byte_array(0).unwrap()
        },
    };

    // Write out hash
    let result: &mut [u8; HASH_SIZE] = &mut [0; HASH_SIZE];
    if (hash.write(&mut (unsafe { &mut *result })[..])).is_err() {
        _env.throw(("java/lang/Exception", "Cannot write hash commitment."));
        return _env.new_byte_array(0).unwrap()
    }

    match _env.byte_array_from_slice(result.as_ref()) {
        Ok(result) => result,
        Err(_) => { _env.throw(("java/lang/Exception", "Cannot write hash commitment.")) ;
            return _env.new_byte_array(0).unwrap()
        },
    }
}

use primitives::{
    vrf::{
        FieldBasedVrf,
        ecvrf::{
            FieldBasedEcVrf, FieldBasedEcVrfProof,
        }
    },
    crh::bowe_hopwood::{BoweHopwoodPedersenCRH, BoweHopwoodPedersenParameters},
};

use demo_circuit::constants::{
    VRFParams, VRFWindow,
};

use lazy_static::*;

use std::slice;
use std::panic;

lazy_static! {
    pub static ref VRF_GH_PARAMS: BoweHopwoodPedersenParameters<G1Projective> = {
        let params = VRFParams::new();
        BoweHopwoodPedersenParameters::<G1Projective>{generators: params.group_hash_generators}
    };
}

//Hash types
type GroupHash = BoweHopwoodPedersenCRH<G1Projective, VRFWindow>;


//Vrf types
type EcVrfProof = FieldBasedEcVrfProof<Fr, G1Projective>;
type EcVrfScheme = FieldBasedEcVrf<Fr, G1Projective, FrHash, GroupHash>;


const VRF_PROOF_SIZE:   usize = G1_SIZE + 2 * FR_SIZE;  // 385
const VRF_OUTPUT_SIZE:  usize = HASH_SIZE;              // 96

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFKeyGenerator_nativeGenerate(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _skResult: jbyteArray,
    _pkResult: jbyteArray,
) -> jboolean
{

    let sk_result: &mut [u8; FS_SIZE] = &mut [0; FS_SIZE];
    let pk_result: &mut [u8; G1_SIZE] = &mut [0; G1_SIZE];

    //Generate a random (pk, sk) pair
    let mut rng = OsRng::default();
    let (pk, sk) = EcVrfScheme::keygen(&mut rng);

    // Write out the pk in affine coordinates
    if (pk.into_affine().write(&mut (unsafe { &mut *pk_result })[..]).is_err()) {
        _env.throw(("java/lang/Exception", "Exception during public key generation."));
        return  JNI_FALSE
    }


    //Write out the sk
    if (sk.write(&mut (unsafe { &mut *sk_result })[..]).is_err()) {
        _env.throw(("java/lang/Exception", "Exception during public key generation."));
        return  JNI_FALSE
    }

    if (_env.set_byte_array_region(_skResult, 0, unsafe{ slice::from_raw_parts(sk_result.as_ptr() as *const i8, sk_result.len()) }).is_err()) {
        _env.throw(("java/lang/Exception", "Exception during write secret key."));
        return  JNI_FALSE
    }

    if (_env.set_byte_array_region(_pkResult, 0, unsafe{ slice::from_raw_parts(pk_result.as_ptr() as *const i8, pk_result.len()) }).is_err()) {
        _env.throw(("java/lang/Exception", "Exception during write public key."));
        return  JNI_FALSE
    }

    JNI_TRUE

}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFPublicKey_nativeVerifyKey(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _pk: jbyteArray,
) -> jboolean
{

    //Read pk
    let pk_raw = match _env.convert_byte_array(_pk) {
        Ok(pk_raw) => pk_raw,
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Key is invalid."));
            return JNI_FALSE
        },
    };
    let pk = match G1Affine::read(&(unsafe { &*pk_raw })[..]) {

        Ok(pk) => pk.into_projective(),
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Key is invalid."));
            return JNI_FALSE
        },
    };

    if EcVrfScheme::keyverify(&pk) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFSecretKey_nativeVRFHash(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _message: jbyteArray,
    _pk: jbyteArray,
    _proof: jbyteArray
) -> jbyteArray
{
    //Read pk
    let pk_raw = match _env.convert_byte_array(_pk) {
        Ok(pk_raw) => pk_raw,
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Key is invalid."));
            return _env.new_byte_array(0).unwrap()
        },
    };
    let pk = match G1Affine::read(&(unsafe { &*pk_raw })[..]) {
        Ok(pk) => pk.into_projective(),
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Key is invalid."));
            return _env.new_byte_array(0).unwrap()
        },
    };

    //Read message as an array of Fr elements
    let message = match _env.convert_byte_array(_message) {
        Ok(message) => message,
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Message is invalid."));
            return _env.new_byte_array(0).unwrap()
        },
    };
    let fes = match read_frs_from_slice(&message) {
        Some(fes) => fes,
        None => { _env.throw(("java/lang/IllegalArgumentException", "Message is invalid."));
            return _env.new_byte_array(0).unwrap()
        },
    };

    //Read proof
    let proof_raw = match _env.convert_byte_array(_proof) {
        Ok(proof_raw) => proof_raw,
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Proof is invalid."));
            return _env.new_byte_array(0).unwrap()
        },
    };
    let proof = match EcVrfProof::read(&(unsafe { &*proof_raw })[..]) {
        Ok(proof) => proof,
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Proof is invalid."));
            return _env.new_byte_array(0).unwrap()
        },
    };

    //Verify proof
    let vrf_out = match EcVrfScheme::proof_to_hash(&VRF_GH_PARAMS, &pk, fes.as_slice(), &proof) {
        Ok(result) => result,
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Proof verification failed."));
            return _env.new_byte_array(0).unwrap()
        },
    };

    //Write out VRF output
    let result: &mut [u8; VRF_PROOF_SIZE] = &mut [0; VRF_PROOF_SIZE];
    if (vrf_out.write(&mut (unsafe { &mut *result })[..]).is_err()) {
        _env.throw(("java/lang/Exception", "Cannot write result hash."));
        return _env.new_byte_array(0).unwrap()
    }

    match _env.byte_array_from_slice(result.as_ref()) {
        Ok(result) => result,
        Err(_) => { _env.throw(("java/lang/Exception", "Cannot write result hash.")) ;
            return _env.new_byte_array(0).unwrap()
        },
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFPublicKey_nativeVerify(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _key: jbyteArray,
    _message: jbyteArray,
    _proof: jbyteArray
) -> jboolean {

    //Read pk
    let pk_raw = match _env.convert_byte_array(_key) {
        Ok(pk_raw) => pk_raw,
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Key is invalid."));
            return JNI_FALSE
        },
    };
    let pk = match G1Affine::read(&(unsafe { &*pk_raw })[..]) {
        Ok(pk) => pk.into_projective(),
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Key is invalid."));
            return JNI_FALSE
        },
    };

    //Read message as an array of Fr elements
    let message = match _env.convert_byte_array(_message) {
        Ok(message) => message,
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Message is invalid."));
            return JNI_FALSE
        },
    };
    let fes = match read_frs_from_slice(&message) {
        Some(fes) => fes,
        None => { _env.throw(("java/lang/IllegalArgumentException", "Message is invalid."));
            return JNI_FALSE
        },
    };

    //Read proof
    let proof_raw = match _env.convert_byte_array(_proof) {
        Ok(proof_raw) => proof_raw,
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Proof is invalid."));
            return JNI_FALSE
        },
    };
    let proof = match EcVrfProof::read(&(unsafe { &*proof_raw })[..]) {
        Ok(proof) => proof,
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Proof is invalid."));
            return JNI_FALSE
        },
    };

    //Verify proof
    match EcVrfScheme::proof_to_hash(&VRF_GH_PARAMS, &pk, fes.as_slice(), &proof) {
        Ok(_) => JNI_TRUE,
        Err(_) => JNI_FALSE,
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFSecretKey_nativeProve(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _publicKey: jbyteArray,
    _secretKey: jbyteArray,
    _message: jbyteArray
) -> jbyteArray {

    //Read sk
    let sk_raw = match _env.convert_byte_array(_secretKey) {
        Ok(sk_raw) => sk_raw,
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Secret key is invalid."));
            return _env.new_byte_array(0).unwrap()
        },
    };
    let sk = match Fs::read(unsafe { &*sk_raw }) {
        Ok(sk) => sk,
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Secret key is invalid."));
            return _env.new_byte_array(0).unwrap()
        },
    };

    //Read pk
    let pk_raw = match _env.convert_byte_array(_publicKey) {
        Ok(pk_raw) => pk_raw,
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Public key is invalid."));
            return _env.new_byte_array(0).unwrap()
        },
    };
    let pk = match G1Affine::read(&(unsafe { &*pk_raw })[..]) {
        Ok(pk) => pk.into_projective(),
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Public key is invalid."));
            return _env.new_byte_array(0).unwrap()
        },
    };

    //Read message as an array of Fr elements
    let message = match _env.convert_byte_array(_message) {
        Ok(message) => message,
        Err(_) => { _env.throw(("java/lang/IllegalArgumentException", "Message is invalid."));
            return _env.new_byte_array(0).unwrap()
        },
    };
    let fes = match read_frs_from_slice(&message) {
        Some(fes) => fes,
        None => { _env.throw(("java/lang/IllegalArgumentException", "Message is invalid."));
            return _env.new_byte_array(0).unwrap()
        },
    };

    //Create proof for message
    let mut rng = OsRng::default();
    let proof = match EcVrfScheme::prove(&mut rng, &VRF_GH_PARAMS, &pk, &sk, fes.as_slice()) {
        Ok(proof) => proof,
        Err(_) => { _env.throw(("java/lang/Exception", "Error during proof creation."));
            return _env.new_byte_array(0).unwrap()
        },
    };

    // Write out signature
    let result: &mut [u8; VRF_PROOF_SIZE] = &mut [0; VRF_PROOF_SIZE];
    if (proof.write(&mut (unsafe { &mut *result })[..])).is_err() {
        _env.throw(("java/lang/Exception", "Cannot write proof."));
        return _env.new_byte_array(0).unwrap()
    }

    match _env.byte_array_from_slice(result.as_ref()) {
        Ok(result) => result,
        Err(_) => { _env.throw(("java/lang/Exception", "Cannot write proof.")) ;
            return _env.new_byte_array(0).unwrap()
        },
    }
}


