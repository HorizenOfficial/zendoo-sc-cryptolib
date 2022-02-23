use demo_circuit::personalizations::BoxType;
use primitives::FieldHasher;

use super::*;

pub(crate) fn parse_sc_utxo_output(_env: &JNIEnv, _utxo_out: JObject) -> Result<UtxoOutput, Error> {
    // Parse spending_pub_key bytes
    let spending_pub_key = parse_fixed_size_byte_array_from_jobject::<SC_PUBLIC_KEY_LENGTH>(
        _env,
        _utxo_out,
        "spendingPubKey",
    )?;

    // Parse amount
    let amount = parse_long_from_jobject(_env, _utxo_out, "amount") as u64;

    // Parse nonce
    let nonce = parse_long_from_jobject(_env, _utxo_out, "nonce") as u64;

    // Parse custom hash bytes
    let custom_hash = parse_fixed_size_byte_array_from_jobject::<SC_CUSTOM_HASH_LENGTH>(
        _env,
        _utxo_out,
        "customHash",
    )?;

    Ok(UtxoOutput {
        spending_pub_key,
        amount,
        nonce,
        custom_hash,
    })
}

ffi_export!(
    fn Java_com_horizen_scutxonative_ScUtxoOutput_nativeGetHash(
        _env: JNIEnv,
        _utxo_out: JObject,
    ) -> jobject 
    {
        // Parse UTXO
        let utxo = ok_or_throw_exc!(
            &_env,
            parse_sc_utxo_output(&_env, _utxo_out),
            "io/horizen/common/librustsidechains/NativeParsingException",
            "Unable to parse SC Utxo output",
            JNI_NULL
        );

        // Compute UTXO hash
        map_to_jobject_or_throw_exc(
            _env,
            utxo.hash(Some(&[FieldElement::from(BoxType::CoinBox as u8)])),
            "io/horizen/common/librustsidechains/FieldElement",
            "io/horizen/common/librustsidechains/FinalizationException",
            "Unable to compute SCUTxo hash"
        )
    }
);