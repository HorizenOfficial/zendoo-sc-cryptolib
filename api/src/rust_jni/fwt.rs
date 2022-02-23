use cctp_primitives::commitment_tree::hashers::hash_fwt;

use super::*;

pub(crate) fn parse_sc_ft_output(_env: &JNIEnv, _ft_out: JObject) -> Result<FtOutput, Error> {
    // Parse amount
    let amount = parse_long_from_jobject(&_env, _ft_out, "amount") as u64;

    // Parse receiver_pub_key bytes
    let receiver_pub_key = parse_fixed_size_byte_array_from_jobject::<SC_PUBLIC_KEY_LENGTH>(
        &_env,
        _ft_out,
        "receiverPubKey",
    )?;

    // Parse spending_pub_key bytes
    let payback_addr_data_hash = parse_fixed_size_byte_array_from_jobject::<MC_PK_SIZE>(
        &_env,
        _ft_out,
        "paybackAddrDataHash",
    )?;

    // Parse tx hash bytes
    let tx_hash =
        parse_fixed_size_byte_array_from_jobject::<SC_TX_HASH_LENGTH>(&_env, _ft_out, "txHash")?;

    // Parse out_idx
    let out_idx = parse_int_from_jobject(&_env, _ft_out, "outIdx") as u32;

    Ok(
        FtOutput {
            amount,
            receiver_pub_key,
            payback_addr_data_hash,
            tx_hash,
            out_idx,
        }   
    )
}

ffi_export!(
    fn Java_com_horizen_fwtnative_ForwardTransferOutput_nativeGetHash(
        _env: JNIEnv,
        _ft_out: JObject,
    ) -> jobject {

        // Parse sc_ft_output
        let sc_ft_output = ok_or_throw_exc!(
            &_env,
            parse_sc_ft_output(&_env, _ft_out),
            "io/horizen/common/librustsidechains/NativeParsingException",
            "Unable to parse FT output",
            JNI_NULL
        );
        
        // Compute FT hash
        let mut receiver_pub_key = sc_ft_output.receiver_pub_key;
        receiver_pub_key.reverse();

        map_to_jobject_or_throw_exc(
            _env,
            hash_fwt(
                sc_ft_output.amount,
                &receiver_pub_key,
                &sc_ft_output.payback_addr_data_hash,
                &sc_ft_output.tx_hash,
                sc_ft_output.out_idx,
            ),
            "io/horizen/common/librustsidechains/FieldElement",
            "io/horizen/common/librustsidechains/FinalizationException",
            "Unable to compute FT hash"
        )
    }
);
