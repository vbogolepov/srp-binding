{
  'targets': [
    {
      'target_name': 'srp',
      'sources': [
        'src/tomcrypt/prngs/yarrow.c',
        'src/tomcrypt/ciphers/aes/aes.c', 'src/tomcrypt/ciphers/anubis.c', 'src/tomcrypt/ciphers/blowfish.c',
        'src/tomcrypt/ciphers/cast5.c', 'src/tomcrypt/ciphers/des.c', 'src/tomcrypt/ciphers/kasumi.c', 'src/tomcrypt/ciphers/khazad.c',
        'src/tomcrypt/ciphers/kseed.c', 'src/tomcrypt/ciphers/multi2.c', 'src/tomcrypt/ciphers/noekeon.c', 'src/tomcrypt/ciphers/rc2.c', 'src/tomcrypt/ciphers/rc5.c',
        'src/tomcrypt/ciphers/rc6.c', 'src/tomcrypt/ciphers/safer/safer.c', 'src/tomcrypt/ciphers/safer/saferp.c', 'src/tomcrypt/ciphers/skipjack.c',
        'src/tomcrypt/ciphers/twofish/twofish.c', 'src/tomcrypt/ciphers/xtea.c', 'src/tomcrypt/encauth/ccm/ccm_memory.c',
        'src/tomcrypt/encauth/eax/eax_addheader.c',
        'src/tomcrypt/encauth/eax/eax_decrypt.c', 'src/tomcrypt/encauth/eax/eax_decrypt_verify_memory.c', 'src/tomcrypt/encauth/eax/eax_done.c',
        'src/tomcrypt/encauth/eax/eax_encrypt_authenticate_memory.c', 'src/tomcrypt/encauth/eax/eax_encrypt.c',
        'src/tomcrypt/encauth/eax/eax_init.c','src/tomcrypt/encauth/gcm/gcm_add_aad.c',
        'src/tomcrypt/encauth/gcm/gcm_add_iv.c', 'src/tomcrypt/encauth/gcm/gcm_done.c', 'src/tomcrypt/encauth/gcm/gcm_gf_mult.c',
        'src/tomcrypt/encauth/gcm/gcm_init.c', 'src/tomcrypt/encauth/gcm/gcm_memory.c', 'src/tomcrypt/encauth/gcm/gcm_mult_h.c',
        'src/tomcrypt/encauth/gcm/gcm_process.c', 'src/tomcrypt/encauth/gcm/gcm_reset.c',
        'src/tomcrypt/encauth/ocb/ocb_decrypt.c', 'src/tomcrypt/encauth/ocb/ocb_decrypt_verify_memory.c',
        'src/tomcrypt/encauth/ocb/ocb_done_decrypt.c', 'src/tomcrypt/encauth/ocb/ocb_done_encrypt.c',
        'src/tomcrypt/encauth/ocb/ocb_encrypt_authenticate_memory.c', 'src/tomcrypt/encauth/ocb/ocb_encrypt.c',
        'src/tomcrypt/encauth/ocb/ocb_init.c', 'src/tomcrypt/encauth/ocb/ocb_ntz.c', 'src/tomcrypt/encauth/ocb/ocb_shift_xor.c',
        'src/tomcrypt/encauth/ocb/s_ocb_done.c', 'src/tomcrypt/hashes/chc/chc.c',
        'src/tomcrypt/hashes/helper/hash_file.c', 'src/tomcrypt/hashes/helper/hash_filehandle.c', 'src/tomcrypt/hashes/helper/hash_memory.c',
        'src/tomcrypt/hashes/helper/hash_memory_multi.c', 'src/tomcrypt/hashes/md2.c', 'src/tomcrypt/hashes/md4.c', 'src/tomcrypt/hashes/md5.c',
        'src/tomcrypt/hashes/rmd128.c', 'src/tomcrypt/hashes/rmd160.c', 'src/tomcrypt/hashes/rmd256.c', 'src/tomcrypt/hashes/rmd320.c', 'src/tomcrypt/hashes/sha1.c',
        'src/tomcrypt/hashes/sha2/sha256.c', 'src/tomcrypt/hashes/sha2/sha384.c', 'src/tomcrypt/hashes/sha2/sha512.c', 'src/tomcrypt/hashes/tiger.c', 'src/tomcrypt/hashes/whirl/whirl.c',
        'src/tomcrypt/mac/f9/f9_done.c', 'src/tomcrypt/mac/f9/f9_file.c', 'src/tomcrypt/mac/f9/f9_init.c', 'src/tomcrypt/mac/f9/f9_memory.c',
        'src/tomcrypt/mac/f9/f9_memory_multi.c', 'src/tomcrypt/mac/f9/f9_process.c','src/tomcrypt/mac/hmac/hmac_done.c',
        'src/tomcrypt/mac/hmac/hmac_file.c', 'src/tomcrypt/mac/hmac/hmac_init.c', 'src/tomcrypt/mac/hmac/hmac_memory.c',
        'src/tomcrypt/mac/hmac/hmac_memory_multi.c', 'src/tomcrypt/mac/hmac/hmac_process.c',
        'src/tomcrypt/mac/omac/omac_done.c', 'src/tomcrypt/mac/omac/omac_file.c', 'src/tomcrypt/mac/omac/omac_init.c', 'src/tomcrypt/mac/omac/omac_memory.c',
        'src/tomcrypt/mac/omac/omac_memory_multi.c', 'src/tomcrypt/mac/omac/omac_process.c',
        'src/tomcrypt/mac/pelican/pelican.c', 'src/tomcrypt/mac/pelican/pelican_memory.c',
        'src/tomcrypt/mac/pmac/pmac_done.c', 'src/tomcrypt/mac/pmac/pmac_file.c', 'src/tomcrypt/mac/pmac/pmac_init.c', 'src/tomcrypt/mac/pmac/pmac_memory.c',
        'src/tomcrypt/mac/pmac/pmac_memory_multi.c', 'src/tomcrypt/mac/pmac/pmac_ntz.c', 'src/tomcrypt/mac/pmac/pmac_process.c',
        'src/tomcrypt/mac/pmac/pmac_shift_xor.c', 'src/tomcrypt/mac/xcbc/xcbc_done.c',
        'src/tomcrypt/mac/xcbc/xcbc_file.c', 'src/tomcrypt/mac/xcbc/xcbc_init.c', 'src/tomcrypt/mac/xcbc/xcbc_memory.c',
        'src/tomcrypt/mac/xcbc/xcbc_memory_multi.c', 'src/tomcrypt/mac/xcbc/xcbc_process.c',
        'src/tomcrypt/math/fp/ltc_ecc_fp_mulmod.c', 'src/tomcrypt/math/gmp_desc.c', 'src/tomcrypt/math/ltm_desc.c', 'src/tomcrypt/math/multi.c',
        'src/tomcrypt/math/rand_prime.c', 'src/tomcrypt/math/tfm_desc.c', 'src/tomcrypt/misc/base64/base64_decode.c',
        'src/tomcrypt/misc/base64/base64_encode.c', 'src/tomcrypt/misc/burn_stack.c', 'src/tomcrypt/misc/crypt/crypt_argchk.c',
        'src/tomcrypt/misc/crypt/crypt.c', 'src/tomcrypt/misc/crypt/crypt_cipher_descriptor.c', 'src/tomcrypt/misc/crypt/crypt_cipher_is_valid.c',
        'src/tomcrypt/misc/crypt/crypt_find_cipher_any.c',
        'src/tomcrypt/misc/crypt/crypt_find_cipher.c', 'src/tomcrypt/misc/crypt/crypt_find_cipher_id.c',
        'src/tomcrypt/misc/crypt/crypt_find_hash_any.c', 'src/tomcrypt/misc/crypt/crypt_find_hash.c',
        'src/tomcrypt/misc/crypt/crypt_find_hash_id.c', 'src/tomcrypt/misc/crypt/crypt_find_hash_oid.c',
        'src/tomcrypt/misc/crypt/crypt_find_prng.c', 'src/tomcrypt/misc/crypt/crypt_fsa.c', 'src/tomcrypt/misc/crypt/crypt_hash_descriptor.c',
        'src/tomcrypt/misc/crypt/crypt_hash_is_valid.c',
        'src/tomcrypt/misc/crypt/crypt_ltc_mp_descriptor.c', 'src/tomcrypt/misc/crypt/crypt_prng_descriptor.c',
        'src/tomcrypt/misc/crypt/crypt_prng_is_valid.c', 'src/tomcrypt/misc/crypt/crypt_register_cipher.c',
        'src/tomcrypt/misc/crypt/crypt_register_hash.c', 'src/tomcrypt/misc/crypt/crypt_register_prng.c',
        'src/tomcrypt/misc/crypt/crypt_unregister_cipher.c', 'src/tomcrypt/misc/crypt/crypt_unregister_hash.c',
        'src/tomcrypt/misc/crypt/crypt_unregister_prng.c', 'src/tomcrypt/misc/error_to_string.c', 'src/tomcrypt/misc/hkdf/hkdf.c',
        'src/tomcrypt/misc/pkcs5/pkcs_5_1.c', 'src/tomcrypt/misc/pkcs5/pkcs_5_2.c',
        'src/tomcrypt/misc/zeromem.c', 'src/tomcrypt/modes/cbc/cbc_decrypt.c',
        'src/tomcrypt/modes/cbc/cbc_done.c', 'src/tomcrypt/modes/cbc/cbc_encrypt.c', 'src/tomcrypt/modes/cbc/cbc_getiv.c',
        'src/tomcrypt/modes/cbc/cbc_setiv.c', 'src/tomcrypt/modes/cbc/cbc_start.c', 'src/tomcrypt/modes/cfb/cfb_decrypt.c',
        'src/tomcrypt/modes/cfb/cfb_done.c', 'src/tomcrypt/modes/cfb/cfb_encrypt.c', 'src/tomcrypt/modes/cfb/cfb_getiv.c',
        'src/tomcrypt/modes/cfb/cfb_setiv.c', 'src/tomcrypt/modes/cfb/cfb_start.c', 'src/tomcrypt/modes/ctr/ctr_decrypt.c',
        'src/tomcrypt/modes/ctr/ctr_done.c', 'src/tomcrypt/modes/ctr/ctr_encrypt.c', 'src/tomcrypt/modes/ctr/ctr_getiv.c',
        'src/tomcrypt/modes/ctr/ctr_setiv.c', 'src/tomcrypt/modes/ctr/ctr_start.c',
        'src/tomcrypt/modes/ecb/ecb_decrypt.c', 'src/tomcrypt/modes/ecb/ecb_done.c', 'src/tomcrypt/modes/ecb/ecb_encrypt.c',
        'src/tomcrypt/modes/ecb/ecb_start.c', 'src/tomcrypt/modes/f8/f8_decrypt.c', 'src/tomcrypt/modes/f8/f8_done.c', 'src/tomcrypt/modes/f8/f8_encrypt.c',
        'src/tomcrypt/modes/f8/f8_getiv.c', 'src/tomcrypt/modes/f8/f8_setiv.c', 'src/tomcrypt/modes/f8/f8_start.c',
        'src/tomcrypt/modes/lrw/lrw_decrypt.c', 'src/tomcrypt/modes/lrw/lrw_done.c', 'src/tomcrypt/modes/lrw/lrw_encrypt.c',
        'src/tomcrypt/modes/lrw/lrw_getiv.c', 'src/tomcrypt/modes/lrw/lrw_process.c', 'src/tomcrypt/modes/lrw/lrw_setiv.c',
        'src/tomcrypt/modes/lrw/lrw_start.c', 'src/tomcrypt/modes/ofb/ofb_decrypt.c', 'src/tomcrypt/modes/ofb/ofb_done.c',
        'src/tomcrypt/modes/ofb/ofb_encrypt.c', 'src/tomcrypt/modes/ofb/ofb_getiv.c', 'src/tomcrypt/modes/ofb/ofb_setiv.c',
        'src/tomcrypt/modes/ofb/ofb_start.c', 'src/tomcrypt/modes/xts/xts_decrypt.c', 'src/tomcrypt/modes/xts/xts_done.c',
        'src/tomcrypt/modes/xts/xts_encrypt.c', 'src/tomcrypt/modes/xts/xts_init.c', 'src/tomcrypt/modes/xts/xts_mult_x.c',
        'src/tomcrypt/pk/asn1/der/bit/der_decode_bit_string.c',
        'src/tomcrypt/pk/asn1/der/bit/der_encode_bit_string.c',
        'src/tomcrypt/pk/asn1/der/bit/der_length_bit_string.c',
        'src/tomcrypt/pk/asn1/der/boolean/der_decode_boolean.c', 'src/tomcrypt/pk/asn1/der/boolean/der_encode_boolean.c',
        'src/tomcrypt/pk/asn1/der/boolean/der_length_boolean.c', 'src/tomcrypt/pk/asn1/der/choice/der_decode_choice.c',
        'src/tomcrypt/pk/asn1/der/ia5/der_decode_ia5_string.c', 'src/tomcrypt/pk/asn1/der/ia5/der_encode_ia5_string.c',
        'src/tomcrypt/pk/asn1/der/ia5/der_length_ia5_string.c', 'src/tomcrypt/pk/asn1/der/integer/der_decode_integer.c',
        'src/tomcrypt/pk/asn1/der/integer/der_encode_integer.c', 'src/tomcrypt/pk/asn1/der/integer/der_length_integer.c',
        'src/tomcrypt/pk/asn1/der/object_identifier/der_decode_object_identifier.c',
        'src/tomcrypt/pk/asn1/der/object_identifier/der_encode_object_identifier.c',
        'src/tomcrypt/pk/asn1/der/object_identifier/der_length_object_identifier.c',
        'src/tomcrypt/pk/asn1/der/octet/der_decode_octet_string.c', 'src/tomcrypt/pk/asn1/der/octet/der_encode_octet_string.c',
        'src/tomcrypt/pk/asn1/der/octet/der_length_octet_string.c',
        'src/tomcrypt/pk/asn1/der/printable_string/der_decode_printable_string.c',
        'src/tomcrypt/pk/asn1/der/printable_string/der_encode_printable_string.c',
        'src/tomcrypt/pk/asn1/der/printable_string/der_length_printable_string.c',
        'src/tomcrypt/pk/asn1/der/sequence/der_decode_sequence_ex.c',
        'src/tomcrypt/pk/asn1/der/sequence/der_decode_sequence_flexi.c',
        'src/tomcrypt/pk/asn1/der/sequence/der_decode_sequence_multi.c',
        'src/tomcrypt/pk/asn1/der/sequence/der_encode_sequence_ex.c',
        'src/tomcrypt/pk/asn1/der/sequence/der_encode_sequence_multi.c',
        'src/tomcrypt/pk/asn1/der/sequence/der_length_sequence.c', 'src/tomcrypt/pk/asn1/der/sequence/der_sequence_free.c',
        'src/tomcrypt/pk/asn1/der/set/der_encode_set.c', 'src/tomcrypt/pk/asn1/der/set/der_encode_setof.c',
        'src/tomcrypt/pk/asn1/der/short_integer/der_decode_short_integer.c',
        'src/tomcrypt/pk/asn1/der/short_integer/der_encode_short_integer.c',
        'src/tomcrypt/pk/asn1/der/short_integer/der_length_short_integer.c',
        'src/tomcrypt/pk/asn1/der/utctime/der_decode_utctime.c', 'src/tomcrypt/pk/asn1/der/utctime/der_encode_utctime.c',
        'src/tomcrypt/pk/asn1/der/utctime/der_length_utctime.c', 'src/tomcrypt/pk/asn1/der/utf8/der_decode_utf8_string.c',
        'src/tomcrypt/pk/asn1/der/utf8/der_encode_utf8_string.c', 'src/tomcrypt/pk/asn1/der/utf8/der_length_utf8_string.c',
        'src/tomcrypt/pk/asn1/der/teletex_string/der_length_teletex_string.c', 'src/tomcrypt/pk/asn1/der/teletex_string/der_decode_teletex_string.c',
        'src/tomcrypt/pk/asn1/der/bit/der_encode_raw_bit_string.c', 'src/tomcrypt/pk/asn1/der/bit/der_decode_raw_bit_string.c',
        'src/tomcrypt/pk/asn1/der/sequence/der_decode_subject_public_key_info.c', 'src/tomcrypt/pk/asn1/der/sequence/der_encode_subject_public_key_info.c',
        'src/tomcrypt/math/rand_bn.c',
        'src/tomcrypt/misc/mem_neq.c', 'src/tomcrypt/misc/pk_get_oid.c',
        'src/tomcrypt/pk/dsa/dsa_decrypt_key.c',
        'src/tomcrypt/pk/dsa/dsa_encrypt_key.c', 'src/tomcrypt/pk/dsa/dsa_export.c', 'src/tomcrypt/pk/dsa/dsa_free.c', 'src/tomcrypt/pk/dsa/dsa_import.c',
        'src/tomcrypt/pk/dsa/dsa_make_key.c', 'src/tomcrypt/pk/dsa/dsa_shared_secret.c', 'src/tomcrypt/pk/dsa/dsa_sign_hash.c',
        'src/tomcrypt/pk/dsa/dsa_verify_hash.c', 'src/tomcrypt/pk/dsa/dsa_verify_key.c', 'src/tomcrypt/pk/ecc/ecc_ansi_x963_export.c',
        'src/tomcrypt/pk/ecc/ecc_ansi_x963_import.c', 'src/tomcrypt/pk/ecc/ecc.c', 'src/tomcrypt/pk/ecc/ecc_decrypt_key.c',
        'src/tomcrypt/pk/ecc/ecc_encrypt_key.c', 'src/tomcrypt/pk/ecc/ecc_export.c', 'src/tomcrypt/pk/ecc/ecc_free.c', 'src/tomcrypt/pk/ecc/ecc_get_size.c',
        'src/tomcrypt/pk/ecc/ecc_import.c', 'src/tomcrypt/pk/ecc/ecc_make_key.c', 'src/tomcrypt/pk/ecc/ecc_shared_secret.c',
        'src/tomcrypt/pk/ecc/ecc_sign_hash.c', 'src/tomcrypt/pk/ecc/ecc_sizes.c', 'src/tomcrypt/pk/ecc/ecc_verify_hash.c',
        'src/tomcrypt/pk/ecc/ltc_ecc_is_valid_idx.c', 'src/tomcrypt/pk/ecc/ltc_ecc_map.c', 'src/tomcrypt/pk/ecc/ltc_ecc_mul2add.c',
        'src/tomcrypt/pk/ecc/ltc_ecc_mulmod.c', 'src/tomcrypt/pk/ecc/ltc_ecc_points.c',
        'src/tomcrypt/pk/ecc/ltc_ecc_projective_add_point.c', 'src/tomcrypt/pk/ecc/ltc_ecc_projective_dbl_point.c',
        'src/tomcrypt/pk/katja/katja_decrypt_key.c', 'src/tomcrypt/pk/katja/katja_encrypt_key.c', 'src/tomcrypt/pk/katja/katja_export.c',
        'src/tomcrypt/pk/katja/katja_exptmod.c', 'src/tomcrypt/pk/katja/katja_free.c', 'src/tomcrypt/pk/katja/katja_import.c',
        'src/tomcrypt/pk/katja/katja_make_key.c', 'src/tomcrypt/pk/pkcs1/pkcs_1_i2osp.c', 'src/tomcrypt/pk/pkcs1/pkcs_1_mgf1.c',
        'src/tomcrypt/pk/pkcs1/pkcs_1_oaep_decode.c', 'src/tomcrypt/pk/pkcs1/pkcs_1_oaep_encode.c', 'src/tomcrypt/pk/pkcs1/pkcs_1_os2ip.c',
        'src/tomcrypt/pk/pkcs1/pkcs_1_pss_decode.c', 'src/tomcrypt/pk/pkcs1/pkcs_1_pss_encode.c', 'src/tomcrypt/pk/pkcs1/pkcs_1_v1_5_decode.c',
        'src/tomcrypt/pk/pkcs1/pkcs_1_v1_5_encode.c', 'src/tomcrypt/pk/rsa/rsa_decrypt_key.c', 'src/tomcrypt/pk/rsa/rsa_encrypt_key.c',
        'src/tomcrypt/pk/rsa/rsa_export.c', 'src/tomcrypt/pk/rsa/rsa_exptmod.c', 'src/tomcrypt/pk/rsa/rsa_free.c',
        'src/tomcrypt/pk/rsa/rsa_import.c', 'src/tomcrypt/pk/rsa/rsa_make_key.c', 'src/tomcrypt/pk/rsa/rsa_sign_hash.c',
        'src/tomcrypt/pk/rsa/rsa_verify_hash.c', 'src/tomcrypt/prngs/fortuna.c', 'src/tomcrypt/prngs/rc4.c',
        'src/tomcrypt/prngs/rng_get_bytes.c', 'src/tomcrypt/prngs/rng_make_prng.c', 'src/tomcrypt/prngs/sober128.c', 'src/tomcrypt/prngs/sprng.c',
        'src/tommath/bncore.c',
        'src/tommath/bn_error.c',
        'src/tommath/bn_fast_mp_invmod.c',
        'src/tommath/bn_fast_mp_montgomery_reduce.c',
        'src/tommath/bn_fast_s_mp_mul_digs.c',
        'src/tommath/bn_fast_s_mp_mul_high_digs.c',
        'src/tommath/bn_fast_s_mp_sqr.c',
        'src/tommath/bn_mp_2expt.c',
        'src/tommath/bn_mp_abs.c',
        'src/tommath/bn_mp_add.c',
        'src/tommath/bn_mp_add_d.c',
        'src/tommath/bn_mp_addmod.c',
        'src/tommath/bn_mp_and.c',
        'src/tommath/bn_mp_clamp.c',
        'src/tommath/bn_mp_clear.c',
        'src/tommath/bn_mp_clear_multi.c',
        'src/tommath/bn_mp_cmp.c',
        'src/tommath/bn_mp_cmp_d.c',
        'src/tommath/bn_mp_cmp_mag.c',
        'src/tommath/bn_mp_cnt_lsb.c',
        'src/tommath/bn_mp_copy.c',
        'src/tommath/bn_mp_count_bits.c',
        'src/tommath/bn_mp_div_2.c',
        'src/tommath/bn_mp_div_2d.c',
        'src/tommath/bn_mp_div_3.c',
        'src/tommath/bn_mp_div.c',
        'src/tommath/bn_mp_div_d.c',
        'src/tommath/bn_mp_dr_is_modulus.c',
        'src/tommath/bn_mp_dr_reduce.c',
        'src/tommath/bn_mp_dr_setup.c',
        'src/tommath/bn_mp_exch.c',
        'src/tommath/bn_mp_expt_d.c',
        'src/tommath/bn_mp_exptmod.c',
        'src/tommath/bn_mp_exptmod_fast.c',
        'src/tommath/bn_mp_exteuclid.c',
        'src/tommath/bn_mp_fread.c',
        'src/tommath/bn_mp_fwrite.c',
        'src/tommath/bn_mp_gcd.c',
        'src/tommath/bn_mp_get_int.c',
        'src/tommath/bn_mp_grow.c',
        'src/tommath/bn_mp_init.c',
        'src/tommath/bn_mp_init_copy.c',
        'src/tommath/bn_mp_init_multi.c',
        'src/tommath/bn_mp_init_set.c',
        'src/tommath/bn_mp_init_set_int.c',
        'src/tommath/bn_mp_init_size.c',
        'src/tommath/bn_mp_invmod.c',
        'src/tommath/bn_mp_invmod_slow.c',
        'src/tommath/bn_mp_is_square.c',
        'src/tommath/bn_mp_jacobi.c',
        'src/tommath/bn_mp_karatsuba_mul.c',
        'src/tommath/bn_mp_karatsuba_sqr.c',
        'src/tommath/bn_mp_lcm.c',
        'src/tommath/bn_mp_lshd.c',
        'src/tommath/bn_mp_mod_2d.c',
        'src/tommath/bn_mp_mod.c',
        'src/tommath/bn_mp_mod_d.c',
        'src/tommath/bn_mp_montgomery_calc_normalization.c',
        'src/tommath/bn_mp_montgomery_reduce.c',
        'src/tommath/bn_mp_montgomery_setup.c',
        'src/tommath/bn_mp_mul_2.c',
        'src/tommath/bn_mp_mul_2d.c',
        'src/tommath/bn_mp_mul.c',
        'src/tommath/bn_mp_mul_d.c',
        'src/tommath/bn_mp_mulmod.c',
        'src/tommath/bn_mp_neg.c',
        'src/tommath/bn_mp_n_root.c',
        'src/tommath/bn_mp_or.c',
        'src/tommath/bn_mp_prime_fermat.c',
        'src/tommath/bn_mp_prime_is_divisible.c',
        'src/tommath/bn_mp_prime_is_prime.c',
        'src/tommath/bn_mp_prime_miller_rabin.c',
        'src/tommath/bn_mp_prime_next_prime.c',
        'src/tommath/bn_mp_prime_rabin_miller_trials.c',
        'src/tommath/bn_mp_prime_random_ex.c',
        'src/tommath/bn_mp_radix_size.c',
        'src/tommath/bn_mp_radix_smap.c',
        'src/tommath/bn_mp_rand.c',
        'src/tommath/bn_mp_read_radix.c',
        'src/tommath/bn_mp_read_signed_bin.c',
        'src/tommath/bn_mp_read_unsigned_bin.c',
        'src/tommath/bn_mp_reduce_2k.c',
        'src/tommath/bn_mp_reduce_2k_l.c',
        'src/tommath/bn_mp_reduce_2k_setup.c',
        'src/tommath/bn_mp_reduce_2k_setup_l.c',
        'src/tommath/bn_mp_reduce.c',
        'src/tommath/bn_mp_reduce_is_2k.c',
        'src/tommath/bn_mp_reduce_is_2k_l.c',
        'src/tommath/bn_mp_reduce_setup.c',
        'src/tommath/bn_mp_rshd.c',
        'src/tommath/bn_mp_set.c',
        'src/tommath/bn_mp_set_int.c',
        'src/tommath/bn_mp_shrink.c',
        'src/tommath/bn_mp_signed_bin_size.c',
        'src/tommath/bn_mp_sqr.c',
        'src/tommath/bn_mp_sqrmod.c',
        'src/tommath/bn_mp_sqrt.c',
        'src/tommath/bn_mp_sub.c',
        'src/tommath/bn_mp_sub_d.c',
        'src/tommath/bn_mp_submod.c',
        'src/tommath/bn_mp_toom_mul.c',
        'src/tommath/bn_mp_toom_sqr.c',
        'src/tommath/bn_mp_toradix.c',
        'src/tommath/bn_mp_toradix_n.c',
        'src/tommath/bn_mp_to_signed_bin.c',
        'src/tommath/bn_mp_to_signed_bin_n.c',
        'src/tommath/bn_mp_to_unsigned_bin.c',
        'src/tommath/bn_mp_to_unsigned_bin_n.c',
        'src/tommath/bn_mp_unsigned_bin_size.c',
        'src/tommath/bn_mp_xor.c',
        'src/tommath/bn_mp_zero.c',
        'src/tommath/bn_prime_tab.c',
        'src/tommath/bn_reverse.c',
        'src/tommath/bn_s_mp_add.c',
        'src/tommath/bn_s_mp_exptmod.c',
        'src/tommath/bn_s_mp_mul_digs.c',
        'src/tommath/bn_s_mp_mul_high_digs.c',
        'src/tommath/bn_s_mp_sqr.c',
        'src/tommath/bn_s_mp_sub.c',
        'src/srp/srp.c',
        'src/srp/cstr.c',
        'src/srp/t_conf.c',
        'src/srp/t_conv.c',
        'src/srp/t_math.c',
        'src/srp/t_misc.c',
        'src/srp/t_pw.c',
        'src/srp/t_read.c',
        'src/srp/t_sha.c',
        'src/srp/t_truerand.c',
        'src/srp/srp6_server.c',
        'src/srp/srp6_client.c',
        'src/srp_object.cc',
        'src/srpbinding.cc'
      ],
        "conditions":[
            ["OS=='linux'", {
                "cflags": [" -Wno-pointer-sign -Wno-return-type -Wno-sign-compare -Wno-missing-field-initializers -Wno-unused-value "],
                "defines": [ "SHA1", "TOMCRYPT", "TOMMATH", "HAVE_MEMCPY" ]
            }],
            ["OS=='win'", {
                "cflags": [" -std=c++11 "],
                "defines": [ "STDC_HEADERS", "TOMCRYPT_SHA", "TOMCRYPT", "TOMMATH", "HAVE_MEMCPY" ]
            }]
      ],
      'include_dirs': [".", "./src/srp", "./src/tommath", "./src/tomcrypt/headers", "<!(node -e \"require('nan')\")"]

    }
  ]
}