#define HEADER_SM2_SIGN_AND_VERIFY
#pragma once
#include <string.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/hmac.h>
#include "sm2_cipher_error_codes.h"

typedef struct sm2_sig_structure {
	unsigned char r_coordinate[32];
	unsigned char s_coordinate[32];
} SM2_SIGNATURE_STRUCT;

int num2ascii(int num, char* ch)
{
	/*[0,15]的整数转换成ASCII*/
	/*0->48*/
	/*a(10)->97*/
	if (0 <= num && num < 10) {
		*ch = (char)(num + 48);
	}
	else if (10 <= num && num < 16) {
		*ch = (char)(num + 87);
	}
	return 1;
}

int hex2str(unsigned char* num, char* str, unsigned int len)
{
	/*unsigned char数组一个元素一个字节，两个十六进制*/
	/*str长度是num两倍*/
	for (int i = 0; i < len; i++) {
		num2ascii((int)(num[i] >> 4), &str[2 * i]);	//ascii
		num2ascii((int)(num[i] % 16), &str[2 * i + 1]);
	}
	return 1;
}

int generate_k_rand(BIGNUM* bn_k, const BIGNUM* q, const unsigned char* msg,
	unsigned int msg_len, const unsigned char* pri_key)
{
	/*RFC6979  generate a random number [1,q-1]*/
	/*使用SM3作为哈希函数*/
	//EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	unsigned char h1[32];
	unsigned int h1_len;
	/*h1 = H（m）*/
	EVP_Digest(msg, msg_len, h1, &h1_len, EVP_sm3(), NULL);

	/*V = 0x01 0x01 0x01 ... 0x01*/
	unsigned char V[32];
	unsigned int V_len = 32;
	memset(V, 0x01, V_len);
	/*K = 0x00 0x00 0x00 ... 0x00*/
	unsigned char K[32];
	unsigned int K_len = 32;
	memset(K, 0x00, K_len);

	/*K = HMAC_K（V || 0x00 || int2octets（x）|| bits2octets（h1））*/
	HMAC_CTX* ctx = HMAC_CTX_new();
	HMAC_CTX_reset(ctx);
	HMAC_Init_ex(ctx, K, 32, EVP_sm3(), NULL);
	HMAC_Update(ctx, V, 32);
	unsigned char zero[1] = { 0x00 };
	HMAC_Update(ctx, zero, 1);
	/*Octet String is unsigned char[]*/
	HMAC_Update(ctx, pri_key, 32);
	HMAC_Update(ctx, h1, h1_len);
	HMAC_Final(ctx, K, &K_len);
	HMAC_CTX_free(ctx);

	/*V = HMAC_K（V）*/
	HMAC(EVP_sm3(), K, K_len, V, V_len, V, &V_len);

	/*K = HMAC_K（V || 0x01 || int2octets（x）|| bits2octets（h1））*/
	ctx = HMAC_CTX_new();
	HMAC_CTX_reset(ctx);
	HMAC_Init_ex(ctx, K, 32, EVP_sm3(), NULL);
	HMAC_Update(ctx, V, 32);
	unsigned char one[1] = { 0x01 };
	HMAC_Update(ctx, one, 1);
	/*Octet String is unsigned char[]*/
	HMAC_Update(ctx, pri_key, 32);
	HMAC_Update(ctx, h1, h1_len);
	HMAC_Final(ctx, K, &K_len);
	HMAC_CTX_free(ctx);

	/*V = HMAC_K（V）*/
	HMAC(EVP_sm3(), K, K_len, V, V_len, V, &V_len);

	/*set T to the empty sequence*/
	/*While tlen < qlen, do the following:*/
	/*Here we qlen=256bits, only one loop*/
	unsigned char T[32];
	unsigned int T_len;
	for (;;) {
		HMAC(EVP_sm3(), K, K_len, V, V_len, V, &V_len);
		memcpy(T, V, V_len);
		T_len = V_len;
		BIGNUM* k = BN_new();
		BN_bin2bn(T, T_len, k);

		/*check if the value of k is within the [1,q-1] range*/
		BIGNUM* BIGNUM_zero = BN_new();
		BN_set_word(BIGNUM_zero, 0);
		if (BN_cmp(k, BIGNUM_zero) == 1 && BN_cmp(k, q) == -1) {
			/*0 < k < q*/
			BN_copy(bn_k, k);
			return 1;
		}
		char* pR = BN_bn2dec(k);
		printf("%s \n", pR);
		unsigned char V_0x00[33];
		memcpy(V_0x00, V, 32);
		V_0x00[32] = 0x00;
		HMAC(EVP_sm3(), K, 32, V_0x00, 33, K, &K_len);
		HMAC(EVP_sm3(), K, 32, V, 32, V, &V_len);
	}
	return 0;
}

/**************************************************
    * Name: sm3_digest_z
    * Function: compute digest of leading Z in SM3 preprocess
    * Parameters:
        id[in]       user id
        id_len[in]   user id length, size in bytes
        pub_key[in]  SM2 public key
        digest[out]  digest value on Z
    * Return value:
        0:                function executes successfully
        any other value:  an error occurs
    * Notes:
    1. The user id value cannot be NULL. If the specific
       value is unknown, the default user id "1234567812345678"
       can be used.
    2. "pub_key" is a octet string of 65 byte length. It
       is a concatenation of 04 || X || Y. X and Y both are
       SM2 public key coordinates of 32-byte length.
    **************************************************/
int sm3_digest_z(const unsigned char* id,
    const int id_len,
    const unsigned char* pub_key,
    unsigned char* z_digest)
{
    int id_bit_len = id_len * 8;
    unsigned char entl[2];
    unsigned char sm2_param_a[32] = { 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff,
                                     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                     0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc };
    unsigned char sm2_param_b[32] = { 0x28, 0xe9, 0xfa, 0x9e, 0x9d, 0x9f, 0x5e, 0x34,
                                 0x4d, 0x5a, 0x9e, 0x4b, 0xcf, 0x65, 0x09, 0xa7,
                     0xf3, 0x97, 0x89, 0xf5, 0x15, 0xab, 0x8f, 0x92,
                     0xdd, 0xbc, 0xbd, 0x41, 0x4d, 0x94, 0x0e, 0x93 };
    unsigned char sm2_param_x_G[32] = { 0x32, 0xc4, 0xae, 0x2c, 0x1f, 0x19, 0x81, 0x19,
                                   0x5f, 0x99, 0x04, 0x46, 0x6a, 0x39, 0xc9, 0x94,
                       0x8f, 0xe3, 0x0b, 0xbf, 0xf2, 0x66, 0x0b, 0xe1,
                       0x71, 0x5a, 0x45, 0x89, 0x33, 0x4c, 0x74, 0xc7 };
    unsigned char sm2_param_y_G[32] = { 0xbc, 0x37, 0x36, 0xa2, 0xf4, 0xf6, 0x77, 0x9c,
                                   0x59, 0xbd, 0xce, 0xe3, 0x6b, 0x69, 0x21, 0x53,
                       0xd0, 0xa9, 0x87, 0x7c, 0xc6, 0x2a, 0x47, 0x40,
                       0x02, 0xdf, 0x32, 0xe5, 0x21, 0x39, 0xf0, 0xa0 };
    unsigned char x_coordinate[32];
    unsigned char y_coordinate[32];
    EVP_MD_CTX* md_ctx;
    const EVP_MD* md;

    if (!(id) || !(pub_key) || !(z_digest))
    {
        return INVALID_NULL_VALUE_INPUT;
    }

    if ((id_bit_len <= 0) || (id_bit_len > 65535))
    {
        return INVALID_INPUT_LENGTH;
    }

    entl[0] = (id_bit_len & 0xff00) >> 8;
    entl[1] = id_bit_len & 0xff;
    memcpy(x_coordinate, (pub_key + 1), sizeof(x_coordinate));
    memcpy(y_coordinate, (pub_key + 1 + sizeof(x_coordinate)), sizeof(y_coordinate));

    md = EVP_sm3();
    if (!(md_ctx = EVP_MD_CTX_new()))
    {
#ifdef _DEBUG
        printf("Allocate a digest context failed at %s, line %d!\n", __FILE__, __LINE__);
#endif
        return COMPUTE_SM3_DIGEST_FAIL;
    }
    EVP_DigestInit_ex(md_ctx, md, NULL);
    EVP_DigestUpdate(md_ctx, entl, sizeof(entl));
    EVP_DigestUpdate(md_ctx, id, id_len);
    EVP_DigestUpdate(md_ctx, sm2_param_a, sizeof(sm2_param_a));
    EVP_DigestUpdate(md_ctx, sm2_param_b, sizeof(sm2_param_b));
    EVP_DigestUpdate(md_ctx, sm2_param_x_G, sizeof(sm2_param_x_G));
    EVP_DigestUpdate(md_ctx, sm2_param_y_G, sizeof(sm2_param_y_G));
    EVP_DigestUpdate(md_ctx, x_coordinate, sizeof(x_coordinate));
    EVP_DigestUpdate(md_ctx, y_coordinate, sizeof(y_coordinate));
    EVP_DigestFinal_ex(md_ctx, z_digest, NULL);
    EVP_MD_CTX_free(md_ctx);
    return 0;
}

/**************************************************
    * Name: sm3_digest_with_preprocess
    * Function: compute SM3 digest with preprocess
    * Parameters:
        message[in]      input message
        message_len[in]  input message length, size in bytes
        id[in]           user id
        id_len[in]       user id length, size in bytes
        pub_key[in]      SM2 public key
        digest[out]      digest value of SM3 preprocess
    * Return value:
        0:                function executes successfully
        any other value:  an error occurs
    * Notes:
    1. The user id value cannot be NULL. If the specific
       value is unknown, the default user id "1234567812345678"
       can be used.
    2. "pub_key" is a octet string of 65 byte length. It
       is a concatenation of 04 || X || Y. X and Y both are
       SM2 public key coordinates of 32-byte length.
    **************************************************/
int sm3_digest_with_preprocess(const unsigned char* message,
    const int message_len,
    const unsigned char* id,
    const int id_len,
    const unsigned char* pub_key,
    unsigned char* digest)
{
    int error_code;
    unsigned char z_digest[32];
    EVP_MD_CTX* md_ctx;
    const EVP_MD* md;

    if (error_code = sm3_digest_z(id,
        id_len,
        pub_key,
        z_digest))
    {
#ifdef _DEBUG
        printf("Compute SM3 digest of leading data Z failed at %s, line %d!\n", __FILE__, __LINE__);
#endif
        return COMPUTE_SM3_DIGEST_FAIL;
    }

    md = EVP_sm3();
    if (!(md_ctx = EVP_MD_CTX_new()))
    {
#ifdef _DEBUG
        printf("Allocate a digest context failed at %s, line %d!\n", __FILE__, __LINE__);
#endif
        return COMPUTE_SM3_DIGEST_FAIL;
    }
    EVP_DigestInit_ex(md_ctx, md, NULL);
    EVP_DigestUpdate(md_ctx, z_digest, sizeof(z_digest));
    EVP_DigestUpdate(md_ctx, message, message_len);
    EVP_DigestFinal_ex(md_ctx, digest, NULL);
    EVP_MD_CTX_free(md_ctx);
    return 0;
}

/**************************************************
* Name: sm2_sign_data
* Function: compute SM2 signature
* Parameters:
    message[in]      input message
    message_len[in]  input message length, size in bytes
    id[in]           user id
    id_len[in]       user id length, size in bytes
    pub_key[in]      SM2 public key
    pri_key[in]      SM2 private key
    sm2_sig[out]     SM2 signature
* Return value:
    0:                function executes successfully
    any other value:  an error occurs
* Notes:
1. The user id value cannot be NULL. If the specific
   value is unknown, the default user id "1234567812345678"
   can be used.
2. "pub_key" is a octet string of 65 byte length. It
   is a concatenation of 04 || X || Y. X and Y both are
   SM2 public key coordinates of 32-byte length.
3. "pri_key" is a octet string of 32 byte length.
**************************************************/
int sm2_sign_data(const unsigned char* message,
	const int message_len,
	const unsigned char* id,
	const int id_len,
	const unsigned char* pub_key,
	const unsigned char* pri_key,
	SM2_SIGNATURE_STRUCT* sm2_sig)
{
	int error_code;
	unsigned char digest[32];
	BN_CTX* ctx = NULL;
	BIGNUM* bn_e = NULL, * bn_k = NULL, * bn_x = NULL, * bn_tmp = NULL;
	BIGNUM* bn_r = NULL, * bn_s = NULL, * bn_one = NULL, * bn_d = NULL;
	BIGNUM* bn_sum_inv = NULL, * bn_dif = NULL;
	const BIGNUM* bn_order;
	EC_GROUP* group = NULL;
	const EC_POINT* generator;
	EC_POINT* k_G = NULL;

	if (error_code = sm3_digest_with_preprocess(message,
		message_len,
		id,
		id_len,
		pub_key,
		digest))
	{
		return error_code;
	}

	error_code = ALLOCATION_MEMORY_FAIL;
	if (!(ctx = BN_CTX_secure_new()))
	{
		goto clean_up;
	}
	BN_CTX_start(ctx);
	bn_one = BN_CTX_get(ctx);
	bn_e = BN_CTX_get(ctx);
	bn_k = BN_CTX_get(ctx);
	bn_x = BN_CTX_get(ctx);
	bn_tmp = BN_CTX_get(ctx);
	bn_r = BN_CTX_get(ctx);
	bn_s = BN_CTX_get(ctx);
	bn_d = BN_CTX_get(ctx);
	bn_sum_inv = BN_CTX_get(ctx);
	bn_dif = BN_CTX_get(ctx);
	if (!(bn_dif))
	{
		goto clean_up;
	}
	if (!(group = EC_GROUP_new_by_curve_name(NID_sm2)))
	{
		goto clean_up;
	}

	if (!(k_G = EC_POINT_new(group)))
	{
		goto clean_up;
	}

	error_code = COMPUTE_SM2_SIGNATURE_FAIL;
	if (!(BN_one(bn_one)))
	{
		goto clean_up;
	}

	if (!(BN_bin2bn(pri_key, 32, bn_d)))
	{
		goto clean_up;
	}

	if (!(BN_bin2bn(digest, sizeof(digest), bn_e)))
	{
		goto clean_up;
	}
	if (!(bn_order = EC_GROUP_get0_order(group)))
	{
		goto clean_up;
	}
	if (!(generator = EC_GROUP_get0_generator(group)))
	{
		goto clean_up;
	}

	do
	{
		/*impl sm2 with RFC6979*/
		if (!(generate_k_rand(bn_k, bn_order, message, message_len, pri_key)))
		{
			printf("failure!");
			goto clean_up;
		}
		if (BN_is_zero(bn_k))
		{
			continue;
		}
		if (!(EC_POINT_mul(group, k_G, bn_k, NULL, NULL, ctx)))
		{
			goto clean_up;
		}
		if (!(EC_POINT_get_affine_coordinates_GFp(group,
			k_G,
			bn_x,
			bn_tmp,
			ctx)))
		{
			goto clean_up;
		}
		if (!(BN_mod_add(bn_r, bn_e, bn_x, bn_order, ctx)))
		{
			goto clean_up;
		}
		if (BN_is_zero(bn_r)) /* check if r==0 ? */
		{
			continue;
		}
		if (!(BN_add(bn_tmp, bn_r, bn_k)))
		{
			goto clean_up;
		}
		if (!(BN_cmp(bn_tmp, bn_order)))  /* check if (r + k) == n ? */
		{
			continue;
		}
		if (!(BN_add(bn_tmp, bn_one, bn_d)))  /* compute (1 + d) */
		{
			goto clean_up;
		}
		if (!(BN_mod_inverse(bn_sum_inv, bn_tmp, bn_order, ctx)))
		{
			goto clean_up;
		}
		if (!(BN_mul(bn_tmp, bn_r, bn_d, ctx)))
		{
			goto clean_up;
		}
		if (!(BN_mod_sub(bn_dif, bn_k, bn_tmp, bn_order, ctx)))
		{
			goto clean_up;
		}
		if (!(BN_mod_mul(bn_s, bn_sum_inv, bn_dif, bn_order, ctx)))
		{
			goto clean_up;
		}
	} while (BN_is_zero(bn_s));  /* check if s == 0 ? */

	if (BN_bn2binpad(bn_r,
		sm2_sig->r_coordinate,
		sizeof(sm2_sig->r_coordinate)) != sizeof(sm2_sig->r_coordinate))
	{
		goto clean_up;
	}
	if (BN_bn2binpad(bn_s,
		sm2_sig->s_coordinate,
		sizeof(sm2_sig->s_coordinate)) != sizeof(sm2_sig->s_coordinate))
	{
		goto clean_up;
	}
	error_code = 0;

clean_up:
	if (ctx)
	{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	if (group)
	{
		EC_GROUP_free(group);
	}
	if (k_G)
	{
		EC_POINT_free(k_G);
	}

	return error_code;
}

int sm2_verify_sig(const unsigned char* message,
	const int message_len,
	const unsigned char* id,
	const int id_len,
	const unsigned char* pub_key,
	SM2_SIGNATURE_STRUCT* sm2_sig)
{
	int error_code;
	unsigned char digest[32];
	unsigned char pub_key_x[32], pub_key_y[32];
	BN_CTX* ctx = NULL;
	BIGNUM* bn_e = NULL, * bn_r = NULL, * bn_s = NULL, * bn_t = NULL;
	BIGNUM* bn_pub_key_x = NULL, * bn_pub_key_y = NULL;
	BIGNUM* bn_x = NULL, * bn_y = NULL, * bn_R = NULL;
	const BIGNUM* bn_order;
	EC_GROUP* group = NULL;
	const EC_POINT* generator;
	EC_POINT* ec_pub_key_pt = NULL, * ec_pt1 = NULL, * ec_pt2 = NULL;

	if (error_code = sm3_digest_with_preprocess(message,
		message_len,
		id,
		id_len,
		pub_key,
		digest))
	{
		return error_code;
	}

	memcpy(pub_key_x, (pub_key + 1), sizeof(pub_key_x));
	memcpy(pub_key_y, (pub_key + 1 + sizeof(pub_key_x)), sizeof(pub_key_y));

	error_code = ALLOCATION_MEMORY_FAIL;
	if (!(ctx = BN_CTX_new()))
	{
		goto clean_up;
	}
	BN_CTX_start(ctx);
	bn_e = BN_CTX_get(ctx);
	bn_r = BN_CTX_get(ctx);
	bn_s = BN_CTX_get(ctx);
	bn_t = BN_CTX_get(ctx);
	bn_pub_key_x = BN_CTX_get(ctx);
	bn_pub_key_y = BN_CTX_get(ctx);
	bn_x = BN_CTX_get(ctx);
	bn_y = BN_CTX_get(ctx);
	bn_R = BN_CTX_get(ctx);
	if (!(bn_R))
	{
		goto clean_up;
	}
	if (!(group = EC_GROUP_new_by_curve_name(NID_sm2)))
	{
		goto clean_up;
	}

	if (!(ec_pub_key_pt = EC_POINT_new(group)))
	{
		goto clean_up;
	}
	if (!(ec_pt1 = EC_POINT_new(group)))
	{
		goto clean_up;
	}
	if (!(ec_pt2 = EC_POINT_new(group)))
	{
		goto clean_up;
	}

	error_code = VERIFY_SM2_SIGNATURE_FAIL;
	if (!(BN_bin2bn(digest, sizeof(digest), bn_e)))
	{
		goto clean_up;
	}
	if (!(BN_bin2bn(sm2_sig->r_coordinate, sizeof(sm2_sig->r_coordinate), bn_r)))
	{
		goto clean_up;
	}
	if (!(BN_bin2bn(sm2_sig->s_coordinate, sizeof(sm2_sig->s_coordinate), bn_s)))
	{
		goto clean_up;
	}
	if (!(BN_bin2bn(pub_key_x, sizeof(pub_key_x), bn_pub_key_x)))
	{
		goto clean_up;
	}
	if (!(BN_bin2bn(pub_key_y, sizeof(pub_key_y), bn_pub_key_y)))
	{
		goto clean_up;
	}

	if (!(bn_order = EC_GROUP_get0_order(group)))
	{
		goto clean_up;
	}
	if (!(generator = EC_GROUP_get0_generator(group)))
	{
		goto clean_up;
	}

	if ((BN_is_zero(bn_r)) || (BN_cmp(bn_r, bn_order) != (-1)))
	{
		error_code = INVALID_SM2_SIGNATURE;
		goto clean_up;
	}
	if ((BN_is_zero(bn_s)) || (BN_cmp(bn_s, bn_order) != (-1)))
	{
		error_code = INVALID_SM2_SIGNATURE;
		goto clean_up;
	}

	if (!(BN_mod_add(bn_t, bn_r, bn_s, bn_order, ctx)))
	{
		goto clean_up;
	}
	if (BN_is_zero(bn_t))
	{
		goto clean_up;
	}

	if (!(EC_POINT_mul(group, ec_pt1, bn_s, NULL, NULL, ctx)))
	{
		goto clean_up;
	}

	if (!(EC_POINT_set_affine_coordinates_GFp(group,
		ec_pub_key_pt,
		bn_pub_key_x,
		bn_pub_key_y,
		ctx)))
	{
		goto clean_up;
	}

	if (!(EC_POINT_mul(group, ec_pt2, NULL, ec_pub_key_pt, bn_t, ctx)))
	{
		goto clean_up;
	}

	if (!(EC_POINT_add(group, ec_pt1, ec_pt1, ec_pt2, ctx)))
	{
		goto clean_up;
	}

	if (!(EC_POINT_get_affine_coordinates_GFp(group,
		ec_pt1,
		bn_x,
		bn_y,
		ctx)))
	{
		goto clean_up;
	}
	if (!(BN_mod_add(bn_R, bn_e, bn_x, bn_order, ctx)))
	{
		goto clean_up;
	}

	if (!(BN_cmp(bn_r, bn_R))) /* verify signature succeed */
	{
		error_code = 0;
	}

clean_up:
	if (ctx)
	{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	if (group)
	{
		EC_GROUP_free(group);
	}

	if (ec_pub_key_pt)
	{
		EC_POINT_free(ec_pub_key_pt);
	}
	if (ec_pt1)
	{
		EC_POINT_free(ec_pt1);
	}
	if (ec_pt2)
	{
		EC_POINT_free(ec_pt2);
	}

	return error_code;
}