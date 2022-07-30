#pragma once
#include <string.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

#include "sm2_cipher_error_codes.h"
#include "sm2_encrypt_and_decrypt.h"
#include "sm2_generate_key_pair.h"
#include "sm2_sign_and_verify.h"

/*先整一个有漏洞的签名，会泄露k*/
//BN_bin2bn(pri_key, 32, bn_d)
int sm2_sign_data_pitfall(const unsigned char* message,
	const int message_len,
	const unsigned char* id,
	const int id_len,
	const unsigned char* pub_key,
	const unsigned char* pri_key,
	SM2_SIGNATURE_STRUCT* sm2_sig,
	BIGNUM* k)
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
		if (!BN_rand_range(bn_k, bn_order)) {
			goto clean_up;
		}
		/*您猜怎么着？嘿这k让我给泄露啦！*/
		BN_copy(k, bn_k);
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

/*再整一个签名方案，可以传入参数k*/
int sm2_sign_data_setk(const unsigned char* message,
	const int message_len,
	const unsigned char* id,
	const int id_len,
	const unsigned char* pub_key,
	const unsigned char* pri_key,
	SM2_SIGNATURE_STRUCT* sm2_sig,
	BIGNUM* k)
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
		if (!BN_rand_range(bn_k, bn_order)) {
			goto clean_up;
		}
		if (bn_k != NULL) {
			BN_copy(bn_k, k);
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

/*还需要一个sm2密钥生成函数，可以设置d*/
int sm2_generate_key_pair_setd(SM2_KEY_PAIR* key_pair, const BIGNUM* d)
{
	int error_code;
	BN_CTX* ctx = NULL;
	BIGNUM* bn_d = NULL, * bn_x = NULL, * bn_y = NULL;
	const BIGNUM* bn_order;
	EC_GROUP* group = NULL;
	EC_POINT* ec_pt = NULL;
	unsigned char pub_key_x[32], pub_key_y[32];

	error_code = ALLOCATION_MEMORY_FAIL;
	if (!(ctx = BN_CTX_secure_new()))
	{
		goto clean_up;
	}
	BN_CTX_start(ctx);
	bn_d = BN_CTX_get(ctx);
	bn_x = BN_CTX_get(ctx);
	bn_y = BN_CTX_get(ctx);
	if (!(bn_y))
	{
		goto clean_up;
	}

	if (!(group = EC_GROUP_new_by_curve_name(NID_sm2)))
	{
		goto clean_up;
	}
	if (!(bn_order = EC_GROUP_get0_order(group)))
	{
		goto clean_up;
	}
	if (!(ec_pt = EC_POINT_new(group)))
	{
		goto clean_up;
	}

	error_code = CREATE_SM2_KEY_PAIR_FAIL;
	do
	{
		BN_copy(bn_d, d);
	} while (BN_is_zero(bn_d));

	if (!(EC_POINT_mul(group, ec_pt, bn_d, NULL, NULL, ctx)))
	{
		goto clean_up;
	}
	if (!(EC_POINT_get_affine_coordinates_GFp(group,
		ec_pt,
		bn_x,
		bn_y,
		ctx)))
	{
		goto clean_up;
	}

	if (BN_bn2binpad(bn_d,
		key_pair->pri_key,
		sizeof(key_pair->pri_key)) != sizeof(key_pair->pri_key))
	{
		goto clean_up;
	}
	if (BN_bn2binpad(bn_x,
		pub_key_x,
		sizeof(pub_key_x)) != sizeof(pub_key_x))
	{
		goto clean_up;
	}
	if (BN_bn2binpad(bn_y,
		pub_key_y,
		sizeof(pub_key_y)) != sizeof(pub_key_y))
	{
		goto clean_up;
	}

	key_pair->pub_key[0] = 0x4;
	memcpy((key_pair->pub_key + 1), pub_key_x, sizeof(pub_key_x));
	memcpy((key_pair->pub_key + 1 + sizeof(pub_key_x)), pub_key_y, sizeof(pub_key_y));
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

	if (ec_pt)
	{
		EC_POINT_free(ec_pt);
	}

	return error_code;
}

/*Leaking k leads to leaking of d*/
int test_leaking_k()
{
	unsigned char msg[] = { "Look at the stars, look how they shine for you." };
	unsigned int msg_len = (unsigned int)(strlen((char*)msg));
	unsigned char id[] = { "201900460049" };
	unsigned int id_len = (unsigned int)(strlen((char*)id));

	SM2_KEY_PAIR* key_pair = new SM2_KEY_PAIR;
	if (sm2_generate_key_pair(key_pair)) {
		printf("Key generation failed!\n");
	}
	printf("Key generation succeed!\n");

	SM2_SIGNATURE_STRUCT sig;
	BN_CTX* ctx = NULL;
	BIGNUM* k = NULL, * r = NULL, * s = NULL, * d = NULL;
	const BIGNUM* n = NULL;
	BIGNUM* bn_d = NULL;//私钥
	ctx = BN_CTX_new();
	k = BN_CTX_get(ctx);
	r = BN_CTX_get(ctx);
	s = BN_CTX_get(ctx);
	d = BN_CTX_get(ctx);
	n = BN_CTX_get(ctx);
	bn_d = BN_CTX_get(ctx);
	sm2_sign_data_pitfall(msg, msg_len, id, id_len, key_pair->pub_key,
		key_pair->pri_key, &sig, k);

	/*get d!*/
	EC_GROUP* group = NULL;
	group = EC_GROUP_new_by_curve_name(NID_sm2);
	n = EC_GROUP_get0_order(group);
	BN_bin2bn(key_pair->pri_key, 32, bn_d);
	BN_bin2bn(sig.r_coordinate, 32, r);
	BN_bin2bn(sig.s_coordinate, 32, s);
	BN_mod_add(r, s, r, n, ctx);
	BN_mod_inverse(r, r, n, ctx);
	BN_mod_sub(s, k, s, n, ctx);
	BN_mod_mul(d, r, s, n, ctx);
	//printf("%d\n", BN_cmp(d, bn_d));
	if (BN_cmp(d,bn_d) == 0) {
		printf("Success!  We've got the private key!\n");
		return 1;
	}
	printf("Failure!\n");
	//unsigned char a[32];
	//unsigned char b[32];
	//BN_bn2bin(d, a);
	//BN_bn2bin(bn_d, b);
	//for (int i = 0; i < 32; i++)
	//	printf("%02x", a[i]);
	//printf("\n");
	//for (int i = 0; i < 32; i++)
	//	printf("%02x", b[i]);
	return 0;
}

/*Reusing k leads to leaking of d*/
int test_reusing_k()
{
	unsigned char msg1[] = { "Look at the stars, look how they shine for you." };
	unsigned char msg2[] = { "Look at the stars, look how they shine for me." };
	unsigned int msg1_len = (unsigned int)(strlen((char*)msg1));
	unsigned int msg2_len = (unsigned int)(strlen((char*)msg2));
	unsigned char id[] = { "201900460049" };
	unsigned int id_len = (unsigned int)(strlen((char*)id));

	SM2_KEY_PAIR* key_pair = new SM2_KEY_PAIR;
	if (sm2_generate_key_pair(key_pair)) {
		printf("Key generation failed!\n");
	}
	printf("Key generation succeed!\n");

	SM2_SIGNATURE_STRUCT sig1, sig2;
	BN_CTX* ctx = NULL;
	BIGNUM* k = NULL, * r1 = NULL, * r2 = NULL, * s1 = NULL, * s2 = NULL, * d = NULL;
	const BIGNUM* n = NULL;
	BIGNUM* bn_d = NULL;//私钥
	ctx = BN_CTX_new();
	k = BN_CTX_get(ctx);
	r1 = BN_CTX_get(ctx);
	r2 = BN_CTX_get(ctx);
	s1 = BN_CTX_get(ctx);
	s2 = BN_CTX_get(ctx);
	d = BN_CTX_get(ctx);
	n = BN_CTX_get(ctx);
	EC_GROUP* group = NULL;
	group = EC_GROUP_new_by_curve_name(NID_sm2);
	n = EC_GROUP_get0_order(group);
	/*generate random k*/
	BN_rand_range(k, n);

	bn_d = BN_CTX_get(ctx);
	sm2_sign_data_setk(msg1, msg1_len, id, id_len, key_pair->pub_key,
		key_pair->pri_key, &sig1, k);
	sm2_sign_data_setk(msg2, msg2_len, id, id_len, key_pair->pub_key,
		key_pair->pri_key, &sig2, k);

	/*get d!*/
	BN_bin2bn(key_pair->pri_key, 32, bn_d);
	BN_bin2bn(sig1.r_coordinate, 32, r1);
	BN_bin2bn(sig1.s_coordinate, 32, s1);
	BN_bin2bn(sig2.r_coordinate, 32, r2);
	BN_bin2bn(sig2.s_coordinate, 32, s2);

	BIGNUM* tmp = NULL;
	tmp = BN_CTX_get(ctx);
	BN_mod_sub(tmp, s2, s1, n, ctx);
	BN_mod_sub(s1, s1, s2, n, ctx);
	BN_mod_sub(r1, r1, r2, n, ctx);
	BN_mod_add(s1, s1, r1, n, ctx);
	BN_mod_inverse(s1, s1, n, ctx);
	BN_mod_mul(d, tmp, s1, n, ctx);
	if (BN_cmp(d, bn_d) == 0) {
		printf("Success!  We've got the private key!\n");
		return 1;
	}
	printf("Failure!\n");
	return 0;
}

/*Reusing k by different users*/
int test_reusing_k2()
{
	unsigned char msg1[] = { "Look at the stars, look how they shine for you." };
	unsigned char msg2[] = { "Look at the stars, look how they shine for me." };
	unsigned int msg1_len = (unsigned int)(strlen((char*)msg1));
	unsigned int msg2_len = (unsigned int)(strlen((char*)msg2));
	unsigned char id[] = { "201900460049" };
	unsigned int id_len = (unsigned int)(strlen((char*)id));

	SM2_KEY_PAIR* key_pair1 = new SM2_KEY_PAIR;
	SM2_KEY_PAIR* key_pair2 = new SM2_KEY_PAIR;
	if (sm2_generate_key_pair(key_pair1)) {
		printf("Alice key generation failed!\n");
	}
	printf("Alice key generation succeed!\n");
	if (sm2_generate_key_pair(key_pair2)) {
		printf("Bob key generation failed!\n");
	}
	printf("Bob key generation succeed!\n");

	SM2_SIGNATURE_STRUCT sig1, sig2;
	BN_CTX* ctx = NULL;
	BIGNUM* k = NULL, * r1 = NULL, * r2 = NULL, * s1 = NULL, * s2 = NULL, * d1 = NULL, * d2 = NULL;
	const BIGNUM* n = NULL;
	BIGNUM* bn_d1 = NULL, * bn_d2 = NULL;//私钥
	ctx = BN_CTX_new();
	k = BN_CTX_get(ctx);
	r1 = BN_CTX_get(ctx);
	r2 = BN_CTX_get(ctx);
	s1 = BN_CTX_get(ctx);
	s2 = BN_CTX_get(ctx);
	d1 = BN_CTX_get(ctx);
	d2 = BN_CTX_get(ctx);
	n = BN_CTX_get(ctx);
	EC_GROUP* group = NULL;
	group = EC_GROUP_new_by_curve_name(NID_sm2);
	n = EC_GROUP_get0_order(group);
	/*generate random k*/
	BN_rand_range(k, n);

	bn_d1 = BN_CTX_get(ctx);
	bn_d2 = BN_CTX_get(ctx);
	sm2_sign_data_setk(msg1, msg1_len, id, id_len, key_pair1->pub_key,
		key_pair1->pri_key, &sig1, k);
	sm2_sign_data_setk(msg2, msg2_len, id, id_len, key_pair2->pub_key,
		key_pair2->pri_key, &sig2, k);

	/*get d!*/
	BN_bin2bn(key_pair1->pri_key, 32, bn_d1);
	BN_bin2bn(key_pair2->pri_key, 32, bn_d2);
	BN_bin2bn(sig1.r_coordinate, 32, r1);
	BN_bin2bn(sig1.s_coordinate, 32, s1);
	BN_bin2bn(sig2.r_coordinate, 32, r2);
	BN_bin2bn(sig2.s_coordinate, 32, s2);

	BN_mod_add(r2, s2, r2, n, ctx);
	BN_mod_inverse(r2, r2, n, ctx);
	BN_mod_sub(s2, k, s2, n, ctx);
	BN_mod_mul(d2, r2, s2, n, ctx);
	BN_mod_add(r1, s1, r1, n, ctx);
	BN_mod_inverse(r1, r1, n, ctx);
	BN_mod_sub(s1, k, s1, n, ctx);
	BN_mod_mul(d1, r1, s1, n, ctx);

	bool flag = 0;
	if (BN_cmp(d2, bn_d2) == 0) {
		printf("Success!  Alice've got the Bob's private key!\n");
		flag++;
	}
	//printf("Failure!\n");
	if (BN_cmp(d1, bn_d1) == 0) {
		printf("Success!  Bob've got the Alice's private key!\n");
		flag++;
	}
	//printf("Failure!\n");
	if (flag == 2)
		return 1;
	return 0;
}

/*Malleability*/
int test_malleability()
{
	EC_GROUP* group = NULL;
	int nid = NID_X9_62_prime256v1;
	group = EC_GROUP_new_by_curve_name(nid);
	EC_KEY* ECDSA_key = NULL;
	ECDSA_key = EC_KEY_new_by_curve_name(nid);
	if (!EC_KEY_generate_key(ECDSA_key)) {
		printf("ECDSA key generation failed!\n");
		return 0;
	}
	printf("ECDSA key generation succeed!\n");

	unsigned char msg[] = { "Look at the stars, look how they shine for you." };
	unsigned int msg_len = (unsigned int)(strlen((char*)msg));
	ECDSA_SIG* sig = NULL;
	sig = ECDSA_do_sign(msg, msg_len, ECDSA_key);
	printf("Signing succeed!\n");
	const BIGNUM* r_ = NULL, * s_ = NULL;
	const BIGNUM* n = NULL;
	BIGNUM* r = NULL, * s = NULL;
	BN_CTX* ctx = NULL;
	ctx = BN_CTX_new();
	r_ = BN_CTX_get(ctx);
	r = BN_CTX_get(ctx);
	s_ = BN_CTX_get(ctx);
	s = BN_CTX_get(ctx);
	n = BN_CTX_get(ctx);
	n = EC_GROUP_get0_order(group);
	ECDSA_SIG_get0(sig, &r_, &s_);
	BN_copy(r, r_);
	BN_copy(s, s_);
	BN_mod_sub(s, n, s, n, ctx);

	/*signature (r,-s)*/
	ECDSA_SIG* sig1 = NULL;
	sig1 = ECDSA_SIG_new();
	ECDSA_SIG_set0(sig1, r, s);

	if (ECDSA_do_verify(msg, msg_len, sig1, ECDSA_key) != 1) {
		printf("Verifying failed!\n");
		return 0;
	}
	printf("Verifying succeed!\n");
	return 1;
}

/*Same d and k with ECDSA*/
int test_same_with_ECDSA()
{
	unsigned char msg[] = { "Look at the stars, look how they shine for you." };
	unsigned int msg_len = (unsigned int)(strlen((char*)msg));
	unsigned char id[] = { "201900460049" };
	unsigned int id_len = (unsigned int)(strlen((char*)id));
	EC_GROUP* group = NULL;
	//int nid = NID_X9_62_prime256v1;
	//group = EC_GROUP_new_by_curve_name(nid);
	group = EC_GROUP_new_by_curve_name(NID_sm2);	//用SM2的曲线
	EC_KEY* ECDSA_key = NULL;
	ECDSA_key = EC_KEY_new_by_curve_name(NID_sm2);
	if (!EC_KEY_generate_key(ECDSA_key)) {
		printf("ECDSA key generation failed!\n");
		return 0;
	}
	printf("ECDSA key generation succeed!\n");

	BN_CTX* ctx = NULL;
	ctx = BN_CTX_new();
	BIGNUM* k = NULL, * kinv = NULL;
	const BIGNUM* n = NULL, * d = NULL;//d是真实私钥
	k = BN_CTX_get(ctx);
	kinv = BN_CTX_get(ctx);
	n = BN_CTX_get(ctx);
	d = BN_CTX_get(ctx);
	n = EC_GROUP_get0_order(group);
	/*generate random k*/
	BN_rand_range(k, n);
	BN_mod_inverse(kinv, k, n, ctx);

	ECDSA_SIG* sig1 = NULL;
	sig1= ECDSA_do_sign_ex(msg, msg_len, kinv, NULL, ECDSA_key);
	d = EC_KEY_get0_private_key(ECDSA_key);
	SM2_KEY_PAIR* key_pair = new SM2_KEY_PAIR;
	if (sm2_generate_key_pair_setd(key_pair, d)) {
		printf("SM2 key generation failed!\n");
	}
	printf("SM2 key generation succeed!\n");
	SM2_SIGNATURE_STRUCT sig2;
	sm2_sign_data_setk(msg, msg_len, id, id_len, key_pair->pub_key,
		key_pair->pri_key, &sig2, k);

	/*recover the private key d with the two sigs*/
	BIGNUM* s1 = NULL, * r1 = NULL, * s2 = NULL, * r2 = NULL, * res = NULL, * e = NULL;
	const BIGNUM* r_ = NULL, * s_ = NULL;
	s1 = BN_CTX_get(ctx);
	r1 = BN_CTX_get(ctx);
	s_ = BN_CTX_get(ctx);
	r_ = BN_CTX_get(ctx);
	s2 = BN_CTX_get(ctx);
	r2 = BN_CTX_get(ctx);
	e = BN_CTX_get(ctx);
	res = BN_CTX_get(ctx);
	BN_bin2bn(sig2.r_coordinate, 32, r2);
	BN_bin2bn(sig2.s_coordinate, 32, s2);
	ECDSA_SIG_get0(sig1, &r_, &s_);
	BN_copy(r1, r_);
	BN_copy(s1, s_);
	//BN_mod_mul(s2, s1, s2, n, ctx);		//s1s2
	unsigned char md[32];
	SHA256(msg, msg_len, md);
	BN_bin2bn(md, 32, e);
	//BN_mod_sub(e, s2, e, n, ctx);	//s1s2-e
	//BN_mod_mul(r2, s1, r2, n, ctx);	//s1r2
	//BN_mod_sub(r1, r1, s2, n, ctx);
	//BN_mod_sub(r1, r1, r2, n, ctx);
	//BN_mod_inverse(r1, r1, n, ctx);
	//BN_mod_mul(res, e, r1, n, ctx);
	//if (BN_cmp(d, res) == 0) {
	//	printf("Success!  We've got the private key!\n");
	//	return 1;
	//}
	//printf("Failure!\n");
	BIGNUM* a = NULL, * b = NULL, * c = NULL;
	a = BN_CTX_get(ctx);
	b = BN_CTX_get(ctx);
	c = BN_CTX_get(ctx);
	BN_mod_mul(a, d, r1, n, ctx);
	BN_mod_mul(b, k, s1, n, ctx);
	BN_mod_sub(c, b, a, n, ctx);
	printf("%d\n",BN_cmp(e, c));
	unsigned char x[32];
	unsigned char y[32];
	BN_bn2bin(c, x);
	BN_bn2bin(e, y);
	for (int i = 0; i < 32; i++)
		printf("%02x", x[i]);
	printf("\n");
	for (int i = 0; i < 32; i++)
		printf("%02x", y[i]);
	return 0;
}


int test()
{
	unsigned char msg[] = { "Look at the stars, look how they shine for you." };
	unsigned int msg_len = (unsigned int)(strlen((char*)msg));
	unsigned char id[] = { "201900460049" };
	unsigned int id_len = (unsigned int)(strlen((char*)id));
	EC_GROUP* group = NULL;
	int nid = NID_X9_62_prime256v1;
	group = EC_GROUP_new_by_curve_name(nid);
	//group = EC_GROUP_new_by_curve_name(NID_sm2);	//用SM2的曲线
	EC_KEY* ECDSA_key = NULL;
	ECDSA_key = EC_KEY_new_by_curve_name(nid);
	if (!EC_KEY_generate_key(ECDSA_key)) {
		printf("ECDSA key generation failed!\n");
		return 0;
	}
	printf("ECDSA key generation succeed!\n");

	BN_CTX* ctx = NULL;
	ctx = BN_CTX_new();
	BIGNUM* k = NULL, * kinv = NULL;
	const BIGNUM* n = NULL, * d = NULL;//d是真实私钥
	k = BN_CTX_get(ctx);
	kinv = BN_CTX_get(ctx);
	n = BN_CTX_get(ctx);
	d = BN_CTX_get(ctx);
	n = EC_GROUP_get0_order(group);
	/*generate random k*/
	BN_rand_range(k, n);
	BN_mod_inverse(kinv, k, n, ctx);

	ECDSA_SIG* sig1 = NULL;
	sig1 = ECDSA_do_sign_ex(msg, msg_len, kinv, NULL, ECDSA_key);
	if (ECDSA_do_verify(msg, msg_len, sig1, ECDSA_key) != 1) {
		printf("Verifying failed!\n");
		return 0;
	}
	printf("Verifying succeed!\n");
	d = EC_KEY_get0_private_key(ECDSA_key);

	/*recover the private key d with the two sigs*/
	BIGNUM* s1 = NULL, * r1 = NULL, * s2 = NULL, * r2 = NULL, * res = NULL, * e = NULL;
	const BIGNUM* r_ = NULL, * s_ = NULL;
	s1 = BN_CTX_get(ctx);
	r1 = BN_CTX_get(ctx);
	//s_ = BN_CTX_get(ctx);
	//r_ = BN_CTX_get(ctx);
	s2 = BN_CTX_get(ctx);
	r2 = BN_CTX_get(ctx);
	e = BN_CTX_get(ctx);
	res = BN_CTX_get(ctx);
	
	ECDSA_SIG_get0(sig1, &r_, &s_);
	BN_copy(r1, r_);
	BN_copy(s1, s_);
	unsigned char md[32];
	SHA256(msg, msg_len, md);
	BN_bin2bn(md, 32, e);
	BIGNUM* a = NULL, * b = NULL, * c = NULL;
	a = BN_CTX_get(ctx);
	b = BN_CTX_get(ctx);
	c = BN_CTX_get(ctx);
	BN_mod_mul(a, d, r1, n, ctx);
	BN_mod_mul(b, k, s1, n, ctx);
	BN_mod_sub(c, a, b, n, ctx);
	printf("%d\n", BN_cmp(e, c));
	unsigned char x[32];
	unsigned char y[32];
	BN_bn2bin(e, x);
	BN_bn2bin(c, y);
	for (int i = 0; i < 32; i++)
		printf("%02x", x[i]);
	printf("\n");
	for (int i = 0; i < 32; i++)
		printf("%02x", y[i]);
	return 0;
}