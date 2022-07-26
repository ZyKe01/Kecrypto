#pragma once
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/bn.h>



int ECDSA_sign_and_verify(EC_KEY* key, const unsigned char* dgst, unsigned int dgst_len)
{
	ECDSA_SIG* sig = NULL;
	sig = ECDSA_do_sign(dgst, dgst_len, key);
	printf("Signing succeed!\n");

	if (ECDSA_do_verify(dgst, dgst_len, sig, key) != 1) {
		printf("Verifying failed!\n");
		return 0;
	}
	printf("Verifying succeed!\n");
	return 1;
}

int forge_signature(EC_KEY* key, EC_GROUP* group, EC_POINT* P)
{
	BIGNUM* u = NULL, * v = NULL, * r = NULL, * s = NULL, * e = NULL;
	u = BN_new();
	v = BN_new();
	r = BN_new();
	s = BN_new();
	e = BN_new();
	BN_set_word(u, 1);
	BN_set_word(v, 2);
	EC_POINT* R = EC_POINT_new(group);
	//compute R'
	EC_POINT_mul(group, R, u, P, v, NULL);
	//get x'
	BIGNUM* x = NULL, * y = NULL, * n = NULL;
	x = BN_new();
	y = BN_new();
	n = BN_new();
	EC_POINT_get_affine_coordinates(group, R, x, y, NULL);
	BN_CTX* ctx = BN_CTX_new();
	EC_GROUP_get_order(group, n, NULL);
	BN_nnmod(r, x, n, ctx);

	//compute e and s
	BN_mod_inverse(v, v, n, ctx);
	BN_mod_mul(e, r, u, n, ctx);
	BN_mod_mul(e, e, v, n, ctx);
	BN_mod_mul(s, r, v, n, ctx);

	//create signature
	ECDSA_SIG* sig = NULL;
	sig = ECDSA_SIG_new();
	ECDSA_SIG_set0(sig, r, s);
	unsigned char dgst[32];
	unsigned int dgst_len = 32;
	memset(dgst, 0, 32);
	BN_bn2bin(e, dgst);
	
	//verify signature
	if (ECDSA_do_verify(dgst, dgst_len, sig, key) != 1) {
		printf("Verifying failed! You're not Satoshi!\n");
		return 0;
	}
	printf("Verifying succeed! You're Satoshi!\n");
	return 1;
}

int forge_example()
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

	unsigned char dgst[32];
	memset(dgst, 0x3f, 32);
	unsigned int dgst_len = 32;
	printf("Normal ECDSA sign and verify:\n");
	ECDSA_sign_and_verify(ECDSA_key, dgst, dgst_len);

	EC_POINT* P = NULL;
	P = (EC_POINT*)EC_KEY_get0_public_key(ECDSA_key);

	printf("\nForged ECDSA sign and verify:\n");
	forge_signature(ECDSA_key, group, P);
	return 1;
}