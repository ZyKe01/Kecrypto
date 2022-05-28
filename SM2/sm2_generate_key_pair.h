#pragma once
#ifndef HEADER_SM2_CREATE_KEY_PAIR_H
#define HEADER_SM2_CREATE_KEY_PAIR_H
#include <string.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "sm2_cipher_error_codes.h"

typedef struct sm2_key_pair_structure {
    /* Private key is a octet string of 32-byte length. */
    unsigned char pri_key[32];
    /* Public key is a octet string of 65 byte length. It is a
       concatenation of 04 || X || Y. X and Y both are SM2 public
       key coordinates of 32-byte length. */
    unsigned char pub_key[65];
    //Uncompress public key: prefix is 04||x||,
} SM2_KEY_PAIR;

#ifdef  __cplusplus
extern "C" {
#endif

    /**************************************************
    * Name: sm2_create_key_pair
    * Function: create SM2 key pair, including private key
        and public key
    * Parameters:
        key_pair[in]  SM2 key pair
    * Return value:
        0:                function executes successfully
        any other value:  an error occurs
    **************************************************/

	int key_pair_free(SM2_KEY_PAIR* key_pair)
	{
		if (key_pair == NULL) {
			printf("key_pair is a null pointer!\n");
			return 0;
		}
		memset(key_pair->pri_key, 0, 32);
		memset(key_pair->pub_key, 0, 65);
		delete key_pair;
		return 1;
	}

	int sm2_generate_key_pair(SM2_KEY_PAIR* key_pair)
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
			if (!(BN_rand_range(bn_d, bn_order)))
			{
				goto clean_up;
			}
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
#ifdef  __cplusplus
}
#endif

#endif  /* end of HEADER_SM2_CREATE_KEY_PAIR_H */