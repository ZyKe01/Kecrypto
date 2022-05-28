#pragma once
#include <string.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

int hash2point(const unsigned char* msg, const unsigned int msg_len, EC_GROUP* group, EC_POINT* point)
{
	unsigned char output[32];
	unsigned int output_len;
	BIGNUM* coordinate_x = BN_new();
	EVP_Digest(msg, msg_len, output, &output_len, EVP_sm3(), NULL);
	BN_bin2bn(output, output_len, coordinate_x);
	
	while (!EC_POINT_set_compressed_coordinates(group, point, coordinate_x, 1, NULL)) {
		BIGNUM* one = BN_new();
		BN_one(one);
		//try and increment
		BN_add(coordinate_x, coordinate_x, one);
	}

	return 1;
}

/*哈希集合中第一个元素*/
int MultiSet_Hash(EC_GROUP* group, EC_POINT* point, const unsigned char* msg, const unsigned int msg_len)
{
	if (hash2point(msg, msg_len, group, point)) {
		printf("Hash success!\n");
		return 1;
	}
	return 0;
}

/*哈希集合中新的元素*/
int MultiSet_Hash_Update(EC_GROUP* group, EC_POINT* point, const unsigned char* msg, const unsigned int msg_len)
{
	EC_POINT* new_point = EC_POINT_new(group);
	if (hash2point(msg, msg_len, group, new_point)) {
		printf("Hash success!\n");
		EC_POINT_add(group, point, point, new_point, NULL);
		return 1;
	}
	return 0;
}

/*去除集合中元素*/
int MultiSet_Hash_Remove(EC_GROUP* group, EC_POINT* point, const unsigned char* msg, const unsigned int msg_len)
{
	EC_POINT* new_point = EC_POINT_new(group);
	if (hash2point(msg, msg_len, group, new_point)) {
		printf("Hash success!\n");
		EC_POINT_invert(group, new_point, NULL);
		EC_POINT_add(group, point, point, new_point, NULL);
		return 1;
	}
	return 0;
}

int print_point(EC_GROUP* group, EC_POINT* point)
{
	BIGNUM* x = BN_new();
	BIGNUM* y = BN_new();
	if (EC_POINT_get_affine_coordinates(group, point, x, y, NULL)) {
		char* pr = BN_bn2dec(x);
		printf("横坐标: %s\n", pr);
		pr = BN_bn2dec(y);
		printf("纵坐标: %s\n", pr);
	}
	return 1;
}

int MultiSet_Hash_Example()
{
	EC_GROUP* group = NULL;
	EC_POINT* point = NULL;
	int nid = OBJ_sn2nid("SM2");
	group = EC_GROUP_new_by_curve_name(nid);
	point = EC_POINT_new(group);
	unsigned char a[32];
	unsigned char b[32];
	unsigned char c[32];
	unsigned char d[32];
	memset(a, 0, 32);
	memset(b, 0x3f, 32);
	memset(c, 0xab, 32);
	memset(d, 0xff, 32);

	MultiSet_Hash(group, point, a, 32);
	printf("Hash a\n");
	print_point(group, point);
	MultiSet_Hash_Update(group, point, b, 32);
	printf("Hash a and b\n");
	print_point(group, point);
	MultiSet_Hash_Remove(group, point, b, 32);
	printf("Hash a and b then remove b\n");
	print_point(group, point);
	printf("-----------------------------------------------------------------------------\n");
	
	point = EC_POINT_new(group);
	MultiSet_Hash(group, point, b, 32);
	printf("Hash b\n");
	print_point(group, point);
	MultiSet_Hash_Update(group, point, a, 32);
	printf("Hash b and a\n");
	print_point(group, point);
	return 1;
}