#pragma once
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "sm2_encrypt_and_decrypt.h"
#include "sm2_generate_key_pair.h"

int test_sm2_encrypt_and_decrypt()
{
	int error_code;
	SM2_KEY_PAIR key_pair;
	unsigned char c1[65], c3[32];
	unsigned char* c2, * plaintext;

	if (error_code = sm2_generate_key_pair(&key_pair))
	{
		printf("Create SM2 key pair failed!\n");
		return (-1);
	}
	printf("Create SM2 key pair succeeded!\n");

	unsigned char msg[] = { "Hello, world!" };
	int msg_len = (int)(strlen((char*)msg));
	c2 = (unsigned char*)malloc(msg_len);
	if (error_code = sm2_encrypt_data_test(msg, msg_len, key_pair.pub_key, c1, c3, c2))
	{
		printf("Create SM2 ciphertext failed!\n");
		free(c2);
		return error_code;
	}
	printf("Create SM2 ciphertext succeeded!\n");

	plaintext = (unsigned char*)malloc(msg_len);
	if(error_code = sm2_decrypt(c1, c3, c2, msg_len, key_pair.pri_key, plaintext)) {
		free(plaintext);
		free(c2);
		printf("Decrypt SM2 ciphertext failed!\n");
		return error_code;
	}
	printf("Decrypted message:\n");
	printf("%s\n", plaintext);
	for (int i = 0; i < msg_len; i++)
	{
		printf("%x  ", plaintext[i]);
	}
}

/*return the length of output*/
int PGP_Encrypt(const unsigned char* pub_key, const unsigned char* msg,
	unsigned int msg_len, unsigned char* out)
{
	/*generate a random symmetric key*/
	BIGNUM* r = BN_new();
	BIGNUM* range = BN_new();
	unsigned char s[16];
	memset(s, 0xff, 16);
	BN_bin2bn(s, 16, range);
	BN_rand_range(r, range);
	unsigned char key[16];
	BN_bn2bin(r, key);

	/*encrypt data*/
	int cipher_len = msg_len;
	unsigned char* ciphertext = (unsigned char*)malloc(cipher_len);
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (EVP_EncryptInit(ctx, EVP_sm4_ctr(), key, NULL) != 1) {
		printf("Inition failed!\n");
		return 0;
	}
	if (EVP_EncryptUpdate(ctx, ciphertext, &cipher_len, msg, msg_len) != 1) {
		printf("Encryption failed!\n");
		return 0;
	}
	/*padding data*/
	int padlen = 0;
	if (EVP_EncryptFinal(ctx, ciphertext + cipher_len, &padlen) != 1) {
		printf("Fianl failed!\n");
		return 0;
	}
	cipher_len += padlen;
	EVP_CIPHER_CTX_free(ctx);
	
	/*encrypt symmetic key with receiver's public key*/
	unsigned char c1[65], c3[32];
	unsigned char* c2;
	unsigned int c2_len = 16;
	c2 = (unsigned char*)malloc(c2_len);
	sm2_encrypt(key, 16, pub_key, c1, c3, c2);
	
	/*ciphertext and encrypted key*/
	memcpy(out, c1, 65);
	memcpy(out + 65, c3, 32);
	memcpy(out + 65 + 32, c2, c2_len);
	memcpy(out + 65 + 32 + c2_len, ciphertext, cipher_len);
	unsigned int out_len = 65 + 32 + c2_len + cipher_len;
	return out_len;
}

/*return the length of plaintext*/
int PGP_Decrypt(const unsigned char* pri_key, const unsigned char* in,
	unsigned int in_len, unsigned char* plaintext)
{
	unsigned char c1[65], c3[32];
	unsigned char* c2;
	unsigned int c2_len = 16;
	c2 = (unsigned char*)malloc(c2_len);
	int cipher_len = in_len - 65 - 32 - c2_len;
	unsigned char* ciphertext = (unsigned char*)malloc(cipher_len);
	memcpy(c1, in, 65);
	memcpy(c3, in + 65, 32);
	memcpy(c2, in + 65 + 32, c2_len);
	memcpy(ciphertext, in + 65 + 32 + c2_len, cipher_len);

	unsigned char key[16];
	sm2_decrypt(c1, c3, c2, c2_len, pri_key, key);
	int plain_len = cipher_len;
	
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (EVP_DecryptInit(ctx, EVP_sm4_ctr(), key, NULL) != 1) {
		printf("Inition failed!\n");
		return 0;
	}
	if (EVP_DecryptUpdate(ctx, plaintext, &plain_len, ciphertext, cipher_len) != 1) {
		printf("Encryption failed!\n");
		return 0;
	}
	/*padding data*/
	int padlen = 0;
	if (EVP_DecryptFinal(ctx, plaintext + plain_len, &padlen) != 1) {
		printf("Fianl failed!\n");
		return 0;
	}
	plain_len += padlen;
	EVP_CIPHER_CTX_free(ctx);
	return plain_len;
}

int Pretty_good_test()
{
	//test_sm2_encrypt_and_decrypt();
	unsigned char msg[] = { "Hello, world!" };
	unsigned int msg_len = strlen((char*)msg);
	unsigned char out[2048];
	unsigned int out_len = 0;

	SM2_KEY_PAIR key_pair;
	if (sm2_generate_key_pair(&key_pair))
	{
		printf("Create SM2 key pair failed!\n");
		return (-1);
	}
	printf("Create SM2 key pair succeeded!\n");

	/*Encrypt*/
	out_len = PGP_Encrypt(key_pair.pub_key, msg, msg_len, out);
	printf("Encryption secceed!\n");
	printf("The length of output is %d.\n", out_len);
	printf("The encrypted data is\n");
	for (int i = 0; i < out_len; i++) {
		printf("%x", out[i]);
	}

	/*Decrypt*/
	unsigned char* plaintext = (unsigned char*)malloc(msg_len);
	int plain_len = PGP_Decrypt(key_pair.pri_key, out, out_len, plaintext);
	printf("\n\nDecryption secceed!\n");
	printf("The plaintext is\n%s\n",(char*)plaintext);
	return 1;
}