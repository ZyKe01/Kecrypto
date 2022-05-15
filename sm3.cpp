#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")
#define _CRT_SECURE_NO_WARNINGS
#pragma warning (disable: 4996)

#include <iostream>
#include <string.h>  
#include <stdlib.h>  
#include <openssl/evp.h> 
using namespace std;

#ifdef CPU_BIGENDIAN

#define cpu_to_be16(v) (v)
#define cpu_to_be32(v) (v)
#define be16_to_cpu(v) (v)
#define be32_to_cpu(v) (v)

#else

#define cpu_to_le16(v) (v)
#define cpu_to_le32(v) (v)
#define le16_to_cpu(v) (v)
#define le32_to_cpu(v) (v)

#define cpu_to_be16(v) (((v)<< 8) | ((v)>>8))
#define cpu_to_be32(v) (((v)>>24) | (((v)>>8)&0xff00) | (((v)<<8)&0xff0000) | ((v)<<24))
#define be16_to_cpu(v) cpu_to_be16(v)
#define be32_to_cpu(v) cpu_to_be32(v)

#endif
#define SM3_DIGEST_LENGTH	32
#define SM3_BLOCK_SIZE		64
#define SM3_CBLOCK		(SM3_BLOCK_SIZE)
typedef struct {
	uint32_t digest[8];
	int nblocks;
	unsigned char block[64];
	int num;
} sm3_ctx_t;

void sm3_init(sm3_ctx_t* ctx);
void sm3_update(sm3_ctx_t* ctx, const unsigned char* data, size_t data_len);
void sm3_final(sm3_ctx_t* ctx, unsigned char digest[SM3_DIGEST_LENGTH]);
void sm3_compress(uint32_t digest[8], const unsigned char block[SM3_BLOCK_SIZE]);
void sm3(const unsigned char* data, size_t datalen,
	unsigned char digest[SM3_DIGEST_LENGTH]);

void print_str(const unsigned char* str, const unsigned int str_len)
{
	for (int i = 0; i < str_len; i++) {
		printf("%x ", str[i]);
	}
	printf("\n");
}

int birthday(unsigned char* str1, unsigned char* str2, unsigned int length)
{
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	unsigned char x0[34];
	memset(x0, 0x3f, 33);
	x0[33] = 0;
	unsigned int x0_len = strlen((char*)x0);
	//print_str(x0, x0_len);
	printf("消息长度%dbytes\n", x0_len);

	unsigned char x1[34];
	unsigned char x2[34];
	memcpy(x1, x0, x0_len);
	memcpy(x2, x0, x0_len);
	unsigned int x1_len = x0_len;
	unsigned int x2_len = x0_len;
	unsigned long long i = 0;
	for (i;; i++) {
		EVP_Digest(x1, x1_len, x1, &x1_len, EVP_sm3(), NULL);
		x1_len = length;	//只要求前length字节相同

		EVP_Digest(x2, x2_len, x2, &x2_len, EVP_sm3(), NULL);
		x2_len = length;	//只要求前length字节相同
		EVP_Digest(x2, x2_len, x2, &x2_len, EVP_sm3(), NULL);
		x2_len = length;	//只要求前length字节相同

		//print_str(x1, x0_len);
		//print_str(x2, x0_len);
		if (!memcmp(x1, x2, length)) {
			printf("存在%dbytes相同\n", length);
			memcpy(x2, x1, x1_len);
			memcpy(x1, x0, x0_len);
			x2_len = x1_len;
			x1_len = x0_len;
			break;
		}
	}
	printf("共尝试%d次\n", i);
	unsigned char out1[34];
	unsigned char out2[34];
	unsigned int out1_len = length;
	unsigned int out2_len = length;
	for (unsigned long long j = 1; j <= i; j++) {
		EVP_Digest(x1, x1_len, out1, &out1_len, EVP_sm3(), NULL);
		out1_len = length;
		EVP_Digest(x2, x2_len, out2, &out2_len, EVP_sm3(), NULL);
		out2_len = length;
		if (!memcmp(out1, out2, length)) {
			memcpy(str1, x1, x1_len);
			memcpy(str2, x2, x2_len);
			printf("j:%d\n", j);
			return 1;
		}
		memcpy(x1, out1, out1_len);
		memcpy(x2, out2, out2_len);
		x1_len = out1_len;
		x2_len = out2_len;
	}
}



int main(int argc, char* argv[])
{
	int length = 4;
	unsigned char str1[34] = { 0 };
	unsigned char str2[34] = { 0 };

	if (!birthday(str1, str2, length)) {
		return 0;
	}
	print_str(str1, 32);
	print_str(str2, 32);

	unsigned char out1[34];
	unsigned char out2[34];
	unsigned int out1_len;
	unsigned int out2_len;

	EVP_Digest(str1, length, out1, &out1_len, EVP_sm3(), NULL);
	EVP_Digest(str2, length, out2, &out2_len, EVP_sm3(), NULL);
	print_str(out1, out1_len);
	print_str(out2, out2_len);

	sm3(str1, 2, out2);
	print_str(out2, 32);
	return 0;
}


void sm3_init(sm3_ctx_t* ctx)
{
	ctx->digest[0] = 0x7380166F;
	ctx->digest[1] = 0x4914B2B9;
	ctx->digest[2] = 0x172442D7;
	ctx->digest[3] = 0xDA8A0600;
	ctx->digest[4] = 0xA96F30BC;
	ctx->digest[5] = 0x163138AA;
	ctx->digest[6] = 0xE38DEE4D;
	ctx->digest[7] = 0xB0FB0E4E;

	ctx->nblocks = 0;
	ctx->num = 0;
}

void sm3_update(sm3_ctx_t* ctx, const unsigned char* data, size_t data_len)
{
	if (ctx->num) {
		unsigned int left = SM3_BLOCK_SIZE - ctx->num;
		if (data_len < left) {
			memcpy(ctx->block + ctx->num, data, data_len);
			ctx->num += data_len;
			return;
		}
		else {
			memcpy(ctx->block + ctx->num, data, left);
			sm3_compress(ctx->digest, ctx->block);
			ctx->nblocks++;
			data += left;
			data_len -= left;
		}
	}
	while (data_len >= SM3_BLOCK_SIZE) {
		sm3_compress(ctx->digest, data);
		ctx->nblocks++;
		data += SM3_BLOCK_SIZE;
		data_len -= SM3_BLOCK_SIZE;
	}
	ctx->num = data_len;
	if (data_len) {
		memcpy(ctx->block, data, data_len);
	}
}

void sm3_final(sm3_ctx_t* ctx, unsigned char* digest)
{
	int i;
	uint32_t* pdigest = (uint32_t*)digest;
	uint32_t* count = (uint32_t*)(ctx->block + SM3_BLOCK_SIZE - 8);

	ctx->block[ctx->num] = 0x80;

	if (ctx->num + 9 <= SM3_BLOCK_SIZE) {
		memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 9);
	}
	else {
		memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 1);
		sm3_compress(ctx->digest, ctx->block);
		memset(ctx->block, 0, SM3_BLOCK_SIZE - 8);
	}

	count[0] = cpu_to_be32((ctx->nblocks) >> 23);
	count[1] = cpu_to_be32((ctx->nblocks << 9) + (ctx->num << 3));

	sm3_compress(ctx->digest, ctx->block);
	for (i = 0; i < sizeof(ctx->digest) / sizeof(ctx->digest[0]); i++) {
		pdigest[i] = cpu_to_be32(ctx->digest[i]);
	}
}

#define ROTATELEFT(X,n)  (((X)<<(n)) | ((X)>>(32-(n))))

#define P0(x) ((x) ^  ROTATELEFT((x),9)  ^ ROTATELEFT((x),17))
#define P1(x) ((x) ^  ROTATELEFT((x),15) ^ ROTATELEFT((x),23))

#define FF0(x,y,z) ( (x) ^ (y) ^ (z))
#define FF1(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

#define GG0(x,y,z) ( (x) ^ (y) ^ (z))
#define GG1(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )

void sm3_compress(uint32_t digest[8], const unsigned char block[64])
{
	int j;
	uint32_t W[68], W1[64];
	const uint32_t* pblock = (const uint32_t*)block;

	uint32_t A = digest[0];
	uint32_t B = digest[1];
	uint32_t C = digest[2];
	uint32_t D = digest[3];
	uint32_t E = digest[4];
	uint32_t F = digest[5];
	uint32_t G = digest[6];
	uint32_t H = digest[7];
	uint32_t SS1, SS2, TT1, TT2, T[64];

	for (j = 0; j < 16; j++) {
		W[j] = cpu_to_be32(pblock[j]);
	}
	for (j = 16; j < 68; j++) {
		W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTATELEFT(W[j - 3], 15)) ^ ROTATELEFT(W[j - 13], 7) ^ W[j - 6];;
	}
	for (j = 0; j < 64; j++) {
		W1[j] = W[j] ^ W[j + 4];
	}

	for (j = 0; j < 16; j++) {

		T[j] = 0x79CC4519;
		SS1 = ROTATELEFT((ROTATELEFT(A, 12) + E + ROTATELEFT(T[j], j)), 7);
		SS2 = SS1 ^ ROTATELEFT(A, 12);
		TT1 = FF0(A, B, C) + D + SS2 + W1[j];
		TT2 = GG0(E, F, G) + H + SS1 + W[j];
		D = C;
		C = ROTATELEFT(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = ROTATELEFT(F, 19);
		F = E;
		E = P0(TT2);
	}

	for (j = 16; j < 64; j++) {

		T[j] = 0x7A879D8A;
		SS1 = ROTATELEFT((ROTATELEFT(A, 12) + E + ROTATELEFT(T[j], j)), 7);
		SS2 = SS1 ^ ROTATELEFT(A, 12);
		TT1 = FF1(A, B, C) + D + SS2 + W1[j];
		TT2 = GG1(E, F, G) + H + SS1 + W[j];
		D = C;
		C = ROTATELEFT(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = ROTATELEFT(F, 19);
		F = E;
		E = P0(TT2);
	}

	digest[0] ^= A;
	digest[1] ^= B;
	digest[2] ^= C;
	digest[3] ^= D;
	digest[4] ^= E;
	digest[5] ^= F;
	digest[6] ^= G;
	digest[7] ^= H;
}

void sm3(const unsigned char* msg, size_t msglen,
	unsigned char dgst[SM3_DIGEST_LENGTH])
{
	sm3_ctx_t ctx;

	sm3_init(&ctx);
	sm3_update(&ctx, msg, msglen);
	sm3_final(&ctx, dgst);

	memset(&ctx, 0, sizeof(sm3_ctx_t));
}
