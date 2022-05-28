#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")
#define _CRT_SECURE_NO_WARNINGS
#pragma warning (disable: 4996)
using namespace std;
#include <iostream>
#include <string.h>  
#include <stdlib.h>
#include "sm2_generate_key_pair.h"
#include "sm2_sign_and_verify.h"
#include "sm2_sign_and_verify_example.h"
#include "elliptic_curve_multiset_hash.h"

int main()
{
    if (example()) {
        printf("BBBBBBBBBBBBBBBBBBBBBBBBBBig failure!\n");
    }
    printf("BBBBBBBBBBBBBBBBBBBBBBBBBBig success!\n");
    //BN_CTX* ctx = BN_CTX_new();
    //BIGNUM* a = BN_new();
    //BIGNUM* b = BN_new();
    //BIGNUM* c = BN_new();
    //unsigned char d[2] = { 0x0, 0x2};
    //char str[32];
    //hex2str(d, str, 2);
    //printf("%d\n", d[0]);
    //printf("%d\n", d[1]);
    //unsigned char e[2] = { '0' ,'a'};
    //cout << BN_hex2bn(&a, str) << endl;
    //cout << BN_hex2bn(&b, (char*)e) << endl;
    //BN_exp(c, a, b, ctx);
    //char* res = BN_bn2dec(c);
    //printf("%s \n", res);
    //BIGNUM* bn_k = NULL, * bn_order = NULL;
    //unsigned char msg[32] = { 0x3f, 0xab ,0x0};
    //SM2_KEY_PAIR* key_pair = new SM2_KEY_PAIR;
    //sm2_generate_key_pair(key_pair);
    //generate_k_rand(bn_k, bn_order, msg, 32, key_pair->pri_key);
    MultiSet_Hash_Example();
    return 2022;
}