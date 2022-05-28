#pragma once
#include "sm2_generate_key_pair.h"
#include "sm2_sign_and_verify.h"

int print_key_pair(const SM2_KEY_PAIR* key_pair)
{
    if (key_pair == NULL) {
        return 0;
    }
    printf("private key is:\n");
    for (int i = 0; i < 32; i++) {
        printf("%x ", key_pair->pri_key[i]);
    }
    printf("\npublic key is:\n");
    if (key_pair->pub_key[0] == 0x04) {
        printf("No compress.\n");
    }
    printf("x_A: ");
    for (int i = 1; i < 33; i++) {
        printf("%x ", key_pair->pub_key[i]);
    }
    printf("\ny_A: ");
    for (int i = 33; i < 65; i++) {
        printf("%x ", key_pair->pub_key[i]);
    }
}

int example()
{
    int ret = 0;
    unsigned char msg[] = { "Look at the stars, look how they shine for you." };
    unsigned int msg_len = (unsigned int)(strlen((char*)msg));
    unsigned char id[] = { "201900460049" };
    unsigned int id_len = (unsigned int)(strlen((char*)id));

    SM2_KEY_PAIR* key_pair = new SM2_KEY_PAIR;
    if (ret = sm2_generate_key_pair(key_pair)) {
        printf("Key generation failed!\n");
        return ret;
    }
    printf("Key generation succeed!\n");
    print_key_pair(key_pair);
    printf("\n");

    SM2_SIGNATURE_STRUCT sig;
    printf("\nGenerating signature... ...\n");
    if (ret = sm2_sign_data(msg, msg_len, id, id_len, key_pair->pub_key,
        key_pair->pri_key, &sig)) {
        printf("Create SM2 signature failed!\n");
        return ret;
    }
    printf("Create SM2 signature succeeded!\n");
    printf("SM2 signature:\n");
    printf("r coordinate:\n");
    for (int i = 0; i < sizeof(sig.r_coordinate); i++)
    {
        printf("0x%x  ", sig.r_coordinate[i]);
    }
    printf("\ns coordinate:\n");
    for (int i = 0; i < sizeof(sig.s_coordinate); i++)
    {
        printf("0x%x  ", sig.s_coordinate[i]);
    }

    printf("\n\Verifying signature... ...\n");
    if (ret = sm2_verify_sig(msg, msg_len, id, id_len, key_pair->pub_key, &sig)) {
        printf("Verify SM2 signature failed!\n");
        return ret;
    }
    printf("Verify SM2 signature succeeded!\n");

    key_pair_free(key_pair);
    return ret;
}
