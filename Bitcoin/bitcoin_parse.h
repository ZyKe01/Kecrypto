#pragma once
#include <string>

int parse(unsigned char* rawData, unsigned int length) {
	unsigned char version[4];
	unsigned char flag[2];
	unsigned char in_cnt[1];
	unsigned char prev_hash[32];
	unsigned char output_index[4];
	unsigned int script_len;
	unsigned int seq;
	unsigned char out_cnt[1];
	unsigned long long value;

	memcpy(version, rawData, 4);
	rawData += 4;
	memcpy(flag, rawData, 2);
	rawData += 2;
	memcpy(in_cnt, rawData, 1);
	rawData += 1;
	memcpy(prev_hash, rawData, 32);
	rawData += 32;
	memcpy(output_index, rawData, 4);
	rawData += 4;
	memcpy(&script_len, rawData, 1);
	rawData += 1;
	memcpy(&seq, rawData, 4);
	rawData += 4;
	memcpy(out_cnt, rawData, 1);
	rawData += 1;
	memcpy(&value, rawData, 8);
	rawData += 8;

	printf("Version: %x\n", version[0]);
	printf("Witness: %x\n", flag[1]);
	printf("tx_in count: %d\n", in_cnt[0]);
	printf("Prev_hash: ");
	for (int i = 31; i >= 0; i--)
		printf("%02x", prev_hash[i]);
	printf("\nOutput_index: ");
	for (int i = 0; i < 4; i++)
		printf("%02x", output_index[i]);
	printf("\nSequence: %u\n", seq);
	printf("tx_out count: %d\n", out_cnt[0]);
	printf("Value: %u\n", value);

	unsigned char pk_script_len;
	memcpy(&pk_script_len, rawData, 1);
	rawData += 1;
	//printf("pk_script_len: %u\n", pk_script_len);
	unsigned char* script = (unsigned char*)malloc(pk_script_len);
	memcpy(script, rawData, pk_script_len);
	rawData += pk_script_len;
	printf("Script: ");
	for (int i = 0; i < pk_script_len; i++)
		printf("%02x", script[i]);
	memcpy(&value, rawData, 8);
	rawData += 8;
	printf("\nValue: %u\n", value);
	memcpy(&pk_script_len, rawData, 1);
	rawData += 1;
	memcpy(script, rawData, pk_script_len);
	rawData += pk_script_len;
	printf("Script: ");
	for (int i = 0; i < pk_script_len; i++)
		printf("%02x", script[i]);
	free(script);

	/*witness*/
	unsigned char wit_cnt;
	memcpy(&wit_cnt, rawData, 1);
	rawData += 1;
	unsigned char wit_len;
	unsigned char* witness = NULL;
	for (int i = 0; i < wit_cnt; i++) {
		memcpy(&wit_len, rawData, 1);
		rawData += 1;
		witness = (unsigned char*)malloc(wit_len);
		memcpy(witness, rawData, wit_len);
		rawData += wit_len;
		printf("\nWitness%d: ", i+1);
		for (int j = 0; j < wit_len; j++)
			printf("%02x", witness[j]);
		free(witness);
	}
	unsigned int lock_time;
	memcpy(&lock_time, rawData, 4);
	rawData += 4;
	printf("\nLock time: %u", lock_time);
	return 1;
}