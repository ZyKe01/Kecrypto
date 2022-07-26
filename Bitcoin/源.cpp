#pragma warning (disable: 4996)
using namespace std;
#include <iostream>
#include <string.h>  
#include <stdlib.h>
#include <openssl/ecdsa.h>
#include "forge_signature.h"
#include "bitcoin_parse.h"

int main()
{
	//forge_example();
	unsigned int length = 450;
	unsigned char rawData[450] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0xf9, 0xb0, 0xfc, 0x05, 0x3a, 0x3b, 0xe3, 0xf6, 0xb3, 0x91, 0x41, 0x30, 0x50, 0x4c, 0xbd, 0x4a, 0x34, 0x9a, 0x22, 0x28, 0x12, 0xcc, 0xe5, 0xe9, 0x84, 0xd0, 0x89, 0xa4, 0x41, 0x18, 0xa0, 0x57, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfd, 0xff, 0xff, 0xff, 0x02, 0x30, 0x75, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x76, 0xa9, 0x14, 0x86, 0x8c, 0xdc, 0x1f, 0x45, 0x36, 0xa6, 0xa5, 0x83, 0x07, 0x29, 0x52, 0xd7, 0x52, 0x89, 0x9a, 0xa0, 0x32, 0x03, 0x6d, 0x88, 0xac, 0x73, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00, 0x14, 0x95, 0x6f, 0xa4, 0x83, 0x09, 0x57, 0x7f, 0x3d, 0x3b, 0xe4, 0xae, 0xec, 0x19, 0x87, 0x93, 0x23, 0x45, 0xba, 0x29, 0x00, 0x02, 0x47, 0x30, 0x44, 0x02, 0x20, 0x25, 0x26, 0x1e, 0x38, 0xcc, 0x67, 0x99, 0x0a, 0xb5, 0xb0, 0xb0, 0x5e, 0x62, 0x23, 0x99, 0x3b, 0x32, 0x62, 0x61, 0x85, 0x6c, 0xc8, 0xf2, 0xb7, 0xe8, 0x94, 0x38, 0x45, 0x2f, 0xc8, 0x14, 0x77, 0x02, 0x20, 0x65, 0xcf, 0x9d, 0x44, 0x36, 0x50, 0x8c, 0x77, 0xa3, 0xd7, 0xad, 0x19, 0xe5, 0xab, 0xb3, 0x88, 0xda, 0x7b, 0x88, 0x77, 0x2e, 0x43, 0x0d, 0x11, 0x77, 0x9a, 0xf7, 0x82, 0xa6, 0xc8, 0x0d, 0x39, 0x01, 0x21, 0x03, 0xc7, 0x71, 0x02, 0xd6, 0x71, 0xe8, 0x0e, 0xdf, 0xb9, 0x25, 0xd9, 0x02, 0x1a, 0x2a, 0x9a, 0x8f, 0x57, 0xaf, 0x1a, 0x41, 0x5f, 0x49, 0x90, 0x2f, 0xcf, 0xcf, 0x06, 0xe8, 0x85, 0xa9, 0xe1, 0xc0, 0x68, 0xe4, 0x22, 0x00 };

	parse(rawData, length);
	return 0;
}