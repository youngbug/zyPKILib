/*
FileName: sm2_test.c
Author: ÕÔÑó cnrgc@163.com
Version : 1.0
Date: 2017.9.21
Description: SM2Ê¾Àý
*/

#include "zypkilib.h"
#include <stdio.h>




int sm2_sign()
{
	unsigned int uiRet;
	unsigned char Pubkey[64];
	unsigned char Prikey[64];
	unsigned char Data[1024];
	unsigned char Sign[64];
	unsigned char r[] = { 0x13,0x3D,0xE2,0xF6,0xCF,0xAD,0xD7,0x02,0x01,0xB5,0xB3,0xA0,0xCA,0xDC,0x10,0x9A,0x69,0xCF,0xFB,0x09,0xFE,0xAD,0x3C,0x1E,0x75,0xA1,0x90,0xAD,0x79,0x51,0x72,0xBE };
	unsigned char s[] = { 0x13,0x3D,0xE2,0xF6,0xCF,0xAD,0xD7,0x02,0x01,0xB5,0xB3,0xA0,0xCA,0xDC,0x10,0x9A,0x69,0xCF,0xFB,0x09,0xFE,0xAD,0x3C,0x1E,0x75,0xA1,0x90,0xAD,0x79,0x51,0x72,0xBE };
	ecdsa_signature sm2_sign;
	int len = 64;
	FILE * fp;
	errno_t err;
	memset(Pubkey, 0, 64);
	memset(Prikey, 0, 64);
	
	uiRet = zypki_sm2_genkeypairs(Prikey, Pubkey);
	/*
	err = fopen_s(&fp,"prikey.bin", "wb");
	fwrite(Prikey, 1, 64, fp);
	fp = fclose(fp);
	//
	err = fopen_s(&fp, "pubkey.bin", "wb");
	fwrite(Pubkey, 1, 64, fp);
	fp = fclose(fp);
	*/
	//

	
	err = fopen_s(&fp, "prikey.bin", "rb");
	fread(Prikey, 1, 64, fp);
	fclose(fp);
	err = fopen_s(&fp, "pubkey.bin", "rb");
	fread(Pubkey, 1, 64, fp);
	fclose(fp);
	
	//uiRet = zypki_sm2_sign(ZYPKI_HASH_ALG_SHA256, Prikey, Data, 1024, Sign, &len);
	memset(Data, 0x01, 1024);
	sm2_sign.iKeyBitLen = 256;
	uiRet = zypki_sm2_sign_without_hash(ZYPKI_HASH_ALG_SHA256, Prikey, Data, 32, &sm2_sign);
	//memcpy(sm2_sign.r, r, 32);
	//memcpy(sm2_sign.s, s, 32);
//	uiRet = zypki_sm2_verify(Pubkey, Data, 32, sm2_sign);
	err = fopen_s(&fp, "r.bin", "wb");
	fwrite(sm2_sign.r, 1, 32, fp);
	fclose(fp);
	err = fopen_s(&fp, "s.bin", "wb");
	fwrite(sm2_sign.s, 1, 32, fp);
	fclose(fp);

	return 0;
}



int main()
{
	sm2_sign();
}