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
	
	memset(Data, 0x01, 1024);
	sm2_sign.iKeyBitLen = 256;
	uiRet = zypki_sm2_sign_without_hash(ZYPKI_HASH_ALG_SHA256, Prikey, Data, 32, &sm2_sign);
	
	uiRet = zypki_sm2_verify(Pubkey, Data, 32, sm2_sign);
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