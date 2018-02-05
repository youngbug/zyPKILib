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
	int len = 64;
	memset(Pubkey, 0, 64);
	memset(Prikey, 0, 64);
	uiRet = zypki_sm2_genkeypairs(Prikey, Pubkey);
	uiRet = zypki_sm2_sign(ZYPKI_HASH_ALG_SHA256, Prikey, Data, 1024, Sign, &len);
	return 0;
}



int main()
{
	sm2_sign();
}