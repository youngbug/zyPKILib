/*
FileName: cert_req.c
Author: ���� cnrgc@163.com
Version : 1.0
Date: 2017.9.21
Description: ����֤�������ļ�CSRʾ��
*/

#include "zypkilib.h"
#include <stdio.h>

int sm2_sign()
{
	unsigned int uiRet;
	unsigned char Pubkey[64];
	unsigned char Prikey[64];
	memset(Pubkey, 0, 64);
	memset(Prikey, 0, 64);
	uiRet = zypki_sm2_genkeypairs(Prikey, Pubkey);
	return 0;
}

int main()
{
	sm2_sign();
	return 0;
}