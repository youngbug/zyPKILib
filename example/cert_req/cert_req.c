/*
FileName: cert_req.c
Author: ���� cnrgc@163.com
Version : 1.0
Date: 2017.9.21
Description: ����֤�������ļ�CSRʾ��
*/

#include "zypkilib.h"
//
int main()
{
	int ret;
	unsigned char pub[10000];
	unsigned char pri[10000];
	//1.����RSA��Կ��
	ret = zypki_gen_keypairs(ALG_TYPE_RSA_1024_BIT, 0x10001, 0x10, pub, pri);

    return 0;
}

