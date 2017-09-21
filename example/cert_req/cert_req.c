/*
FileName: cert_req.c
Author: 赵洋 cnrgc@163.com
Version : 1.0
Date: 2017.9.21
Description: 产生证书请求文件CSR示例
*/

#include "zypkilib.h"
//
int main()
{
	int ret;
	unsigned char pub[10000];
	unsigned char pri[10000];
	//1.产生RSA密钥对
	ret = zypki_gen_keypairs(ALG_TYPE_RSA_1024_BIT, 0x10001, 0x10, pub, pri);

    return 0;
}

