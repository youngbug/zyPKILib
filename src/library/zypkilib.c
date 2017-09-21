/*
FileName: zypkilib.c
Author: 赵洋 cnrgc@163.com
Version : 1.0
Date: 2017.9.21
Description: zypkilib 函数实现
*/

#include "zypkilib.h"
#include "polarssl/ecdsa.h"
#include "polarssl/rsa.h"
#include "polarssl/pk.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
//
#define RET_ERR(r,errcode)  if(r!=0) { return errcode;}
//
//
unsigned char __stdcall zypki_gen_keypairs(unsigned char ucAlgorithmType, int iPara, unsigned char ucMode, unsigned char * pucPublicKey, unsigned char * pucPrivateKey)
{
	int	ret;
	int keysize;
	int format;
	pk_type_t pk_type;
	pk_context key;
	entropy_context entropy;
	ctr_drbg_context ctr_drbg;
	const char *pers = "zy_gen_key";
	unsigned char pubkey[16000];
	unsigned char prikey[16000];
	unsigned char *c_pub = pubkey;
	unsigned char *c_pri = prikey;
	FILE *f;
	int pub_len,pri_len;
	//
	if (ucAlgorithmType > ALG_TYPE_ECC_192_BIT)
	{
		return ZYPKI_ERR_PARAMETER;
	}
	//
	/**
	* 0.准备工作
	*/
	pk_init(&key);
	entropy_init(&entropy);
	ret = ctr_drbg_init(&ctr_drbg, entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
	RET_ERR(ret, ZYPKI_ERR_CRYPTO);
	//
	switch (ucAlgorithmType)
	{
		case ALG_TYPE_RSA_1024_BIT:
			pk_type = POLARSSL_PK_RSA;
			keysize = 1024;
			break;
		case ALG_TYPE_RSA_2048_BIT:
			pk_type = POLARSSL_PK_RSA;
			keysize = 2048;
			break;
		case ALG_TYPE_ECC_192_BIT:
			pk_type = POLARSSL_PK_ECKEY;
			keysize = 192;
			break;
		default:
			return ZYPKI_ERR_PARAMETER;
	}
	//
	/**
	* 1. 产生密钥对
	*/
	if (POLARSSL_PK_RSA == pk_type)
	{
		ret = pk_init_ctx(&key, pk_info_from_type(POLARSSL_PK_RSA));
		RET_ERR(ret, ZYPKI_ERR_CRYPTO);
		//
		ret = rsa_gen_key(pk_rsa(key), ctr_drbg_random, &ctr_drbg, keysize, iPara);
		RET_ERR(ret, ZYPKI_ERR_GENKEYPAIRS);
		//
	}
	else if (POLARSSL_PK_ECKEY == pk_type)
	{
		ret = pk_init_ctx(&key, pk_info_from_type(POLARSSL_PK_ECKEY));
		RET_ERR(ret, ZYPKI_ERR_CRYPTO);
		//
		ret = ecp_gen_key(iPara, pk_ec(key), ctr_drbg_random, &ctr_drbg);
		RET_ERR(ret, ZYPKI_ERR_GENKEYPAIRS);
		//
	}
	//
	/**
	* 2. 输出密钥对
	*/
	if ( 1 == ucMode >> 4 & 0x01)  //第4bit为1 pem格式
	{
		ret = pk_write_key_pem(&key, prikey, sizeof(prikey));
		RET_ERR(ret, ZYPKI_ERR_PEMENCODE);
		pri_len = strlen((char *)prikey);
		//
		ret = pk_write_pubkey_pem(&key, pubkey, sizeof(pubkey));
		RET_ERR(ret, ZYPKI_ERR_PEMENCODE);
		pub_len = strlen((char *)pubkey);
	}
	else //第5bit不为1 der格式
	{
		ret = pk_write_key_der(&key, prikey, sizeof(prikey));
		if (ret < 0)
		{
			return ZYPKI_ERR_DERENCODE;
		}
		pri_len = ret;
		c_pri = prikey + sizeof(prikey) - pri_len;
		//
		ret = pk_write_pubkey_der(&key, pubkey, sizeof(pubkey));
		if (ret < 0)
		{
			return ZYPKI_ERR_DERENCODE;
		}
		pub_len = ret;
		c_pub = pubkey + sizeof(pubkey) - pub_len;
	}
	//
	/**
	* 2.1 输出到缓冲区或者文件
	*/
	if (1 == ucMode & 0x01) //输出到文件 第0bit为1
	{
		f = fopen(prikey, "wb");
		if (NULL == f)
		{
			return	ZYPKI_ERR_FILEIO;
		}
		if (fwrite(c_pri, 1, pri_len, f) != pri_len)
		{
			fclose(f);
			return ZYPKI_ERR_FILEIO;
		}
		//
		f = fopen(pubkey, "wb");
		if (NULL == f)
		{
			return	ZYPKI_ERR_FILEIO;
		}
		if (fwrite(c_pub, 1, pub_len, f) != pub_len)
		{
			fclose(f);
			return ZYPKI_ERR_FILEIO;
		}
	}
	else //输出到缓冲区
	{
		memcpy(pucPrivateKey, c_pri, pri_len);
		memcpy(pucPublicKey, c_pub, pub_len);
	}
	return ZYPKI_ERR_SUCCESS;
}

unsigned char __stdcall zypki_gen_certsignreq(csr_opt * pcsr_opt, char * pcCsrFilePath)
{
	return 0;
}
