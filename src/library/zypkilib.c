/*
FileName: zypkilib.c
Author: 赵洋 cnrgc@163.com
Version : 1.0
Date: 2017.9.21
Description: zypkilib 函数实现
*/

#include "zypkilib.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_csr.h"
//
#define RET_ERR(r,errcode)  if(r!=0) { ret = errcode; goto exit;}
//
//
unsigned char __stdcall zypki_gen_keypairs(unsigned char ucAlgorithmType, int iPara, unsigned char ucMode, unsigned char * pucPublicKey, unsigned char * pucPrivateKey)
{
	int	ret;
	int keysize;
	int format;
	mbedtls_pk_type_t pk_type;
	mbedtls_pk_context key;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
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
	mbedtls_pk_init(&key);
	mbedtls_entropy_init(&entropy);
	ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
	RET_ERR(ret, ZYPKI_ERR_CRYPTO);
	//
	switch (ucAlgorithmType)
	{
		case ALG_TYPE_RSA_1024_BIT:
			pk_type = MBEDTLS_PK_RSA;
			keysize = 1024;
			break;
		case ALG_TYPE_RSA_2048_BIT:
			pk_type = MBEDTLS_PK_RSA;
			keysize = 2048;
			break;
		case ALG_TYPE_ECC_192_BIT:
			pk_type = MBEDTLS_PK_ECKEY;
			keysize = 192;
			break;
		default:
			return ZYPKI_ERR_PARAMETER;
	}
	//
	/**
	* 1. 产生密钥对
	*/
	if (MBEDTLS_PK_RSA == pk_type)
	{
		ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
		RET_ERR(ret, ZYPKI_ERR_CRYPTO);
		//
		ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random, &ctr_drbg, keysize, iPara);
		RET_ERR(ret, ZYPKI_ERR_GENKEYPAIRS);
		//
	}
	else if (MBEDTLS_PK_ECKEY == pk_type)
	{
		ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
		RET_ERR(ret, ZYPKI_ERR_CRYPTO);
		//
		ret = mbedtls_ecp_gen_key(iPara, mbedtls_pk_ec(key), mbedtls_ctr_drbg_random, &ctr_drbg);
		RET_ERR(ret, ZYPKI_ERR_GENKEYPAIRS);
		//
	}
	//
	/**
	* 2. 输出密钥对
	*/
	if ( 1 == ucMode >> 4 & 0x01)  //第4bit为1 pem格式
	{
		ret = mbedtls_pk_write_key_pem(&key, prikey, sizeof(prikey));
		RET_ERR(ret, ZYPKI_ERR_PEMENCODE);
		pri_len = strlen((char *)prikey);
		//
		ret = mbedtls_pk_write_pubkey_pem(&key, pubkey, sizeof(pubkey));
		RET_ERR(ret, ZYPKI_ERR_PEMENCODE);
		pub_len = strlen((char *)pubkey);
	}
	else //第5bit不为1 der格式
	{
		ret = mbedtls_pk_write_key_der(&key, prikey, sizeof(prikey));
		if (ret < 0)
		{
			ret =  ZYPKI_ERR_DERENCODE;
			goto exit;
		}
		pri_len = ret;
		c_pri = prikey + sizeof(prikey) - pri_len;
		//
		ret = mbedtls_pk_write_pubkey_der(&key, pubkey, sizeof(pubkey));
		if (ret < 0)
		{
			ret = ZYPKI_ERR_DERENCODE;
			goto exit;
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
			ret = ZYPKI_ERR_FILEIO;
			goto exit;
		}
		if (fwrite(c_pri, 1, pri_len, f) != pri_len)
		{
			fclose(f);
			ret = ZYPKI_ERR_FILEIO;
			goto exit;
		}
		//
		f = fopen(pubkey, "wb");
		if (NULL == f)
		{
			ret = ZYPKI_ERR_FILEIO;
			goto exit;
		}
		if (fwrite(c_pub, 1, pub_len, f) != pub_len)
		{
			fclose(f);
			ret = ZYPKI_ERR_FILEIO;
			goto exit;
		}
	}
	else //输出到缓冲区
	{
		memcpy(pucPrivateKey, c_pri, pri_len);
		memcpy(pucPublicKey, c_pub, pub_len);
	}
	ret = ZYPKI_ERR_SUCCESS;
	//
exit:
	mbedtls_pk_free(&key);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	return ret;
}

unsigned char __stdcall zypki_gen_certsignreq(csr_opt * pcsr_opt, char * pcCsrFilePath)
{
	int ret = 0;
	mbedtls_pk_context key;
	char buf[1024];
	int i;
	char *p, *q, *r;
	mbedtls_x509write_csr req;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *pers = "zy_csr";
	//
	mbedtls_x509write_csr_init(&req);
	mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);
	mbedtls_pk_init(&key);
	memset(buf, 0, sizeof(buf));
	//
	mbedtls_x509write_csr_set_key_usage(&req, pcsr_opt->ucKeyUsage);
	mbedtls_x509write_csr_set_ns_cert_type(&req, pcsr_opt->ucNSCertType);
	//
	ret = mbedtls_x509write_csr_set_subject_name(&req, pcsr_opt->pcSubject);
	//
	return 0;
}
