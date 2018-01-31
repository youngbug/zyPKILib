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
#include "mbedtls/x509_crt.h"
//
#define RET_ERR(r,errcode)  if(r!=0) { ret = errcode; goto exit;}
//
//
unsigned int __stdcall zypki_gen_keypairs(unsigned char ucAlgorithmType, int iPara, unsigned char ucMode, unsigned char * pucPublicKey, unsigned char * pucPrivateKey)
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
	if (1 == (ucMode & 0x01)) //输出到文件 第0bit为1
	{
		f = fopen(pucPrivateKey, "wb");
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
		fclose(f);
		//
		f = fopen(pucPublicKey, "wb");
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
		fclose(f);
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

unsigned int __stdcall zypki_gen_certsignreq(csr_opt * pcsr_opt, char * pcCsrFilePath, unsigned char* pucCSRBuffer)
{
	int ret = 0;
	mbedtls_pk_context key;
	char buf[1024];
	unsigned char csr_buf[4096];
	int i;
	char *p, *q, *r;
	mbedtls_x509write_csr req;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *pers = "zy_csr";
	FILE *f;
	size_t len = 0;
	//
	mbedtls_x509write_csr_init(&req);
	mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);
	mbedtls_pk_init(&key);
	memset(buf, 0, sizeof(buf));
	//
	mbedtls_x509write_csr_set_key_usage(&req, pcsr_opt->ucKeyUsage);
	mbedtls_x509write_csr_set_ns_cert_type(&req, pcsr_opt->ucNSCertType);
	//0. Seed the PRNG
	mbedtls_entropy_init(&entropy);
	ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
	RET_ERR(ret, ZYPKI_ERR_CRYPTO);
	//1.设置Subject
	ret = mbedtls_x509write_csr_set_subject_name(&req, pcsr_opt->pcSubject);
	RET_ERR(ret, ZYPKI_ERR_CERTSUBJECT);
	//2.Load the key
	ret = mbedtls_pk_parse_keyfile(&key, pcsr_opt->keyfilepath, NULL);
	RET_ERR(ret, ZYPKI_ERR_LOADPRIKEY);
	//3.Set the key
	mbedtls_x509write_csr_set_key(&req, &key);
	//4.Gen CSR
	ret = mbedtls_x509write_csr_pem(&req, csr_buf, 4096, mbedtls_ctr_drbg_random, &ctr_drbg);
	RET_ERR(ret, ZYPKI_ERR_WRITECSR);
	//5.1 检查csr文件路径是否存在,不存在直接输出到缓冲区
	memcpy(pucCSRBuffer, csr_buf, 4096);
	if (NULL == pcCsrFilePath)
	{
		ret = ZYPKI_ERR_SUCCESS;
		goto exit;
	}
	//5.2 将证书请求保存到文件中
	len = strlen((char *)csr_buf);
	f = fopen(pcCsrFilePath, "w");
	if (NULL == f)
	{
		ret = ZYPKI_ERR_FILEIO;
		goto exit;
	}
	if (fwrite(csr_buf, 1, len, f) != len)
	{
		ret = ZYPKI_ERR_FILEIO;
		fclose(f);
		goto exit;
	}
	fclose(f);
	ret = ZYPKI_ERR_SUCCESS;
exit:
	mbedtls_x509write_csr_free(&req);
	mbedtls_pk_free(&key);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	//
	return ret;
}

unsigned int __stdcall zypki_sign_cert(signcert_opt * psc_opt, char* pcCertFilePath, unsigned char * pucCertBuffer)
{
	int ret = 0;
	mbedtls_mpi serial;
	mbedtls_x509_crt issuer_crt;
	mbedtls_pk_context loaded_issuer_key, loaded_subject_key;
	mbedtls_pk_context *issuer_key = &loaded_issuer_key, *subject_key = &loaded_subject_key;
	mbedtls_x509_csr csr;
	char subject_name[256];
	mbedtls_x509write_cert crt;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *pers = "zy sign cert";
	FILE *f;
	unsigned char output_buf[4096];
	size_t len = 0;
	// 0. Set 
	mbedtls_x509write_crt_init(&crt);
	mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
	mbedtls_pk_init(&loaded_issuer_key);
	mbedtls_pk_init(&loaded_subject_key);
	mbedtls_mpi_init(&serial);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_x509_csr_init(&csr);
	mbedtls_x509_crt_init(&issuer_crt);
	memset(subject_name, 0, sizeof(subject_name));
	// 0. Seed the PRNG
	mbedtls_entropy_init(&entropy);
	ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
	RET_ERR(ret, ZYPKI_ERR_CRYPTO);
	
	//
	ret = mbedtls_mpi_read_string(&serial, 10, psc_opt->pcSerial);
	RET_ERR(ret, ZYPKI_ERR_SERIALNUM);
	
	//1.1 Load the CSR
	if (!(psc_opt->iSelfSign) && strlen(psc_opt->pcCSRFilePath))
	{
		ret = mbedtls_x509_csr_parse_file(&csr, psc_opt->pcCSRFilePath);
		RET_ERR(ret, ZYPKI_ERR_READCSR);
		
		//
		ret = mbedtls_x509_dn_gets(subject_name, sizeof(subject_name), &csr.subject);
		if (ret < 0)
		{
			ret = ZYPKI_ERR_READCSR;
			goto exit;
		}
		//
		psc_opt->pcSubjectName = subject_name;
		subject_key = &csr.pk;
	}
	// 1.2 Load the keys 
	// mbedTLS的示例里这里要判断不是自签名，那自签名的issuerkey从哪装载？后面也没机会装载了啊？不判断是不是自签名合理一些吧？
	if (/*!(psc_opt->iSelfSign) && */strlen(psc_opt->pcSubjectKeyFilePath))
	{
		ret = mbedtls_pk_parse_keyfile(&loaded_subject_key, psc_opt->pcSubjectKeyFilePath, psc_opt->pcSubjectPwd);
		RET_ERR(ret, ZYPKI_ERR_LOADPRIKEY);
		//
		ret = mbedtls_pk_parse_keyfile(&loaded_issuer_key, psc_opt->pcIssuerKeyFilePath, psc_opt->pcIssuerPwd);
		RET_ERR(ret, ZYPKI_ERR_LOADPRIKEY);
	}
	// 1.3 check issuer certificate match

	// 1.4  if self sign certificate
	if ( psc_opt->iSelfSign)
	{
		//自签名证书的签发机构名字就是subject name
		psc_opt->pcSubjectName = psc_opt->pcIssuerName; 
		subject_key = issuer_key;
	}
	//
	mbedtls_x509write_crt_set_subject_key(&crt, subject_key);
	mbedtls_x509write_crt_set_issuer_key(&crt, issuer_key);
	//
	// 1.0 Check the names for validity
	ret = mbedtls_x509write_crt_set_subject_name(&crt, psc_opt->pcSubjectName);
	RET_ERR(ret, ZYPKI_ERR_CERTSUBJECT);
	//
	ret = mbedtls_x509write_crt_set_issuer_name(&crt, psc_opt->pcIssuerName);
	RET_ERR(ret, ZYPKI_ERR_ISSUER);
	//
	ret = mbedtls_x509write_crt_set_serial(&crt, &serial);
	RET_ERR(ret, ZYPKI_ERR_SERIALNUM);
	//
	ret = mbedtls_x509write_crt_set_validity(&crt, psc_opt->pcNotBefore, psc_opt->pcNotAfter);
	RET_ERR(ret, ZYPKI_ERR_INVALIDDATE);
	//Adding the Basic Constraints extension
	ret = mbedtls_x509write_crt_set_basic_constraints(&crt, psc_opt->iIsCA, psc_opt->iCAMaxPath);
	RET_ERR(ret, ZYPKI_ERR_PARAMETER);
	//Adding the Subject Key Identifier
	ret = mbedtls_x509write_crt_set_subject_key_identifier(&crt);
	RET_ERR(ret, ZYPKI_ERR_PARAMETER);
	// Adding the Authority Key Identifier
	ret = mbedtls_x509write_crt_set_authority_key_identifier(&crt);
	RET_ERR(ret, ZYPKI_ERR_PARAMETER);
	//
	ret = mbedtls_x509write_crt_set_key_usage(&crt, psc_opt->ucKeyUsage);
	RET_ERR(ret, ZYPKI_ERR_PARAMETER);
	//
	ret = mbedtls_x509write_crt_set_ns_cert_type(&crt, psc_opt->ucNSCertType);
	RET_ERR(ret, ZYPKI_ERR_PARAMETER);
	//
	ret = mbedtls_x509write_crt_pem(&crt, output_buf, 4096, mbedtls_ctr_drbg_random, &ctr_drbg);
	if (ret < 0)
	{
		ret = ZYPKI_ERR_SIGNCERT;
		goto exit;
	}
	len = strlen((char*)output_buf);
	memcpy(pucCertBuffer, output_buf, len);
	if (NULL != pcCertFilePath)
	{
		f = fopen(pcCertFilePath, "w");
		if (NULL == f)
		{
			fclose(f);
			ret = ZYPKI_ERR_FILEIO;
			goto exit;
		}
		if (fwrite(output_buf, 1, len, f) != len)
		{
			fclose(f);
			ret = ZYPKI_ERR_FILEIO;
			goto exit;
		}
		fclose(f);
	}

exit:
	mbedtls_x509write_crt_free(&crt);
	mbedtls_pk_free(&loaded_subject_key);
	mbedtls_pk_free(&loaded_issuer_key);
	mbedtls_mpi_free(&serial);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	return ret;
}

unsigned int __stdcall zypki_sm2_genkeypairs(unsigned char * pucPrivateKey, unsigned char * pucPublicKey)
{
	int ret;
	mbedtls_ecdsa_context ctx;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *pers = "zy_ecdsa";
	//
	mbedtls_ecdsa_init(&ctx);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
	RET_ERR(ret, ZYPKI_ERR_GENKEYPAIRS);
	//MBEDTLS_ECP_DP_SECP192R1
	ret = mbedtls_ecdsa_genkey(&ctx, MBEDTLS_ECP_DP_SECP256K1, mbedtls_ctr_drbg_random, &ctr_drbg);
	//ret = mbedtls_ecdsa_genkey(&ctx, MBEDTLS_ECP_DP_SM2256, mbedtls_ctr_drbg_random, &ctr_drbg);
	RET_ERR(ret, ZYPKI_ERR_GENKEYPAIRS);


exit:
	return 0;
}

unsigned int __stdcall zypki_sm2_sign(unsigned char ucHashAlgID, unsigned char * pucPrivateKey, unsigned char * pucData, unsigned int uiDataLen, unsigned char * pucSignature, unsigned int * puiSignatureLen)
{

	return 0;
}
