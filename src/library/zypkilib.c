/*
FileName: zypkilib.c
Author: 赵洋 cnrgc@163.com
Version : 1.0
Date: 2017.9.21
Description: zypkilib 函数实现
*/
#include <Windows.h>
#include "zypkilib.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/sha256.h"
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
	int len;
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
	ret = mbedtls_ecdsa_genkey(&ctx, MBEDTLS_ECP_DP_SM2256, mbedtls_ctr_drbg_random, &ctr_drbg);
	RET_ERR(ret, ZYPKI_ERR_GENKEYPAIRS);
	//ret = mbedtls_ecp_point_write_binary(&ctx.grp, &ctx.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &len, pucPublicKey, 64);
	ret = mbedtls_mpi_write_binary(&ctx.Q.X, pucPublicKey, 32);
	RET_ERR(ret, ZYPKI_ERR_READ_BIGNUM);
	ret = mbedtls_mpi_write_binary(&ctx.Q.Y, pucPublicKey+32, 32);
	RET_ERR(ret, ZYPKI_ERR_READ_BIGNUM);
	ret = mbedtls_mpi_write_binary(&ctx.d, pucPrivateKey, 32);
	RET_ERR(ret, ZYPKI_ERR_GENKEYPAIRS);
exit:
	return ret;
}

unsigned int __stdcall zypki_sm2_sign(unsigned char ucHashAlgID, unsigned char * pucPrivateKey, unsigned char * pucData, unsigned int uiDataLen, unsigned char * pucSignature, unsigned int * puiSignatureLen)
{
	int ret;
	mbedtls_ecdsa_context ctx;
	unsigned char  Hash1[32];
	unsigned char  Hash2[32];
	unsigned char  T1[2+13+32*6];
	unsigned char* T2;
	unsigned char  IDA[] = { 0x63, 0x6E, 0x72, 0x67, 0x63, 0x40, 0x31, 0x36, 0x33, 0x2E, 0x63, 0x6F, 0x6D};
	unsigned char  ENTLA[2] = {0x00, 0x68}; //cnrgc@163.com -- 0x68bit
	unsigned char  Pub_X[32];
	unsigned char  Pub_Y[32];
	//直接从ctx中使用mpi读出来的数组字节序就是正确的，不需要逆序
	unsigned char  a[32];
	unsigned char  b[32];
	unsigned char  Gx[32];
	unsigned char  Gy[32];
	mbedtls_mpi		r, s;
	mbedtls_ecdsa_init(&ctx);
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);
	//1.先加载SM2椭圆曲线参数
	ret = mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_SM2256);
	RET_ERR(ret, ZYPKI_ERR_LOAD_SM2ECGROUP);
	//2.将私钥加载
	ret = mbedtls_mpi_read_binary(&ctx.d, pucPrivateKey, 32);
	RET_ERR(ret, ZYPKI_ERR_LOAD_SM2KEY);
	//3.将公钥算出来
	ret = mbedtls_ecp_mul(&ctx.grp, &ctx.Q, &ctx.d, &ctx.grp.G, NULL, NULL);
	RET_ERR(ret, ZYPKI_ERR_LOAD_SM2KEY);
	//4.准备计算杂凑ZA的数据
	ret = mbedtls_mpi_write_binary(&ctx.Q.X, Pub_X, 32);
	RET_ERR(ret, ZYPKI_ERR_READ_BIGNUM);
	ret = mbedtls_mpi_write_binary(&ctx.Q.Y, Pub_Y, 32);
	RET_ERR(ret, ZYPKI_ERR_READ_BIGNUM);
	ret = mbedtls_mpi_write_binary(&ctx.grp.A, a, 32);
	RET_ERR(ret, ZYPKI_ERR_READ_BIGNUM);
	ret = mbedtls_mpi_write_binary(&ctx.grp.B, b, 32);
	RET_ERR(ret, ZYPKI_ERR_READ_BIGNUM);
	ret = mbedtls_mpi_write_binary(&ctx.grp.G.X, Gx, 32);
	RET_ERR(ret, ZYPKI_ERR_READ_BIGNUM);
	ret = mbedtls_mpi_write_binary(&ctx.grp.G.Y, Gy, 32);
	RET_ERR(ret, ZYPKI_ERR_READ_BIGNUM);
	//5.算杂凑之ZA
	//ZA=H256(ENTLA || IDA || a || b || xG || yG || xA || yA), IDA的位数是ENTLA, xG,yG是G点，xA,yA是公钥
	//IDA: 636E726763403136332E636F6D "cnrgc@163.com"
	memcpy(T1, ENTLA, 2);
	memcpy(T1 + 2, IDA, 13);
	memcpy(T1 + 2 + 13, a, 32);
	memcpy(T1 + 2 + 13 + 32, b, 32);
	memcpy(T1 + 2 + 13 + 32 + 32, Gx, 32);
	memcpy(T1 + 2 + 13 + 32 + 32 + 32, Gy, 32);
	memcpy(T1 + 2 + 13 + 32 + 32 + 32 + 32, Pub_X, 32);
	memcpy(T1 + 2 + 13 + 32 + 32 + 32 + 32 + 32, Pub_Y, 32);
	//
	if (ZYPKI_HASH_ALG_SHA256 ==ucHashAlgID)
	{
		mbedtls_sha256(T1, 2 + 13 + 32 * 6, Hash1, 0);
	}
	else
	{
		RET_ERR(ret, ZYPKI_ERR_UNSUPPORTEDHASHALG);
	}
	//6.计算H256(ZA||M)
	T2 = malloc(uiDataLen + 32);
	if (NULL == T2)
	{
		RET_ERR(ret, ZYPKI_ERR_MALLOC);
	}
	memcpy(T2, Hash1, 32);
	memcpy(T2 + 32, pucData, uiDataLen);
	if (ZYPKI_HASH_ALG_SHA256 == ucHashAlgID)
	{
		mbedtls_sha256(T2, uiDataLen + 32, Hash2, 0);
		//7.计算ECC签名
		ret = mbedtls_ecdsa_sign_det(&ctx.grp, &r, &s, &ctx.d, Hash2, 32, MBEDTLS_MD_SHA256);
		RET_ERR(ret, ZYPKI_ERR_SM2SIGN);
	}
	else
	{
		RET_ERR(ret, ZYPKI_ERR_UNSUPPORTEDHASHALG);
	}
	//8.把MPI的数据读出来
	ret = mbedtls_mpi_write_binary(&r, pucSignature, 32);
	RET_ERR(ret, ZYPKI_ERR_READ_BIGNUM);
	ret = mbedtls_mpi_write_binary(&s, pucSignature + 32, 32);
	RET_ERR(ret, ZYPKI_ERR_READ_BIGNUM);
exit:
	free(T2);
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	mbedtls_ecdsa_free(&ctx);
	return ret;
}
