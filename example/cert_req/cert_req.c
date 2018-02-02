/*
FileName: cert_req.c
Author: 赵洋 cnrgc@163.com
Version : 1.0
Date: 2017.9.21
Description: 产生证书请求文件CSR示例
*/

#include "zypkilib.h"
#include <stdio.h>
//
int main()
{
	int ret;
	unsigned char pub[10000];
	unsigned char pri[10000];
	unsigned char csr_buf[4096];
	unsigned char cer_buf[4096];
	signcert_opt  sgopt;
	//char keypath =;
	csr_opt		opt;
	//1.产生RSA密钥对
	//ret = zypki_gen_keypairs(ALG_TYPE_RSA_1024_BIT, 0x10001, 0x10, pub, pri);
	ret = zypki_gen_keypairs(ALG_TYPE_RSA_1024_BIT, 0x10001, 0x01, "F:\\pub.key", "F:\\pri.key");
	opt.keyfilepath = "F:\\pri.key";
	opt.ucKeyUsage = X509_KU_DIGITAL_SIGNATURE;
	opt.ucNSCertType = X509_NS_CERT_TYPE_EMAIL;
	opt.pcSubject = "CN=Cert,O=Zhao Yang,C=CN";
	ret = zypki_gen_certsignreq(&opt, "F:\\cert.csr",csr_buf);
	//
	sgopt.iCAMaxPath = 120;
	sgopt.iIsCA = 1;
	sgopt.iSelfSign = 1;
	sgopt.pcCSRFilePath = "F:\\cert.csr";
	sgopt.pcIssuerKeyFilePath = "F:\\pri.key";
	sgopt.pcIssuerName = "CN=Cert,O=Zhao Yang,C=CN";
	//20100317160000Z
	sgopt.pcNotAfter = "20180101000000";
	sgopt.pcNotBefore = "20170901000000";
	sgopt.pcSerial = "1234567890";
	sgopt.pcSubjectKeyFilePath = "F:\\pri.key";
	sgopt.pcIssuerPwd = NULL;
	sgopt.pcSubjectPwd = NULL;
	sgopt.ucKeyUsage = X509_KU_DIGITAL_SIGNATURE | X509_KU_KEY_CERT_SIGN;
	//
	ret = zypki_sign_cert(&sgopt, "F:\\cert.cer",cer_buf);
    return 0;
}

