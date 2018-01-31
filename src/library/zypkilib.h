/*
FileName: zypkilib.h
Author: 赵洋 cnrgc@163.com
Version : 1.0
Date: 2017.9.20
Description: zypkilib 函数声明
*/
#ifndef __ZYPKILIB_H__
#define __ZYPKILIB_H__

#ifdef __cplusplus
extern "C" {
#endif

//错误码
#define		ZYPKI_ERR_BASE				0xF0000000
#define		ZYPKI_ERR_SUCCESS			0							//成功
#define		ZYPKI_ERR_PARAMETER			ZYPKI_ERR_BASE + 1			//参数错误
#define		ZYPKI_ERR_CRYPTO			ZYPKI_ERR_BASE + 2			//加密算法库错
#define		ZYPKI_ERR_GENKEYPAIRS		ZYPKI_ERR_BASE + 3			//产生密钥对错误
#define		ZYPKI_ERR_DERENCODE			ZYPKI_ERR_BASE + 4			//der编码错误
#define		ZYPKI_ERR_PEMENCODE			ZYPKI_ERR_BASE + 5			//pem编码错误
#define		ZYPKI_ERR_FILEIO			ZYPKI_ERR_BASE + 6			//文件IO错误
#define		ZYPKI_ERR_CERTSUBJECT		ZYPKI_ERR_BASE + 7			//证书Subject错误
#define		ZYPKI_ERR_LOADPRIKEY		ZYPKI_ERR_BASE + 8			//加载私钥错误
#define		ZYPKI_ERR_WRITECSR			ZYPKI_ERR_BASE + 9			//写CSR错误
#define		ZYPKI_ERR_SERIALNUM			ZYPKI_ERR_BASE + 10			//serial num错误
#define		ZYPKI_ERR_READCSR			ZYPKI_ERR_BASE + 11			//读CSR错误
#define		ZYPKI_ERR_ISSUER			ZYPKI_ERR_BASE + 12			//Issuer错误
#define		ZYPKI_ERR_INVALIDDATE		ZYPKI_ERR_BASE + 13			//错误的时间
#define		ZYPKI_ERR_SIGNCERT			ZYPKI_ERR_BASE + 14			//签发证书失败

//算法类型
#define		ALG_TYPE_RSA_1024_BIT		1
#define		ALG_TYPE_RSA_2048_BIT		2
#define		ALG_TYPE_ECC_192_BIT		3


/*
* X.509 v3 Key Usage Extension flags
*/
#define X509_KU_DIGITAL_SIGNATURE            (0x80)  /* bit 0 */
#define X509_KU_NON_REPUDIATION              (0x40)  /* bit 1 */
#define X509_KU_KEY_ENCIPHERMENT             (0x20)  /* bit 2 */
#define X509_KU_DATA_ENCIPHERMENT            (0x10)  /* bit 3 */
#define X509_KU_KEY_AGREEMENT                (0x08)  /* bit 4 */
#define X509_KU_KEY_CERT_SIGN                (0x04)  /* bit 5 */
#define X509_KU_CRL_SIGN                     (0x02)  /* bit 6 */
#define X509_KU_ENCIPHER_ONLY                (0x01)  /* bit 7 */
#define X509_KU_DECIPHER_ONLY              (0x8000)  /* bit 8 */

/*
* Netscape certificate types
* (http://www.mozilla.org/projects/security/pki/nss/tech-notes/tn3.html)
*/

#define X509_NS_CERT_TYPE_SSL_CLIENT         (0x80)  /* bit 0 */
#define X509_NS_CERT_TYPE_SSL_SERVER         (0x40)  /* bit 1 */
#define X509_NS_CERT_TYPE_EMAIL              (0x20)  /* bit 2 */
#define X509_NS_CERT_TYPE_OBJECT_SIGNING     (0x10)  /* bit 3 */
#define X509_NS_CERT_TYPE_RESERVED           (0x08)  /* bit 4 */
#define X509_NS_CERT_TYPE_SSL_CA             (0x04)  /* bit 5 */
#define X509_NS_CERT_TYPE_EMAIL_CA           (0x02)  /* bit 6 */
#define X509_NS_CERT_TYPE_OBJECT_SIGNING_CA  (0x01)  /* bit 7 */


//数据类型
typedef struct
{
	char*			pcSubject;
	unsigned char	ucKeyUsage;
	unsigned char	ucNSCertType;
	char*			keyfilepath;
}csr_opt;
//
typedef struct
{
	char*		pcIssuerCert; 
	char*		pcCSRFilePath;
	char*		pcSubjectKeyFilePath;
	char*		pcIssuerKeyFilePath;
	char*		pcSubjectPwd;
	char*		pcIssuerPwd;
	char*		pcSerial; 
	char*		pcSubjectName;
	char*		pcIssuerName;
	int			iSelfSign; 
	char*		pcNotBefore;
	char*		pcNotAfter;
	int			iIsCA;
	int			iCAMaxPath;
	unsigned char ucKeyUsage;
	unsigned char ucNSCertType; 
}signcert_opt;
//
unsigned int __stdcall zypki_initialize();
unsigned int __stdcall zypki_gen_keypairs(unsigned char ucAlgorithmType, int iPara, unsigned char ucMode, unsigned char* pucPublicKey, unsigned char* pucPrivateKey);
unsigned int __stdcall zypki_gen_certsignreq(csr_opt* pcsr_opt, char* pcCsrFilePath, unsigned char* pucCSRBuffer);
unsigned int __stdcall zypki_sign_cert(signcert_opt* psc_opt, char* pcCertFilePath, unsigned char* pucCertBuffer);

//
unsigned int __stdcall zypki_sm2_genkeypairs(unsigned char* pucPrivateKey, unsigned char* pucPublicKey);
unsigned int __stdcall zypki_sm2_sign(unsigned char ucHashAlgID, unsigned char* pucPrivateKey, unsigned char* pucData, unsigned int uiDataLen, unsigned char* pucSignature, unsigned int* puiSignatureLen);

#ifdef __cplusplus
}
#endif


#endif // !__ZYPKILIB_H__

