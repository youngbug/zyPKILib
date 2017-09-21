/*
FileName: zypkilib.h
Author: ���� cnrgc@163.com
Version : 1.0
Date: 2017.9.20
Description: zypkilib ��������
*/
#ifndef __ZYPKILIB_H__
#define __ZYPKILIB_H__

#ifdef __cplusplus
extern "C" {
#endif

//������
#define		ZYPKI_ERR_BASE				0xF0000000
#define		ZYPKI_ERR_SUCCESS			0							//�ɹ�
#define		ZYPKI_ERR_PARAMETER			ZYPKI_ERR_BASE + 1			//��������
#define		ZYPKI_ERR_CRYPTO			ZYPKI_ERR_BASE + 2			//�����㷨���
#define		ZYPKI_ERR_GENKEYPAIRS		ZYPKI_ERR_BASE + 3			//������Կ�Դ���
#define		ZYPKI_ERR_DERENCODE			ZYPKI_ERR_BASE + 4			//der�������
#define		ZYPKI_ERR_PEMENCODE			ZYPKI_ERR_BASE + 5			//pem�������
#define		ZYPKI_ERR_FILEIO			ZYPKI_ERR_BASE + 6			//�ļ�IO����

//�㷨����
#define		ALG_TYPE_RSA_1024_BIT		1
#define		ALG_TYPE_RSA_2048_BIT		2
#define		ALG_TYPE_ECC_192_BIT		3

//��������
typedef struct
{
	char*			pcSubject;
	unsigned char	ucKeyUsage;
	unsigned char	ucNSCertType;
}csr_opt;
//
unsigned char __stdcall zypki_initialize();
unsigned char __stdcall zypki_gen_keypairs(unsigned char ucAlgorithmType, int iPara, unsigned char ucMode, unsigned char* pucPublicKey, unsigned char* pucPrivateKey);
unsigned char __stdcall zypki_gen_certsignreq(csr_opt* pcsr_opt, char* pcCsrFilePath);


#ifdef __cplusplus
}
#endif


#endif // !__ZYPKILIB_H__

