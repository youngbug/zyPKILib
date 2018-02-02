#include "sm2.h"
/*
FileName: sm2.c
Author: 赵洋 cnrgc@163.com
Version : 1.0
Date: 2018.2.1
Description: 国密算法SM2 函数实现
*/

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecp.h"

#define BYTES_TO_T_UINT_4( a, b, c, d )             \
    ( (mbedtls_mpi_uint) a <<  0 ) |                          \
    ( (mbedtls_mpi_uint) b <<  8 ) |                          \
    ( (mbedtls_mpi_uint) c << 16 ) |                          \
    ( (mbedtls_mpi_uint) d << 24 )

#define BYTES_TO_T_UINT_2( a, b )                   \
    BYTES_TO_T_UINT_4( a, b, 0, 0 )

#define BYTES_TO_T_UINT_8( a, b, c, d, e, f, g, h ) \
    BYTES_TO_T_UINT_4( a, b, c, d ),                \
    BYTES_TO_T_UINT_4( e, f, g, h )

/*
* SM2椭圆曲线公钥密码算法推荐曲线参数
*/
static const mbedtls_mpi_uint sm2256_p[] = {
	BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF),
	BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF ,0xFF, 0xFF, 0xFF, 0xFF),
	BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00),
	BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
};
static const mbedtls_mpi_uint sm2256_a[] = {
	BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF),
	BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
	BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00),
	BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC),
};
static const mbedtls_mpi_uint sm2256_b[] = {
	BYTES_TO_T_UINT_8(0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34),
	BYTES_TO_T_UINT_8(0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7),
	BYTES_TO_T_UINT_8(0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92),
	BYTES_TO_T_UINT_8(0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93),
};
static const mbedtls_mpi_uint sm2256_gx[] = {
	BYTES_TO_T_UINT_8(0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19),
	BYTES_TO_T_UINT_8(0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94),
	BYTES_TO_T_UINT_8(0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1),
	BYTES_TO_T_UINT_8(0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7),
};
static const mbedtls_mpi_uint sm2256_gy[] = {
	BYTES_TO_T_UINT_8(0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C),
	BYTES_TO_T_UINT_8(0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53),
	BYTES_TO_T_UINT_8(0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40),
	BYTES_TO_T_UINT_8(0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0),
};
static const mbedtls_mpi_uint sm2256_n[] = {
	BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF),
	BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
	BYTES_TO_T_UINT_8(0x72, 0x03, 0xDF, 0x6B, 0x21, 0xC6, 0x05, 0x2B),
	BYTES_TO_T_UINT_8(0x53, 0xBB, 0xF4, 0x09, 0x39, 0xD5, 0x41, 0x23),
};



unsigned int zy_sm2_generate_keypairs(unsigned char * pucPrivateKey, unsigned char * pucPublicKey)
{
	int ret;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	//
	mbedtls_mpi P;		//素数p
	mbedtls_mpi A, B;	//系数a,b
	mbedtls_mpi N;		//阶n
	mbedtls_ecp_point G;//基点G
	const char *pers = "zy_ecdsa";
	static mbedtls_mpi_uint one[] = { 1 };
	//
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
	//
	mbedtls_mpi_init(&P); 
	mbedtls_mpi_init(&A);
	mbedtls_mpi_init(&B);
	mbedtls_mpi_init(&N);
	mbedtls_ecp_point_init(&G);
	//
	P.s = 1;
	P.n = sizeof(sm2256_p) / sizeof(mbedtls_mpi_uint);
	P.p = (mbedtls_mpi_uint*)sm2256_p;
	//
	A.s = 1;
	A.n = sizeof(sm2256_a) / sizeof(mbedtls_mpi_uint);
	A.p = (mbedtls_mpi_uint*)sm2256_a;
	//
	B.s = 1;
	B.n = sizeof(sm2256_b) / sizeof(mbedtls_mpi_uint);
	B.p = (mbedtls_mpi_uint*)sm2256_b;
	//
	N.s = 1;
	N.n = sizeof(sm2256_n) / sizeof(mbedtls_mpi_uint);
	N.p = (mbedtls_mpi_uint*)sm2256_n;
	//
	G.X.s = 1;
	G.X.n = sizeof(sm2256_gx) / sizeof(mbedtls_mpi_uint);
	G.X.p = (mbedtls_mpi_uint*)sm2256_gx;
	//
	G.Y.s = 1;
	G.Y.n = sizeof(sm2256_gy) / sizeof(mbedtls_mpi_uint);
	G.Y.p = (mbedtls_mpi_uint*)sm2256_gy;
	//
	G.Z.s = 1;
	G.Z.n = 1;
	G.Z.p = one;
	//

	return 0;
}
