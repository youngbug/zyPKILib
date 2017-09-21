> Author: 赵洋  cnrgc@163.com  
> Date:   September 19,2017

函数接口说明
===
## 1. zypki_initialize

## 2. zypki_gen_keypairs
zypki_gen_keypair用于产生一个非对称算法的密钥对并将密钥对输出到给定的缓冲区或者指定的文件中。
* **声明**  

`unsigned char __stdcall zypki_gen_keypairs(unsigned char ucAlgorithmType, int iPara, unsigned char ucMode, unsigned char* pucPublicKey, unsigned char* pucPrivateKey);`

  
* **参数**  

_ucAlgorithmType_ [in]  
指示算法类型，告诉函数使用的非对称算法和密钥长度，支持的取值如下

|值|含义|
|-|-|
|ALG_TYPE_RSA_1024_BIT|1024位长的RSA密钥对|
|ALG_TYPE_RSA_2048_BIT|2048位长的RSA密钥对|

_iPara_ [in]  
如果是产生RSA密钥对，则表示公钥指数e的值，一般取值3或者0x10001；如果是产生ECC密钥对则指示椭圆曲线参数，取值如如下：  
```
typedef enum
{
    ECP_DP_NONE = 0,
    ECP_DP_SECP192R1,      /*!< 192-bits NIST curve  */
    ECP_DP_SECP224R1,      /*!< 224-bits NIST curve  */
    ECP_DP_SECP256R1,      /*!< 256-bits NIST curve  */
    ECP_DP_SECP384R1,      /*!< 384-bits NIST curve  */
    ECP_DP_SECP521R1,      /*!< 521-bits NIST curve  */
    ECP_DP_BP256R1,        /*!< 256-bits Brainpool curve */
    ECP_DP_BP384R1,        /*!< 384-bits Brainpool curve */
    ECP_DP_BP512R1,        /*!< 512-bits Brainpool curve */
    ECP_DP_M221,           /*!< (not implemented yet)    */
    ECP_DP_M255,           /*!< Curve25519               */
    ECP_DP_M383,           /*!< (not implemented yet)    */
    ECP_DP_M511,           /*!< (not implemented yet)    */
    ECP_DP_SECP192K1,      /*!< 192-bits "Koblitz" curve */
    ECP_DP_SECP224K1,      /*!< 224-bits "Koblitz" curve */
    ECP_DP_SECP256K1,      /*!< 256-bits "Koblitz" curve */
} ecp_group_id;
```

_ucMode_ [in]  
指示产生密钥对的输出模式是输出到缓冲区，还是输出到文件。

|值|含义|
|-|-|
|0x00|将DER格式的密钥直接输出到pucPublicKey和pucPrivateKey指向的缓冲区中|
|0x10|将PEM格式密钥直接输出到pucPublicKey和pucPrivateKey指向的缓冲区中|
|0x01|将DER格式密钥输出到pucPublicKey和pucPrivateKey指向的文件地址中|
|0x11|将PEM格式密钥输出到pucPublicKey和pucPrivateKey指向的文件地址中|

_pucPublicKey_ [in/out]  
密钥输出模式为输出到缓冲区时，输出的公钥数据保存在缓冲区中，调用者需要保证缓冲区的空间足够大。  
密钥输出模式为输出到文件时，调用时需要将输出公钥文件的路径作为参数输入。

_pucPrivateKey_ [in/out]  
密钥输出模式为输出到缓冲区时，输出的私钥数据保存在缓冲区中，调用者需要保证缓冲区的空间足够大。  
密钥输出模式为输出到文件时，调用时需要将输出私钥文件的路径作为参数输入。

* **返回值** 

|返回值|说明|
|-|-|
|ZYPKI_ERR_SUCCESS|成功|
|ZYPKI_ERR_PARAMETER|参数错误|

## 3.zypki_gen_certsignreq
zypki_gen_certsignreq用于生成证书签名请求的函数。  

* **声明**  
`unsigned char __stdcall zypki_gen_certsignreq(csr_opt * pcsr_opt, char * pcCsrFilePath)
`  

* **参数**  

_pcsr_opt_ [in]  
指向一个csr_opt结构体的指针，制作证书请求的必要信息都需要提前保存在这个结构体里。

_pcCsrFilePath_ [in]  
传入证书请求文件的生成路径。

* **返回值** 

|返回值|说明|
|-|-|
|ZYPKI_ERR_SUCCESS|成功|