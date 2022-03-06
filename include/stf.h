/**
 * @brief STF国标接口
 */
#pragma once

#if defined(_WIN32) || defined(__CYGWIN__) || defined(__MINGW32__) ||          \
    defined(__MINGW64__)
#ifdef SDF_EXPORT_API
#ifdef __GNUC__
#define SDF_EXPORT __attribute__((dllexport))
#else
#define SDF_EXPORT __declspec(dllexport)
#endif
#else
#ifdef __GNUC__
#define SDF_EXPORT __attribute__((dllimport))
#else
#define SDF_EXPORT __declspec(dllimport)
#endif
#endif
#else
#define SDF_EXPORT __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif
// 时间戳服务接口常量定义
typedef unsigned char SGD_UINT8;
typedef unsigned int SGD_UINT32;

// 返回值与错误码定义
#define STF_TS_OK 0
#define STF_TS_ERROR_BASE 0x04000000
#define STF_TS_INDATA_TOOLONG 0x04000001
#define STF_TS_ENOUGH_MEMORY 0x04000002
#define STF_TS_MALFORMAT 0x04000003
#define STF_TS_INVALID_ITEM 0x04000004
#define STF_TS_INVALID_SIGNATURE 0x04000005
#define STF_TS_INVALID_ALG 0x04000006
#define STF_TS_INVALID_REQUEST 0x04000007
#define STF_TS_INVALID_DATAFORMAT 0x04000008
#define STF_TS_TIME_NOT_AVAILABLE 0x04000009
#define STF_TS_UNACCEPTED_POLICY 0x0400000A
#define STF_TS_UNACCEPTED_EXTENSION 0x0400000B
#define STF_TS_ADDINFO_NOT_AVAILBLE 0x0400000C
#define STF_TS_SYSTEM_FAILURE 0x0400000E

#define STF_TS_CONFIG_ERROR 0x04000010

/**
 * @brief 建立时间戳环境句柄
 * @param phTSHandle[out]: 时间戳环境句柄指针
 * @return 0:成功; 其他:失败
 */
SGD_UINT32 STF_InitEnvironment(void **phTSHandle);

/**
 * @brief 清除时间戳环境句柄
 * @param hTSHandle[in]:时间戳环境句柄
 * @return 0:成功; 其他:失败
 */
SGD_UINT32 STF_ClearEnvironment(void *hTSHandle);

/**
 * @brief 用指定算法对时间戳请求信息indata进行密码杂凑运算，生成时间戳请求包
 * @param hTSHandle[in]: 时间戳环境句柄
 * @param pucInData[in]: 需要加盖时间戳的用户信息
 * @param uiInDataLength[in]: 用户信息的长度
 * @param uiReqType[in]: 请求的时间戳服务类型
 * @param pucTSExt[in]: 时间戳请求包的其他扩展，DER编码格式
 * @param uiHashAlgID[in]: 密码杂凑算法标识
 * @param pucTSRequest[out]: 时间戳请求
 * @param puiTSRequestLength[in,out]: 时间戳请求的长度
 * @return 0:成功; 其他:失败
 * @note uiReqType:
 * 0代表时间戳响应应该包含时间戳服务器的证书，1代表时间戳响应不包含时间戳服务器的证书
 * puiTSRequestLength[in,out]:
 * 入口值为指定的用于存放时间戳请求的字符数组的最大长度，出口值为时间戳请求的实际长度
 */
SGD_UINT32 STF_CreateTSRequest(void *hTSHandle, SGD_UINT8 *pucInData,
                               SGD_UINT32 uiInDataLength, SGD_UINT32 uiReqType,
                               SGD_UINT8 *pucTSExt, SGD_UINT32 uiHashAlgID,
                               SGD_UINT8 *pucTSRequest,
                               SGD_UINT32 *puiTSRequestLength);

/**
 * @brief 根据时间戳请求包生成时间戳响应包
 * @param hTSHandle[in]: 时间戳环境句柄
 * @param pucTSRequest[in]: 时间戳请求
 * @param uiTSRequestLength[in]: 时间戳请求的长度
 * @param uiSignatureAlgID[in]: 签名算法标识
 * @param pucTSResponse[out]: 时间戳响应
 * @param puiTSResponseLength[in,out]: 时间戳响应的长度
 * @return 0:成功; 其他:失败
 * @note puiTSResponseLength[in,out]:
 * 入口值为指定的用于存放时间戳的字符数组的最大长度，出口值为时间戳的实际长度
 */
SGD_UINT32 STF_CreateTSReponse(void *hTSHandle, SGD_UINT8 *pucTSRequest,
                               SGD_UINT32 uiTSRequestLength,
                               SGD_UINT32 uiSignatureAlgID,
                               SGD_UINT8 *pucTSResponse,
                               SGD_UINT32 *puiTSResponseLength);

/**
 * @brief 验证时间戳响应是否有效
 * @param hTSHandle[in]: 时间戳环境句柄
 * @param pucTSResponse[in]: 获取的时间戳响应
 * @param uiTSResponseLength[in]: 时间戳响应的长度
 * @param uiHashAlgID[in]: 密码杂凑算法标识
 * @param uiSignatureAlgID[in]: 签名算法标识
 * @param pucTSCert[in]: TSA的证书，DER编码格式
 * @param uiTSCertLength[in]: TSA证书的长度
 * @return 0:成功; 其他:失败
 * @note
 * 该函数验证时间戳响应是否有效。对于不包含时间戳服务器证书的响应，需要指定时间戳服务器的证书才能进行验证；
 * 对于包含时间戳服务器证书的响应，可以把入口的证书参数置为空，使用响应中自带的证书进行验证，否则将使用指定的证书进行验证，即指定的证书优先于自带的证书。
 */
SGD_UINT32 STF_VerifyTSValidity(void *hTSHandle, SGD_UINT8 *pucTSResponse,
                                SGD_UINT32 uiTSResponseLength,
                                SGD_UINT32 uiHashAlgID,
                                SGD_UINT32 uiSignatureAlgID,
                                SGD_UINT8 *pucTSCert,
                                SGD_UINT32 uiTSCertLength);
/**
 * @brief 获取时间戳的主要信息。
 * @param hTSHandle[in]: 时间戳环境句柄
 * @param pucTSResponse[in]: 获取的时间戳响应
 * @param uiTSResponseLength[in]: 时间戳响应的长度
 * @param pucIssuerName[out]: TSA的通用名
 * @param puiIssuerNameLength[in,out]: TSA通用名的长度
 * @param pucTime[out]: 时间戳标注的时间值
 * @param puiTimeLength[in,out]: 时间戳标注的时间值长度
 * @return 0:成功; 其他:失败
 * @note 该函数解析时间戳的主要信息，包括TSA的通用名和时间戳的签发时间。
 * puiIssuerNameLength[in,out]:
 * 入口值为指定的用于存放签发者名称的字符数组的最大长度，出口值为签发者名称的实际长度
 * puiTimeLength[in,out]:
 * 入口值为指定的用于存放时间戳标注时间值的字符数组的最大长度，出口值为时间戳标注的时间值的实际长度
 */
SGD_UINT32 STF_GetTSInfo(void *hTSHandle, SGD_UINT8 *pucTSResponse,
                         SGD_UINT32 uiTSResponseLength,
                         SGD_UINT8 *pucIssuerName,
                         SGD_UINT32 *puiIssuerNameLength, SGD_UINT8 *pucTime,
                         SGD_UINT32 *puiTimeLength);

/**
 * @brief 获取时间戳的主要信息
 * @param hTSHandle[in]: 时间戳环境句柄
 * @param pucTSResponse[in]: 获取的时间戳响应
 * @param uiTSResponseLength[in]: 时间戳响应的长度
 * @param uiItemnumber[in]: 指定获取时间戳详细信息的项目编号
 * @param pucItemValue[out]: 解析得到的时间戳相关信息
 * @param puiItemValueLength[in,out]: 时间戳相关信息的对应长度
 * @return 0:成功; 其他:失败
 * @note 该函数解析时间戳的详细信息，uiItemnumber定义：
 * STF_TIME_OF_STAMP：签发时间
 * STF_CN_OF_TSSIGNER：签发者的通用名
 * STF_ORINGINAL_DATA：时间戳请求的原始信息
 * STF_CERT_OF_TSSERVER：时间戳服务器的证书
 * STF_CERTCHAIN_OF_TSSERVER：时间戳服务器的证书链
 * STF_SOURCE_OF_TIME：时间源的来源
 * STF_TIME_PRECISION：时间精度
 * STF_RESPONSE_TYPE：响应方式
 * STF_SUBJECT_COUNTRY_OF_TSSIGNER：签发者国家
 * STF_SUBJECT_ORGNIZATION_OF_TSSIGNER：签发者组织
 * STF_SUBJECT_CITY_OF_TSSIGNER：签发者城市
 * STF_SUBJECT_EMAIL_OF_TSSIGNER：签发者联系用电子信箱。
 */
SGD_UINT32 STF_GetTSDetail(void *hTSHandle, SGD_UINT8 *pucTSResponse,
                           SGD_UINT32 uiTSResponseLength,
                           SGD_UINT32 uiItemnumber, SGD_UINT8 *pucItemValue,
                           SGD_UINT32 *puiItemValueLength);

#ifdef __cplusplus
}
#endif
