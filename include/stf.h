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

/**
 * @brief
 * @param phTSHandle
 * @return
 */
SGD_UINT32 STF_InitEnvironment(void** phTSHandle);

/**
 * @brief
 * @param hTSHandle
 * @return
 */
SGD_UINT32 STF_ClearEnvironment(void* hTSHandle);



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








#ifdef __cplusplus
}
#endif
