#include <cstring>
#include <iostream>

#include "stf.h"

#define UNUSED __attribute__((unused))
const char kBase64Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                               "abcdefghijklmnopqrstuvwxyz"
                               "0123456789+/";
//192.168.209.140     172.27.120.33
class Base64 {
public:
  static bool Encode(const std::string &in, std::string *out) {
    int i = 0, j = 0;
    size_t enc_len = 0;
    unsigned char a3[3];
    unsigned char a4[4];

    out->resize(EncodedLength(in));

    size_t input_len = in.size();
    std::string::const_iterator input = in.begin();

    while (input_len--) {
      a3[i++] = *(input++);
      if (i == 3) {
        a3_to_a4(a4, a3);

        for (i = 0; i < 4; i++) {
          (*out)[enc_len++] = kBase64Alphabet[a4[i]];
        }

        i = 0;
      }
    }

    if (i) {
      for (j = i; j < 3; j++) {
        a3[j] = '\0';
      }

      a3_to_a4(a4, a3);

      for (j = 0; j < i + 1; j++) {
        (*out)[enc_len++] = kBase64Alphabet[a4[j]];
      }

      while ((i++ < 3)) {
        (*out)[enc_len++] = '=';
      }
    }

    return (enc_len == out->size());
  }

  static bool Encode(const char *input, size_t input_length, char *out, size_t out_length) {
    int i = 0, j = 0;
    char *out_begin = out;
    unsigned char a3[3];
    unsigned char a4[4];

    size_t encoded_length = EncodedLength(input_length);

    if (out_length < encoded_length) return false;

    while (input_length--) {
      a3[i++] = *input++;
      if (i == 3) {
        a3_to_a4(a4, a3);

        for (i = 0; i < 4; i++) {
          *out++ = kBase64Alphabet[a4[i]];
        }

        i = 0;
      }
    }

    if (i) {
      for (j = i; j < 3; j++) {
        a3[j] = '\0';
      }

      a3_to_a4(a4, a3);

      for (j = 0; j < i + 1; j++) {
        *out++ = kBase64Alphabet[a4[j]];
      }

      while ((i++ < 3)) {
        *out++ = '=';
      }
    }

    return (out == (out_begin + encoded_length));
  }

  static bool Decode(const std::string &in, std::string *out) {
    int i = 0, j = 0;
    size_t dec_len = 0;
    unsigned char a3[3];
    unsigned char a4[4];

    size_t input_len = in.size();
    std::string::const_iterator input = in.begin();

    out->resize(DecodedLength(in));

    while (input_len--) {
      if (*input == '=') {
        break;
      }

      a4[i++] = *(input++);
      if (i == 4) {
        for (i = 0; i <4; i++) {
          a4[i] = b64_lookup(a4[i]);
        }

        a4_to_a3(a3,a4);

        for (i = 0; i < 3; i++) {
          (*out)[dec_len++] = a3[i];
        }

        i = 0;
      }
    }

    if (i) {
      for (j = i; j < 4; j++) {
        a4[j] = '\0';
      }

      for (j = 0; j < 4; j++) {
        a4[j] = b64_lookup(a4[j]);
      }

      a4_to_a3(a3,a4);

      for (j = 0; j < i - 1; j++) {
        (*out)[dec_len++] = a3[j];
      }
    }

    return (dec_len == out->size());
  }

  static bool Decode(const char *input, size_t input_length, char *out, size_t out_length) {
    int i = 0, j = 0;
    char *out_begin = out;
    unsigned char a3[3];
    unsigned char a4[4];

    size_t decoded_length = DecodedLength(input, input_length);

    if (out_length < decoded_length) return false;

    while (input_length--) {
      if (*input == '=') {
        break;
      }

      a4[i++] = *(input++);
      if (i == 4) {
        for (i = 0; i <4; i++) {
          a4[i] = b64_lookup(a4[i]);
        }

        a4_to_a3(a3,a4);

        for (i = 0; i < 3; i++) {
          *out++ = a3[i];
        }

        i = 0;
      }
    }

    if (i) {
      for (j = i; j < 4; j++) {
        a4[j] = '\0';
      }

      for (j = 0; j < 4; j++) {
        a4[j] = b64_lookup(a4[j]);
      }

      a4_to_a3(a3,a4);

      for (j = 0; j < i - 1; j++) {
        *out++ = a3[j];
      }
    }

    return (out == (out_begin + decoded_length));
  }

  static size_t DecodedLength(const char *in, size_t in_length) {
    int numEq = 0;

    const char *in_end = in + in_length;
    while (*--in_end == '=') ++numEq;

    return ((6 * in_length) / 8) - numEq;
  }

  static size_t DecodedLength(const std::string &in) {
    int numEq = 0;
    size_t n = in.size();

    for (std::string::const_reverse_iterator it = in.rbegin(); *it == '='; ++it) {
      ++numEq;
    }

    return ((6 * n) / 8) - numEq;
  }

  inline static size_t EncodedLength(size_t length) {
    return (length + 2 - ((length + 2) % 3)) / 3 * 4;
  }

  inline static size_t EncodedLength(const std::string &in) {
    return EncodedLength(in.length());
  }

  inline static void StripPadding(std::string *in) {
    while (!in->empty() && *(in->rbegin()) == '=') in->resize(in->size() - 1);
  }

private:
  static inline void a3_to_a4(unsigned char * a4, unsigned char * a3) {
    a4[0] = (a3[0] & 0xfc) >> 2;
    a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
    a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
    a4[3] = (a3[2] & 0x3f);
  }

  static inline void a4_to_a3(unsigned char * a3, unsigned char * a4) {
    a3[0] = (a4[0] << 2) + ((a4[1] & 0x30) >> 4);
    a3[1] = ((a4[1] & 0xf) << 4) + ((a4[2] & 0x3c) >> 2);
    a3[2] = ((a4[2] & 0x3) << 6) + a4[3];
  }

  static inline unsigned char b64_lookup(unsigned char c) {
    if(c >='A' && c <='Z') return c - 'A';
    if(c >='a' && c <='z') return c - 71;
    if(c >='0' && c <='9') return c + 4;
    if(c == '+') return 62;
    if(c == '/') return 63;
    return 255;
  }
};

int main(UNUSED int argc, UNUSED char *argv[]) {
  void *handle;

  UNUSED unsigned char timestampReqData[2048] = {0};
  UNUSED unsigned int timestampReqDataLen = sizeof(timestampReqData);

  UNUSED unsigned char timestampRespData[4096] = {0};
  UNUSED unsigned int timestampRespDataLen = sizeof(timestampRespData);
  UNUSED char TSACertData[2048] = {0};
  UNUSED int TSACertDataLen = sizeof(TSACertData);

  UNUSED unsigned char issuerName[2048] = {0};
  UNUSED unsigned int issuerNameLen = sizeof(issuerName);
  UNUSED unsigned char timeData[2048] = {0};
  UNUSED unsigned int timeDataLen = sizeof(timeData);
  UNUSED unsigned char itemData[2048] = {0};
  UNUSED unsigned int itemDataLen = sizeof(itemData);

  UNUSED const char *plainData = "test plain data";
  std::cout<<plainData<<std::endl;
  UNUSED unsigned int plainDataLen = (unsigned int)strlen(plainData);

  //**************************************************************************
  SGD_UINT32 retcode = STF_InitEnvironment(&handle);
  if (retcode == STF_TS_OK) {
    std::cout << "STF_InitEnvironment: OK" << std::endl;
  } else {
    printf("STF_InitEnvironment: %x\n",retcode);
  }

  //**************************************************************************
  timestampReqDataLen = sizeof(timestampReqData);
  memset(timestampReqData, 0, timestampReqDataLen);
  //uiReqType = 0表示包含时间戳服务器证书，1表示不包含时间戳服务器证书
  retcode = STF_CreateTSRequest(handle, (unsigned char *)plainData,
                                plainDataLen, 0, NULL, 0, SGD_SHA256,
                                timestampReqData, &timestampReqDataLen);
  if (retcode == STF_TS_OK) {
    std::cout << "STF_CreateTSRequest: OK" << std::endl;
//    for (size_t i = 0; i < timestampReqDataLen; i++) {
//      std::cout << timestampReqData[i];
//    }std::cout << std::endl;
    char base64[2048] = {0};
    Base64::Encode(reinterpret_cast<const char *>(timestampReqData),timestampReqDataLen,base64,2048);
    std::cout<<base64<<std::endl;
    std::cout << "\ttimestampReqDataLen: " << timestampReqDataLen << std::endl;
  } else {
    printf("STF_CreateTSRequest: %x\n",retcode);
  }

  //**************************************************************************
  timestampRespDataLen = sizeof(timestampRespData);
  memset(timestampRespData, 0, timestampRespDataLen);
  retcode = STF_CreateTSResponse(handle, timestampReqData, timestampReqDataLen,
                                 SGD_SHA256_RSA, timestampRespData,
                                 &timestampRespDataLen);
  if (retcode == STF_TS_OK) {
    std::cout << "STF_CreateTSResponse: OK" << std::endl;
//    for (size_t i = 0; i < timestampRespDataLen; i++) {
//      std::cout << timestampRespData[i];
//    }
//    std::cout << std::endl;
    char base64_resp[10920] = {0};
    Base64::Encode(reinterpret_cast<const char *>(timestampRespData),timestampRespDataLen,base64_resp,10920);
    std::cout<<base64_resp<<std::endl;
  } else {
    std::cout << "STF_CreateTSResponse: " << retcode << std::endl;
  }

  //  //**************************************************************************
  retcode =
      STF_VerifyTSValidity(handle, timestampRespData, timestampRespDataLen,
                           SGD_SHA256, SGD_SHA256_RSA, NULL, 0);
  if (retcode == STF_TS_OK) {
    std::cout << "STF_VerifyTSValidity: OK" << std::endl;

  } else {
    printf("STF_VerifyTSValidity: %x\n",retcode);
  }

  //  //**************************************************************************

  issuerNameLen = sizeof(issuerName);
  memset(issuerName, 0, issuerNameLen);
  timeDataLen = sizeof(timeData);
  memset(timeData, 0, timeDataLen);
  retcode = STF_GetTSInfo(handle, timestampRespData, timestampRespDataLen,
                          issuerName, &issuerNameLen, timeData, &timeDataLen);
  if (retcode == STF_TS_OK) {
    std::cout << "STF_GetTSInfo: OK" << std::endl;
    for (size_t i = 0; i < issuerNameLen; i++) {
      std::cout << issuerName[i];
    }
    std::cout << std::endl;
    for (size_t i = 0; i < timeDataLen; i++) {
      std::cout << timeData[i];
    }
    std::cout << std::endl;
  } else {
    printf("STF_GetTSInfo: %x\n",retcode);
  }

  //  //**************************************************************************
  timeDataLen = sizeof(timeData);
  memset(timeData, 0, timeDataLen);
  retcode = STF_GetTSDetail(handle, timestampRespData, timestampRespDataLen,
                            STF_CN_OF_TSSIGNER, itemData, &itemDataLen);
  if (retcode == STF_TS_OK) {
    std::cout << "STF_GetTSDetail: OK" << std::endl;
    for (size_t i = 0; i < itemDataLen; i++) {
      std::cout << itemData[i];
      //printf("%x",itemData[i]);
    }
    std::cout << std::endl;

  } else {
    printf("STF_GetTSDetail: %x\n",retcode);
  }

  //**************************************************************************
  retcode = STF_ClearEnvironment(handle);
  if (retcode == STF_TS_OK) {
    std::cout << "STF_ClearEnvironment: OK" << std::endl;
  } else {
    printf("STF_ClearEnvironment: %x\n",retcode);
  }
}
