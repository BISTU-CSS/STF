#include <cstring>
#include <iostream>

#include "stf.h"

#define UNUSED __attribute__((unused))

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
  UNUSED unsigned int plainDataLen = (unsigned int)strlen(plainData);

  //**************************************************************************
  SGD_UINT32 retcode = STF_InitEnvironment(&handle);
  if (retcode == STF_TS_OK) {
    std::cout << "STF_InitEnvironment: OK" << std::endl;
  } else {
    std::cout << "STF_InitEnvironment: " << retcode << std::endl;
  }

  //**************************************************************************
  timestampReqDataLen = sizeof(timestampReqData);
  memset(timestampReqData, 0, timestampReqDataLen);
  retcode = STF_CreateTSRequest(handle, (unsigned char *)plainData,
                                plainDataLen, 0, NULL, 0, SGD_SM3,
                                timestampReqData, &timestampReqDataLen);
  if (retcode == STF_TS_OK) {
    std::cout << "STF_CreateTSRequest: OK" << std::endl;
    std::cout << "\ttimestampReqData: " << timestampReqData << std::endl;
    std::cout << "\ttimestampReqDataLen: " << timestampReqDataLen << std::endl;
  } else {
    std::cout << "STF_CreateTSRequest: " << retcode << std::endl;
  }

  //**************************************************************************
  //  timestampRespDataLen = sizeof(timestampRespData);
  //  memset(timestampRespData, 0, timestampRespDataLen);
  //  retcode = STF_CreateTSResponse(handle, timestampReqData,
  //  timestampReqDataLen,
  //                                 SGD_SM3_SM2, timestampRespData,
  //                                 &timestampRespDataLen);
  //  if (retcode == STF_TS_OK) {
  //    std::cout << "STF_CreateTSResponse: OK" << std::endl;
  //
  //  } else {
  //    std::cout << "STF_CreateTSResponse: " << retcode << std::endl;
  //  }
  //
  //  //**************************************************************************
  //  retcode =
  //      STF_VerifyTSValidity(handle, timestampRespData, timestampRespDataLen,
  //                           SGD_SM3, SGD_SM3_SM2, NULL, 0);
  //  if (retcode == STF_TS_OK) {
  //    std::cout << "STF_VerifyTSValidity: OK" << std::endl;
  //
  //  } else {
  //    std::cout << "STF_VerifyTSValidity: " << retcode << std::endl;
  //  }
  //
  //  //**************************************************************************
  //
  //  issuerNameLen = sizeof(issuerName);
  //  memset(issuerName, 0, issuerNameLen);
  //  timeDataLen = sizeof(timeData);
  //  memset(timeData, 0, timeDataLen);
  //  retcode = STF_GetTSInfo(handle, timestampRespData, timestampRespDataLen,
  //                          issuerName, &issuerNameLen, timeData,
  //                          &timeDataLen);
  //  if (retcode == STF_TS_OK) {
  //    std::cout << "STF_GetTSInfo: OK" << std::endl;
  //  } else {
  //    std::cout << "STF_GetTSInfo: " << retcode << std::endl;
  //  }
  //
  //  //**************************************************************************
  //  timeDataLen = sizeof(timeData);
  //  memset(timeData, 0, timeDataLen);
  retcode = STF_GetTSDetail(handle, timestampRespData, timestampRespDataLen,
                            STF_TIME_OF_STAMP, itemData, &itemDataLen);
  if (retcode == STF_TS_OK) {
    std::cout << "STF_GetTSDetail: OK" << std::endl;
  } else {
    std::cout << "STF_GetTSDetail: " << retcode << std::endl;
  }

  //**************************************************************************
  retcode = STF_ClearEnvironment(handle);
  if (retcode == STF_TS_OK) {
    std::cout << "STF_ClearEnvironment: OK" << std::endl;
  } else {
    std::cout << "STF_ClearEnvironment: " << retcode << std::endl;
  }
}
