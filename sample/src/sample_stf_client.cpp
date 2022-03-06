#include <cstring>
#include <iostream>

#include "stf.h"

#define UNUSED __attribute__((unused))

int main(UNUSED int argc, UNUSED char *argv[]) {
  void *handle;

  unsigned char timestampReqData[2048] = {0};
  unsigned int timestampReqDataLen = sizeof(timestampReqData);
  unsigned char timestampRespData[4096] = {0};
  unsigned int timestampRespDataLen = sizeof(timestampRespData);
  char TSACertData[2048] = {0};
  int TSACertDataLen = sizeof(TSACertData);

  unsigned char issuerName[2048] = {0};
  unsigned int issuerNameLen = sizeof(issuerName);
  unsigned char timeData[2048] = {0};
  unsigned int timeDataLen = sizeof(timeData);
  unsigned char itemData[2048] = {0};
  unsigned int itemDataLen = sizeof(itemData);

  const char *plainData = "test plain data";
  unsigned int plainDataLen = (unsigned int)strlen(plainData);

  SGD_UINT32 retcode = STF_InitEnvironment(&handle);
  std::cout << "STF_InitEnvironment: " << retcode << std::endl;

  timestampReqDataLen = sizeof(timestampReqData);
  memset(timestampReqData, 0, timestampReqDataLen);
  retcode = STF_CreateTSRequest(handle, (unsigned char *)plainData,
                                plainDataLen, 0, NULL, 0, SGD_SM3,
                                timestampReqData, &timestampReqDataLen);
  std::cout << "STF_CreateTSRequest: " << retcode << std::endl;



  retcode = STF_ClearEnvironment(handle);
  std::cout << "STF_ClearEnvironment: " << retcode << std::endl;
}
