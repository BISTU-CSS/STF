#include "stf.h"

SGD_UINT32 STF_InitEnvironment(void **phTSHandle) { return STF_TS_OK; }

SGD_UINT32 STF_ClearEnvironment(void *hTSHandle) { return STF_TS_OK; }

SGD_UINT32 STF_CreateTSRequest(void *hTSHandle, SGD_UINT8 *pucInData,
                               SGD_UINT32 uiInDataLength, SGD_UINT32 uiReqType,
                               SGD_UINT8 *pucTSExt, SGD_UINT32 uiHashAlgID,
                               SGD_UINT8 *pucTSRequest,
                               SGD_UINT32 *puiTSRequestLength) {
  return STF_TS_OK;
}

SGD_UINT32 STF_CreateTSReponse(void *hTSHandle, SGD_UINT8 *pucTSRequest,
                               SGD_UINT32 uiTSRequestLength,
                               SGD_UINT32 uiSignatureAlgID,
                               SGD_UINT8 *pucTSResponse,
                               SGD_UINT32 *puiTSResponseLength) {
  return STF_TS_OK;
}

SGD_UINT32 STF_VerifyTSValidity(void *hTSHandle, SGD_UINT8 *pucTSResponse,
                                SGD_UINT32 uiTSResponseLength,
                                SGD_UINT32 uiHashAlgID,
                                SGD_UINT32 uiSignatureAlgID,
                                SGD_UINT8 *pucTSCert,
                                SGD_UINT32 uiTSCertLength) {
  return STF_TS_OK;
}

SGD_UINT32 STF_GetTSInfo(void *hTSHandle, SGD_UINT8 *pucTSResponse,
                         SGD_UINT32 uiTSResponseLength,
                         SGD_UINT8 *pucIssuerName,
                         SGD_UINT32 *puiIssuerNameLength, SGD_UINT8 *pucTime,
                         SGD_UINT32 *puiTimeLength) {
  return STF_TS_OK;
}

SGD_UINT32 STF_GetTSDetail(void *hTSHandle, SGD_UINT8 *pucTSResponse,
                           SGD_UINT32 uiTSResponseLength,
                           SGD_UINT32 uiItemnumber, SGD_UINT8 *pucItemValue,
                           SGD_UINT32 *puiItemValueLength) {

  return STF_TS_OK;
}
