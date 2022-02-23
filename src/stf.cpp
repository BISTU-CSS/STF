#include "stf.h"
#include "openssl/ossl_typ.h"
#include "openssl/pkcs7.h"
#include "openssl/x509v3.h"
#include "openssl/ts.h"

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

struct TS_msg_imprint_st {
  X509_ALGOR *hash_algo;
  ASN1_OCTET_STRING *hashed_msg;
};
/*-
 * TimeStampReq ::= SEQUENCE  {
 *    version                  INTEGER  { v1(1) },
 *    messageImprint           MessageImprint,
 *      --a hash algorithm OID and the hash value of the data to be
 *      --time-stamped
 *    reqPolicy                TSAPolicyId                OPTIONAL,
 *    nonce                    INTEGER                    OPTIONAL,
 *    certReq                  BOOLEAN                    DEFAULT FALSE,
 *    extensions               [0] IMPLICIT Extensions    OPTIONAL  }
 */
struct TS_req_st {
  ASN1_INTEGER *version;
  TS_msg_imprint_st *msg_imprint;
  ASN1_OBJECT *policy_id;
  ASN1_INTEGER *nonce;
  ASN1_BOOLEAN cert_req;
  STACK_OF(X509_EXTENSION) *extensions;
};


struct TS_status_info_st {
  ASN1_INTEGER *status;
  STACK_OF(ASN1_UTF8STRING) *text;
  ASN1_BIT_STRING *failure_info;
};



/*-
 * TimeStampResp ::= SEQUENCE  {
 *     status                  PKIStatusInfo,
 *     timeStampToken          TimeStampToken     OPTIONAL }
 */
struct TS_resp_st {
  TS_status_info_st *status;
  PKCS7 *token;
  TS_TST_INFO *tst_info;
};


/*-
 * Accuracy ::= SEQUENCE {
 *                 seconds        INTEGER           OPTIONAL,
 *                 millis     [0] INTEGER  (1..999) OPTIONAL,
 *                 micros     [1] INTEGER  (1..999) OPTIONAL  }
 */
struct TS_accuracy_st {
  ASN1_INTEGER *seconds;
  ASN1_INTEGER *millis;
  ASN1_INTEGER *micros;
};

/*-
 * TSTInfo ::= SEQUENCE  {
 *     version                      INTEGER  { v1(1) },
 *     policy                       TSAPolicyId,
 *     messageImprint               MessageImprint,
 *       -- MUST have the same value as the similar field in
 *       -- TimeStampReq
 *     serialNumber                 INTEGER,
 *      -- Time-Stamping users MUST be ready to accommodate integers
 *      -- up to 160 bits.
 *     genTime                      GeneralizedTime,
 *     accuracy                     Accuracy                 OPTIONAL,
 *     ordering                     BOOLEAN             DEFAULT FALSE,
 *     nonce                        INTEGER                  OPTIONAL,
 *       -- MUST be present if the similar field was present
 *       -- in TimeStampReq.  In that case it MUST have the same value.
 *     tsa                          [0] GeneralName          OPTIONAL,
 *     extensions                   [1] IMPLICIT Extensions  OPTIONAL   }
 */
struct TS_tst_info_st {
  ASN1_INTEGER *version;
  ASN1_OBJECT *policy_id;
  TS_msg_imprint_st *msg_imprint;
  ASN1_INTEGER *serial;
  ASN1_GENERALIZEDTIME *time;
  TS_accuracy_st *accuracy;
  ASN1_BOOLEAN ordering;
  ASN1_INTEGER *nonce;
  GENERAL_NAME *tsa;
  STACK_OF(X509_EXTENSION) *extensions;
};
