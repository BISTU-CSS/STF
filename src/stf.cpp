#include <fstream>
#include "stf.h"
#include "openssl/ossl_typ.h"
#include "openssl/pkcs7.h"
#include "openssl/x509v3.h"
#include "openssl/ts.h"

#include "grpc_cs/greeter_client.h"

#define UNUSED __attribute__((unused))

std::string ndsec_tsa_config;

bool load_config(){
    if(ndsec_tsa_config.empty()){
        std::ifstream config_file("NdsecTsaConfig.ini");
        std::string temp;
        if (!config_file.is_open()){
            return false;
        }
        while(getline(config_file,temp)){
            std::cout<<temp<<std::endl;
        }
        config_file.close();
    }
    // not empty
    return true;
}

InitEnvironmentOutput TimeStampClient::InitEnvironment() {
    timestamp::InitEnvironmentInput request;
    timestamp::InitEnvironmentOutput reply;
    grpc::ClientContext context;
    grpc::Status status = stub_->InitEnvironment(&context, request, &reply);
    return reply;
};
SGD_UINT32 STF_InitEnvironment(UNUSED void **phTSHandle) {
    if(load_config()){
        return STF_TS_CONFIG_ERROR;
    }
    /*
    TimeStampClient greeter(grpc::CreateChannel(
            ndsec_tsa_config, grpc::InsecureChannelCredentials()));
    InitEnvironmentOutput res = greeter.InitEnvironment();
    std::cout << "Status code: " <<  res.code() << std::endl;

    if(res.code() != timestamp::GRPC_STF_TS_OK){
        return res.code();
    }

    std::cout << "Status code: " <<  res.handle().session_id() << std::endl;
    */
    return STF_TS_OK;
}

SGD_UINT32 STF_ClearEnvironment(UNUSED void *hTSHandle) {
    load_config();

    return STF_TS_OK;
}

SGD_UINT32 STF_CreateTSRequest(UNUSED void *hTSHandle,UNUSED SGD_UINT8 *pucInData,
                               UNUSED SGD_UINT32 uiInDataLength,UNUSED SGD_UINT32 uiReqType,
                               UNUSED SGD_UINT8 *pucTSExt,UNUSED SGD_UINT32 uiHashAlgID,
                               UNUSED SGD_UINT8 *pucTSRequest,
                               UNUSED SGD_UINT32 *puiTSRequestLength) {
    load_config();
    return STF_TS_OK;
}

SGD_UINT32 STF_CreateTSReponse(UNUSED void *hTSHandle,UNUSED SGD_UINT8 *pucTSRequest,
                               UNUSED SGD_UINT32 uiTSRequestLength,
                               UNUSED SGD_UINT32 uiSignatureAlgID,
                               UNUSED SGD_UINT8 *pucTSResponse,
                               UNUSED SGD_UINT32 *puiTSResponseLength) {
    load_config();
    return STF_TS_OK;
}

SGD_UINT32 STF_VerifyTSValidity(UNUSED void *hTSHandle,UNUSED SGD_UINT8 *pucTSResponse,
                                UNUSED SGD_UINT32 uiTSResponseLength,
                                UNUSED SGD_UINT32 uiHashAlgID,
                                UNUSED SGD_UINT32 uiSignatureAlgID,
                                UNUSED SGD_UINT8 *pucTSCert,
                                UNUSED SGD_UINT32 uiTSCertLength) {
    load_config();
    return STF_TS_OK;
}

SGD_UINT32 STF_GetTSInfo(UNUSED void *hTSHandle,UNUSED SGD_UINT8 *pucTSResponse,
                         UNUSED SGD_UINT32 uiTSResponseLength,
                         UNUSED SGD_UINT8 *pucIssuerName,
                         UNUSED SGD_UINT32 *puiIssuerNameLength,UNUSED SGD_UINT8 *pucTime,
                         UNUSED SGD_UINT32 *puiTimeLength) {
    load_config();
    return STF_TS_OK;
}

SGD_UINT32 STF_GetTSDetail(UNUSED void *hTSHandle,UNUSED SGD_UINT8 *pucTSResponse,
                           UNUSED SGD_UINT32 uiTSResponseLength,
                           UNUSED SGD_UINT32 uiItemnumber, UNUSED SGD_UINT8 *pucItemValue,
                           UNUSED SGD_UINT32 *puiItemValueLength) {
    load_config();
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
