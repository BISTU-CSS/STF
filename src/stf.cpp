#include "stf.h"

#include "fmt/os.h"
#include "openssl/ossl_typ.h"
#include "openssl/pkcs7.h"
#include "openssl/ts.h"
#include "openssl/x509v3.h"

#include <fstream>
#include <regex>

#include "grpc_cs/greeter_client.h"

#define UNUSED __attribute__((unused))

std::string ndsec_tsa_config;

bool load_config() {
  if (ndsec_tsa_config.empty()) {
    std::ifstream config_file("NdsecTsaConfig.ini");
    std::string temp;
    if (!config_file.is_open()) {
      return false;
    }
    std::regex ip_pattern("ip=(.*)");
    std::regex port_pattern("port=(.*)");
    std::string ip;
    std::string port;
    while (getline(config_file, temp)) {
      std::smatch results;
      int count = 0;
      if (regex_match(temp, results, ip_pattern)) {
        for (const auto &result : results) {
          if (count == 0) {
            count++;
            continue;
          }
          ip = result;
        }
      } else if (regex_match(temp, results, port_pattern)) {
        for (const auto &result : results) {
          if (count == 0) {
            count++;
            continue;
          }
          port = result;
        }
      }
    }
    ndsec_tsa_config = fmt::format("{}:{}", ip, port);
    config_file.close();
  }
  return true;
}

InitEnvironmentOutput TimeStampClient::InitEnvironment() {
  InitEnvironmentInput request;
  InitEnvironmentOutput reply;

  grpc::ClientContext context;
  grpc::Status status = stub_->InitEnvironment(&context, request, &reply);
  return reply;
}
SGD_UINT32 STF_InitEnvironment(void **phTSHandle) {
  if (!load_config()) {
    return STF_TS_CONFIG_ERROR;
  }
  TimeStampClient greeter(grpc::CreateChannel(
      ndsec_tsa_config, grpc::InsecureChannelCredentials()));
  InitEnvironmentOutput res = greeter.InitEnvironment();
  if (res.code() != timestamp::GRPC_STF_TS_OK) {
    return res.code();
  }
  *phTSHandle = new uint64_t(res.handle().session_id());
  return STF_TS_OK;
}

ClearEnvironmentOutput
TimeStampClient::ClearEnvironment(const ClearEnvironmentInput &request) {
  ClearEnvironmentOutput reply;
  grpc::ClientContext context;
  grpc::Status status = stub_->ClearEnvironment(&context, request, &reply);
  return reply;
}
SGD_UINT32 STF_ClearEnvironment(void *hTSHandle) {
  if (!load_config()) {
    return STF_TS_CONFIG_ERROR;
  }
  TimeStampClient greeter(grpc::CreateChannel(
      ndsec_tsa_config, grpc::InsecureChannelCredentials()));
  ClearEnvironmentInput req_input;
  auto *handle = new timestamp::Handle;
  handle->set_session_id(*(uint64_t *)hTSHandle);
  req_input.set_allocated_handle(handle);
  ClearEnvironmentOutput res = greeter.ClearEnvironment(req_input);
  free(hTSHandle);
  return STF_TS_OK;
}

CreateTSRequestOutput
TimeStampClient::CreateTSRequest(const CreateTSRequestInput &request) {
  CreateTSRequestOutput reply;
  grpc::ClientContext context;
  grpc::Status status = stub_->CreateTSRequest(&context, request, &reply);
  return reply;
}
SGD_UINT32 STF_CreateTSRequest(void *hTSHandle, UNUSED SGD_UINT8 *pucInData,
                               UNUSED SGD_UINT32 uiInDataLength,
                               SGD_UINT32 uiReqType, UNUSED SGD_UINT8 *pucTSExt,
                               UNUSED SGD_UINT32 uiTSExtLength,
                               SGD_UINT32 uiHashAlgID,
                               UNUSED SGD_UINT8 *pucTSRequest,
                               UNUSED SGD_UINT32 *puiTSRequestLength) {
  if (!load_config()) {
    return STF_TS_CONFIG_ERROR;
  }
  if (!(uiHashAlgID == SGD_SHA256 || uiHashAlgID == SGD_SM3)) {
    return STF_TS_INVALID_ALG; //不支持的算法类型
  }
  if (!(uiReqType == 0 || uiHashAlgID == 1)) {
    return STF_TS_INVALID_REQUEST; //非法请求
  }
  if (pucInData == nullptr || uiInDataLength == 0) {
    return STF_TS_INVALID_DATAFORMAT; //数据格式错误
  }
  if (pucTSRequest == nullptr || puiTSRequestLength == nullptr) {
    return STF_TS_INVALID_DATAFORMAT; //数据格式错误
  }
  TimeStampClient greeter(grpc::CreateChannel(
      ndsec_tsa_config, grpc::InsecureChannelCredentials()));
  CreateTSRequestInput req_input;
  auto *handle = new timestamp::Handle;
  handle->set_session_id(*(uint64_t *)hTSHandle);
  req_input.set_allocated_handle(handle);

  CreateTSRequestOutput res = greeter.CreateTSRequest(req_input);
  if (res.code() != timestamp::GRPC_STF_TS_OK) {
    return res.code();
  }

  return STF_TS_OK;
}

CreateTSResponseOutput
TimeStampClient::CreateTSResponse(const CreateTSResponseInput &request) {
  CreateTSResponseOutput reply;
  grpc::ClientContext context;
  grpc::Status status = stub_->CreateTSResponse(&context, request, &reply);
  return reply;
}
SGD_UINT32 STF_CreateTSReponse(UNUSED void *hTSHandle,
                               UNUSED SGD_UINT8 *pucTSRequest,
                               UNUSED SGD_UINT32 uiTSRequestLength,
                               UNUSED SGD_UINT32 uiSignatureAlgID,
                               UNUSED SGD_UINT8 *pucTSResponse,
                               UNUSED SGD_UINT32 *puiTSResponseLength) {
  if (!load_config()) {
    return STF_TS_CONFIG_ERROR;
  }
  TimeStampClient greeter(grpc::CreateChannel(
      ndsec_tsa_config, grpc::InsecureChannelCredentials()));

  return STF_TS_OK;
}

VerifyTSValidityOutput
TimeStampClient::VerifyTSValidity(const VerifyTSValidityInput &request) {
  VerifyTSValidityOutput reply;
  grpc::ClientContext context;
  grpc::Status status = stub_->VerifyTSValidity(&context, request, &reply);
  return reply;
}
SGD_UINT32 STF_VerifyTSValidity(UNUSED void *hTSHandle,
                                UNUSED SGD_UINT8 *pucTSResponse,
                                UNUSED SGD_UINT32 uiTSResponseLength,
                                UNUSED SGD_UINT32 uiHashAlgID,
                                UNUSED SGD_UINT32 uiSignatureAlgID,
                                UNUSED SGD_UINT8 *pucTSCert,
                                UNUSED SGD_UINT32 uiTSCertLength) {
  if (!load_config()) {
    return STF_TS_CONFIG_ERROR;
  }
  TimeStampClient greeter(grpc::CreateChannel(
      ndsec_tsa_config, grpc::InsecureChannelCredentials()));

  return STF_TS_OK;
}

GetTSInfoOutput TimeStampClient::GetTSInfo(const GetTSInfoInput &request) {
  GetTSInfoOutput reply;
  grpc::ClientContext context;
  grpc::Status status = stub_->GetTSInfo(&context, request, &reply);
  return reply;
}
SGD_UINT32 STF_GetTSInfo(UNUSED void *hTSHandle,
                         UNUSED SGD_UINT8 *pucTSResponse,
                         UNUSED SGD_UINT32 uiTSResponseLength,
                         UNUSED SGD_UINT8 *pucIssuerName,
                         UNUSED SGD_UINT32 *puiIssuerNameLength,
                         UNUSED SGD_UINT8 *pucTime,
                         UNUSED SGD_UINT32 *puiTimeLength) {
  if (!load_config()) {
    return STF_TS_CONFIG_ERROR;
  }
  TimeStampClient greeter(grpc::CreateChannel(
      ndsec_tsa_config, grpc::InsecureChannelCredentials()));

  return STF_TS_OK;
}

GetTSDetailOutput TimeStampClient::GetTSInfo(const GetTSDetailInput &request) {
  GetTSDetailOutput reply;
  grpc::ClientContext context;
  grpc::Status status = stub_->GetTSDetail(&context, request, &reply);
  return reply;
}
SGD_UINT32 STF_GetTSDetail(UNUSED void *hTSHandle,
                           UNUSED SGD_UINT8 *pucTSResponse,
                           UNUSED SGD_UINT32 uiTSResponseLength,
                           UNUSED SGD_UINT32 uiItemnumber,
                           UNUSED SGD_UINT8 *pucItemValue,
                           UNUSED SGD_UINT32 *puiItemValueLength) {
  if (!load_config()) {
    return STF_TS_CONFIG_ERROR;
  }
  TimeStampClient greeter(grpc::CreateChannel(
      ndsec_tsa_config, grpc::InsecureChannelCredentials()));

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
  STACK_OF(X509_EXTENSION) * extensions;
};

struct TS_status_info_st {
  ASN1_INTEGER *status;
  STACK_OF(ASN1_UTF8STRING) * text;
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
  STACK_OF(X509_EXTENSION) * extensions;
};
