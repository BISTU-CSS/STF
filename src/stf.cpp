#include "stf.h"

#include <fstream>
#include <regex>

#include "fmt/os.h"

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
  // 基本检查
  if (!load_config()) {
    return STF_TS_CONFIG_ERROR;
  }
  //创建链接
  TimeStampClient greeter(grpc::CreateChannel(
      ndsec_tsa_config, grpc::InsecureChannelCredentials()));
  //调用服务器
  InitEnvironmentOutput res = greeter.InitEnvironment();
  if (res.code() == GRPC_STF_TS_LINK_FAILED) {
    return STF_TS_SERVER_ERROR; //连接服务器错误
  } else if (res.code() != timestamp::GRPC_STF_TS_OK) {
    return res.code();
  }
  //正常情况
  *phTSHandle = new uint64_t(res.handle().session_id());
  return STF_TS_OK;
}

ClearEnvironmentOutput
TimeStampClient::ClearEnvironment(ClearEnvironmentInput request) {
  ClearEnvironmentOutput reply;
  grpc::ClientContext context;
  grpc::Status status = stub_->ClearEnvironment(&context, request, &reply);
  return reply;
}
SGD_UINT32 STF_ClearEnvironment(void *hTSHandle) {
  // 基本检查
  if (!load_config()) {
    return STF_TS_CONFIG_ERROR;
  }
  if (hTSHandle == nullptr) {
    return STF_TS_INVALID_REQUEST; //非法请求
  }
  //创建链接
  TimeStampClient greeter(grpc::CreateChannel(
      ndsec_tsa_config, grpc::InsecureChannelCredentials()));
  //设置向服务器传入的参数
  ClearEnvironmentInput req_input;
  auto *handle = new timestamp::Handle;
  handle->set_session_id(*(uint64_t *)hTSHandle);
  req_input.set_allocated_handle(handle);
  //调用服务器
  ClearEnvironmentOutput res = greeter.ClearEnvironment(req_input);
  if (res.code() == GRPC_STF_TS_LINK_FAILED) {
    return STF_TS_SERVER_ERROR; //连接服务器错误
  } else if (res.code() != timestamp::GRPC_STF_TS_OK) {
    return res.code();
  }
  //正常情况
  free(hTSHandle);

  return STF_TS_OK;
}

CreateTSRequestOutput
TimeStampClient::CreateTSRequest(CreateTSRequestInput request) {
  CreateTSRequestOutput reply;
  grpc::ClientContext context;
  grpc::Status status = stub_->CreateTSRequest(&context, request, &reply);
  return reply;
}
SGD_UINT32 STF_CreateTSRequest(void *hTSHandle, SGD_UINT8 *pucInData,
                               SGD_UINT32 uiInDataLength, SGD_UINT32 uiReqType,
                               SGD_UINT8 *pucTSExt, SGD_UINT32 uiTSExtLength,
                               SGD_UINT32 uiHashAlgID, SGD_UINT8 *pucTSRequest,
                               SGD_UINT32 *puiTSRequestLength) {
  // 基本检查
  if (!load_config()) {
    return STF_TS_CONFIG_ERROR;
  }
  if (hTSHandle == nullptr) {
    return STF_TS_INVALID_REQUEST; //非法请求
  }
  if (!(uiHashAlgID == SGD_SHA256 || uiHashAlgID == SGD_SM3 ||
        uiHashAlgID == SGD_SHA1)) {
    return STF_TS_INVALID_ALG; //不支持的算法类型
  }
  if (!(uiReqType == 0 || uiReqType == 1)) {
    return STF_TS_INVALID_REQUEST; //非法请求
  }
  if (pucInData == nullptr || uiInDataLength == 0) {
    return STF_TS_INVALID_DATAFORMAT; //数据格式错误
  }
  if (pucTSRequest == nullptr || puiTSRequestLength == nullptr) {
    return STF_TS_INVALID_DATAFORMAT; //数据格式错误
  }
  if (pucTSExt != nullptr || uiTSExtLength != 0) {
    return STF_TS_UNACCEPTED_EXTENSION;
  }
  //创建链接
  TimeStampClient greeter(grpc::CreateChannel(
      ndsec_tsa_config, grpc::InsecureChannelCredentials()));
  //设置向服务器传入的参数
  CreateTSRequestInput req_input;
  auto *handle = new timestamp::Handle;
  handle->set_session_id(*(uint64_t *)hTSHandle);
  req_input.set_allocated_handle(handle);
  req_input.set_uireqtype(uiReqType);
  req_input.set_uihashalgid(uiHashAlgID);
  std::string indata_tmp_string;
  indata_tmp_string.resize(uiInDataLength);
  for (size_t i = 0; i < uiInDataLength; i++) {
    indata_tmp_string[i] = pucInData[i];
  }
  req_input.set_pucindata(indata_tmp_string);
  req_input.set_uiindatalength(uiInDataLength);
  //调用服务器
  CreateTSRequestOutput res = greeter.CreateTSRequest(req_input);
  if (res.code() == GRPC_STF_TS_LINK_FAILED) {
    return STF_TS_SERVER_ERROR; //连接服务器错误
  } else if (res.code() != timestamp::GRPC_STF_TS_OK) {
    return res.code(); //出现错误服务器的错误码
  }

  //连接服务器成功
  if (res.puctsrequestlength() <=
      reinterpret_cast<size_t>(puiTSRequestLength)) {
    //缓冲区正常
    *puiTSRequestLength = res.puctsrequestlength();
    memcpy(pucTSRequest, res.puctsrequest().data(), res.puctsrequestlength());
  } else {
    return STF_TS_NOT_ENOUGH_MEMORY; //缓冲区错误（特殊TS）
  }
  return STF_TS_OK;
}

CreateTSResponseOutput
TimeStampClient::CreateTSResponse(CreateTSResponseInput request) {
  CreateTSResponseOutput reply;
  grpc::ClientContext context;
  grpc::Status status = stub_->CreateTSResponse(&context, request, &reply);
  return reply;
}
SGD_UINT32 STF_CreateTSResponse(void *hTSHandle, SGD_UINT8 *pucTSRequest,
                                SGD_UINT32 uiTSRequestLength,
                                SGD_UINT32 uiSignatureAlgID,
                                SGD_UINT8 *pucTSResponse,
                                SGD_UINT32 *puiTSResponseLength) {
  // 基本检查
  if (!load_config()) {
    return STF_TS_CONFIG_ERROR;
  }
  if (hTSHandle == nullptr) {
    return STF_TS_INVALID_REQUEST; //非法请求
  }
  if (pucTSRequest == nullptr || uiTSRequestLength == 0) {
    return STF_TS_INVALID_DATAFORMAT; //数据格式错误
  }
  if (pucTSResponse == nullptr || puiTSResponseLength == nullptr) {
    return STF_TS_INVALID_DATAFORMAT; //数据格式错误
  }
  if (!(uiSignatureAlgID == SGD_SM3_SM2 || uiSignatureAlgID == SGD_SM3_RSA ||
        uiSignatureAlgID == SGD_SHA1_RSA ||
        uiSignatureAlgID == SGD_SHA256_RSA)) {
    return STF_TS_INVALID_ALG; //不支持的算法类型
  }
  //创建链接
  TimeStampClient greeter(grpc::CreateChannel(
      ndsec_tsa_config, grpc::InsecureChannelCredentials()));
  //设置向服务器传入的参数
  CreateTSResponseInput req_input;
  auto *handle = new timestamp::Handle;
  handle->set_session_id(*(uint64_t *)hTSHandle);
  req_input.set_allocated_handle(handle);
  std::string request_tmp_string;
  request_tmp_string.resize(uiTSRequestLength);
  for (size_t i = 0; i < uiTSRequestLength; i++) {
    request_tmp_string[i] = pucTSRequest[i];
  }
  req_input.set_puctsresquest(request_tmp_string);
  req_input.set_uitsrequestlength(uiTSRequestLength);
  req_input.set_uisignaturealgid(uiSignatureAlgID);
  //调用服务器
  CreateTSResponseOutput res = greeter.CreateTSResponse(req_input);
  if (res.code() == GRPC_STF_TS_LINK_FAILED) {
    return STF_TS_SERVER_ERROR; //连接服务器错误
  } else if (res.code() != timestamp::GRPC_STF_TS_OK) {
    return res.code();
  }
  //连接服务器成功
  if (res.puitsresponselength() <=
      reinterpret_cast<size_t>(puiTSResponseLength)) {
    //缓冲区正常
    *puiTSResponseLength = res.puitsresponselength();
    memcpy(pucTSRequest, res.puitsresponse().data(), res.puitsresponselength());
  } else {
    return STF_TS_NOT_ENOUGH_BUFFER; //缓冲区错误
  }
  return STF_TS_OK;
}

VerifyTSValidityOutput
TimeStampClient::VerifyTSValidity(VerifyTSValidityInput request) {
  VerifyTSValidityOutput reply;
  grpc::ClientContext context;
  grpc::Status status = stub_->VerifyTSValidity(&context, request, &reply);
  return reply;
}
SGD_UINT32 STF_VerifyTSValidity(void *hTSHandle, SGD_UINT8 *pucTSResponse,
                                SGD_UINT32 uiTSResponseLength,
                                SGD_UINT32 uiHashAlgID,
                                SGD_UINT32 uiSignatureAlgID,
                                SGD_UINT8 *pucTSCert,
                                SGD_UINT32 uiTSCertLength) {
  if (!load_config()) {
    return STF_TS_CONFIG_ERROR;
  }
  // 基本检查
  if (hTSHandle == nullptr) {
    return STF_TS_INVALID_REQUEST; //非法请求
  }
  if (!(uiHashAlgID == SGD_SHA256 || uiHashAlgID == SGD_SM3 ||
        uiHashAlgID == SGD_SHA1)) {
    return STF_TS_INVALID_ALG; //不支持的算法类型
  }
  if (!(uiSignatureAlgID == SGD_SM3_SM2 || uiSignatureAlgID == SGD_SM3_RSA ||
        uiSignatureAlgID == SGD_SHA1_RSA ||
        uiSignatureAlgID == SGD_SHA256_RSA)) {
    return STF_TS_INVALID_ALG; //不支持的算法类型
  }
  if (pucTSResponse == nullptr || uiTSResponseLength == 0) {
    return STF_TS_INVALID_DATAFORMAT; //数据格式错误
  }
  //创建链接
  TimeStampClient greeter(grpc::CreateChannel(
      ndsec_tsa_config, grpc::InsecureChannelCredentials()));
  //设置向服务器传入的参数
  VerifyTSValidityInput req_input;
  auto *handle = new timestamp::Handle;
  handle->set_session_id(*(uint64_t *)hTSHandle);
  req_input.set_allocated_handle(handle);
  req_input.set_uisignaturealgid(uiSignatureAlgID);
  req_input.set_uihashalgid(uiHashAlgID);
  std::string response_tmp_string;
  response_tmp_string.resize(uiTSResponseLength);
  for (size_t i = 0; i < uiTSResponseLength; i++) {
    response_tmp_string[i] = pucTSResponse[i];
  }
  req_input.set_puctsresponse(response_tmp_string);
  req_input.set_uitsresponselength(uiTSResponseLength);
  std::string cert_tmp_string;
  cert_tmp_string.resize(uiTSCertLength);
  for (size_t i = 0; i < uiTSCertLength; i++) {
    cert_tmp_string[i] = pucTSCert[i];
  }
  req_input.set_puctscert(cert_tmp_string);
  req_input.set_uitscertlength(uiTSCertLength);
  //调用服务器
  VerifyTSValidityOutput res = greeter.VerifyTSValidity(req_input);
  if (res.code() == GRPC_STF_TS_LINK_FAILED) {
    return STF_TS_SERVER_ERROR; //连接服务器错误
  } else if (res.code() == timestamp::GRPC_STF_TS_OK) {
    //连接服务器成功 + 验证成功
    return STF_TS_OK;
  } else {
    return res.code(); //出现错误，返回错误码
  }
}

GetTSInfoOutput TimeStampClient::GetTSInfo(GetTSInfoInput request) {
  GetTSInfoOutput reply;
  grpc::ClientContext context;
  grpc::Status status = stub_->GetTSInfo(&context, request, &reply);
  return reply;
}
SGD_UINT32 STF_GetTSInfo(void *hTSHandle, SGD_UINT8 *pucTSResponse,
                         SGD_UINT32 uiTSResponseLength,
                         SGD_UINT8 *pucIssuerName,
                         SGD_UINT32 *puiIssuerNameLength, SGD_UINT8 *pucTime,
                         SGD_UINT32 *puiTimeLength) {
  if (!load_config()) {
    return STF_TS_CONFIG_ERROR;
  }
  // 基本检查
  if (hTSHandle == nullptr) {
    return STF_TS_INVALID_REQUEST; //非法请求
  }
  if (pucTSResponse == nullptr || uiTSResponseLength == 0) {
    return STF_TS_INVALID_DATAFORMAT; //数据格式错误
  }
  if (pucIssuerName == nullptr || puiIssuerNameLength == nullptr) {
    return STF_TS_INVALID_DATAFORMAT; //数据格式错误
  }
  if (pucTime == nullptr || puiTimeLength == nullptr) {
    return STF_TS_INVALID_DATAFORMAT; //数据格式错误
  }
  //创建链接
  TimeStampClient greeter(grpc::CreateChannel(
      ndsec_tsa_config, grpc::InsecureChannelCredentials()));
  //设置向服务器传入的参数
  GetTSInfoInput req_input;
  auto *handle = new timestamp::Handle;
  handle->set_session_id(*(uint64_t *)hTSHandle);
  req_input.set_allocated_handle(handle);
  std::string response_tmp_string;
  response_tmp_string.resize(uiTSResponseLength);
  for (size_t i = 0; i < uiTSResponseLength; i++) {
    response_tmp_string[i] = pucTSResponse[i];
  }
  req_input.set_puctsresponse(response_tmp_string);
  req_input.set_uitsresponselength(uiTSResponseLength);
  GetTSInfoOutput res = greeter.GetTSInfo(req_input);
  if (res.code() == GRPC_STF_TS_LINK_FAILED) {
    return STF_TS_SERVER_ERROR; //连接服务器错误
  } else if (res.code() != timestamp::GRPC_STF_TS_OK) {
    return res.code();
  }

  //连接服务器成功
  if (res.puiissuernamelength() <=
      reinterpret_cast<size_t>(puiIssuerNameLength)) {
    *puiIssuerNameLength = res.puiissuernamelength();
    memcpy(pucIssuerName, res.pucissuername().data(),
           res.puiissuernamelength());
  } else {
    return STF_TS_NOT_ENOUGH_BUFFER; //缓冲区错误
  }

  if (res.puitimelength() <= reinterpret_cast<size_t>(puiTimeLength)) {
    *puiTimeLength = res.puitimelength();
    memcpy(pucTime, res.puctime().data(), res.puitimelength());
  } else {
    return STF_TS_NOT_ENOUGH_BUFFER; //缓冲区错误
  }
  return STF_TS_OK;
}

GetTSDetailOutput TimeStampClient::GetTSDetail(GetTSDetailInput request) {
  GetTSDetailOutput reply;
  grpc::ClientContext context;
  grpc::Status status = stub_->GetTSDetail(&context, request, &reply);
  return reply;
}
SGD_UINT32 STF_GetTSDetail(void *hTSHandle, SGD_UINT8 *pucTSResponse,
                           SGD_UINT32 uiTSResponseLength,
                           SGD_UINT32 uiItemNumber, SGD_UINT8 *pucItemValue,
                           SGD_UINT32 *puiItemValueLength) {
  if (!load_config()) {
    return STF_TS_CONFIG_ERROR;
  }
  // 基本检查
  if (hTSHandle == nullptr) {
    return STF_TS_INVALID_REQUEST; //非法请求
  }
  if (pucTSResponse == nullptr || uiTSResponseLength == 0) {
    return STF_TS_INVALID_DATAFORMAT; //数据格式错误
  }
  if (pucItemValue == nullptr || puiItemValueLength == nullptr) {
    return STF_TS_INVALID_DATAFORMAT; //数据格式错误
  }
  switch (uiItemNumber) {
  case STF_TIME_OF_STAMP:
  case STF_CN_OF_TSSIGNER:
  case STF_ORIGINAL_DATA:
  case STF_CERT_OF_TSSERVER:
  case STF_CERTCHAIN_OF_TSSERVER:
  case STF_SOURCE_OF_TIME:
  case STF_TIME_PRECISION:
  case STF_RESPONSE_TYPE:
  case STF_SUBJECT_COUNTRY_OF_TSSIGNER:
  case STF_SUBJECT_ORGNIZATION_OF_TSSIGNER:
  case STF_SUBJECT_CITY_OF_TSSIGNER:
  case STF_SUBJECT_EMAIL_OF_TSSIGNER:
    break;
  default:
    return STF_TS_INVALID_ITEM; //输人项目编号无效
  }
  //创建链接
  TimeStampClient greeter(grpc::CreateChannel(
      ndsec_tsa_config, grpc::InsecureChannelCredentials()));
  //设置向服务器传入的参数
  GetTSDetailInput req_input;
  auto *handle = new timestamp::Handle;
  handle->set_session_id(*(uint64_t *)hTSHandle);
  req_input.set_allocated_handle(handle);

  req_input.set_uiitemnumber(uiItemNumber);
  std::string response_tmp_string;
  response_tmp_string.resize(uiTSResponseLength);
  for (size_t i = 0; i < uiTSResponseLength; i++) {
    response_tmp_string[i] = pucTSResponse[i];
  }
  req_input.set_puctsresponse(response_tmp_string);
  req_input.set_uitsresponselength(uiTSResponseLength);
  //调用服务器
  GetTSDetailOutput res = greeter.GetTSDetail(req_input);
  if (res.code() == GRPC_STF_TS_LINK_FAILED) {
    return STF_TS_SERVER_ERROR; //连接服务器错误
  } else if (res.code() != timestamp::GRPC_STF_TS_OK) {
    return res.code();
  }
  //连接服务器成功
  if (res.puiitemvaluelength() <=
      reinterpret_cast<size_t>(puiItemValueLength)) {
    *puiItemValueLength = res.puiitemvaluelength();
    memcpy(pucItemValue, res.puiitemvalue().data(), res.puiitemvaluelength());
  } else {
    return STF_TS_NOT_ENOUGH_BUFFER; //缓冲区错误
  }
  return STF_TS_OK;
}
