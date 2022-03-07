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
  TimeStampClient greeter(grpc::CreateChannel(
      ndsec_tsa_config, grpc::InsecureChannelCredentials()));
  InitEnvironmentOutput res = greeter.InitEnvironment();
  if(res.code() == GRPC_STF_TS_LINK_FAILED){
    return STF_TS_SERVER_ERROR;     //连接服务器错误
  }
  else if (res.code() != timestamp::GRPC_STF_TS_OK) {
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
  TimeStampClient greeter(grpc::CreateChannel(
      ndsec_tsa_config, grpc::InsecureChannelCredentials()));
  ClearEnvironmentInput req_input;
  auto *handle = new timestamp::Handle;
  handle->set_session_id(*(uint64_t *)hTSHandle);
  req_input.set_allocated_handle(handle);
  ClearEnvironmentOutput res = greeter.ClearEnvironment(req_input);
  if(res.code() == GRPC_STF_TS_LINK_FAILED){
    return STF_TS_SERVER_ERROR;     //连接服务器错误
  }
  else if (res.code() != timestamp::GRPC_STF_TS_OK) {
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
                               UNUSED SGD_UINT32 uiInDataLength,
                               SGD_UINT32 uiReqType, UNUSED SGD_UINT8 *pucTSExt,
                               UNUSED SGD_UINT32 uiTSExtLength,
                               SGD_UINT32 uiHashAlgID, SGD_UINT8 *pucTSRequest,
                               SGD_UINT32 *puiTSRequestLength) {
  // 基本检查
  if (!load_config()) {
    return STF_TS_CONFIG_ERROR;
  }
  if (hTSHandle == nullptr) {
    return STF_TS_INVALID_REQUEST; //非法请求
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
  auto prepare_buffer_length = reinterpret_cast<size_t>(puiTSRequestLength);
  TimeStampClient greeter(grpc::CreateChannel(
      ndsec_tsa_config, grpc::InsecureChannelCredentials()));
  CreateTSRequestInput req_input;
  auto *handle = new timestamp::Handle;
  handle->set_session_id(*(uint64_t *)hTSHandle);
  req_input.set_allocated_handle(handle);
  req_input.set_uireqtype(uiReqType);
  req_input.set_uihashalgid(uiHashAlgID);
  std::string tmp_indata = reinterpret_cast<const char *>(pucInData);
  req_input.set_pucindata(tmp_indata);
  req_input.set_uiindatalength(uiInDataLength);
  CreateTSRequestOutput res = greeter.CreateTSRequest(req_input);
  *puiTSRequestLength = res.puctsrequestlength();
  auto result_buffer = res.puctsrequest().c_str();

  if (strlen(result_buffer) <= prepare_buffer_length) {
    //缓冲区正常
    strcpy((char *)pucTSRequest, result_buffer);
  } else {
    //缓冲区错误
    return STF_TS_NOT_ENOUGH_MEMORY;
  }

  if(res.code() == GRPC_STF_TS_LINK_FAILED){
    return STF_TS_SERVER_ERROR;     //连接服务器错误
  }
  else if (res.code() != timestamp::GRPC_STF_TS_OK) {
    return res.code();
  }
  //正常情况

  return STF_TS_OK;
}

CreateTSResponseOutput
TimeStampClient::CreateTSResponse(CreateTSResponseInput request) {
  CreateTSResponseOutput reply;
  grpc::ClientContext context;
  grpc::Status status = stub_->CreateTSResponse(&context, request, &reply);
  return reply;
}
SGD_UINT32 STF_CreateTSResponse(void *hTSHandle, UNUSED SGD_UINT8 *pucTSRequest,
                               UNUSED SGD_UINT32 uiTSRequestLength,
                               UNUSED SGD_UINT32 uiSignatureAlgID,
                               UNUSED SGD_UINT8 *pucTSResponse,
                               UNUSED SGD_UINT32 *puiTSResponseLength) {
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
  CreateTSResponseInput req_input;
  auto *handle = new timestamp::Handle;
  handle->set_session_id(*(uint64_t *)hTSHandle);
  req_input.set_allocated_handle(handle);

  //发送，并获得结果
  CreateTSResponseOutput res = greeter.CreateTSResponse(req_input);
  if(res.code() == GRPC_STF_TS_LINK_FAILED){
    return STF_TS_SERVER_ERROR;   //连接服务器错误
  }
  else if (res.code() != timestamp::GRPC_STF_TS_OK) {
    return res.code();
  }
  //正常情况


  return STF_TS_OK;
}

VerifyTSValidityOutput
TimeStampClient::VerifyTSValidity(VerifyTSValidityInput request) {
  VerifyTSValidityOutput reply;
  grpc::ClientContext context;
  grpc::Status status = stub_->VerifyTSValidity(&context, request, &reply);
  return reply;
}
SGD_UINT32 STF_VerifyTSValidity(void *hTSHandle,
                                UNUSED SGD_UINT8 *pucTSResponse,
                                UNUSED SGD_UINT32 uiTSResponseLength,
                                UNUSED SGD_UINT32 uiHashAlgID,
                                UNUSED SGD_UINT32 uiSignatureAlgID,
                                UNUSED SGD_UINT8 *pucTSCert,
                                UNUSED SGD_UINT32 uiTSCertLength) {
  // 基本检查
  if (hTSHandle == nullptr) {
    return STF_TS_INVALID_REQUEST; //非法请求
  }
  if (!load_config()) {
    return STF_TS_CONFIG_ERROR;
  }
  TimeStampClient greeter(grpc::CreateChannel(
      ndsec_tsa_config, grpc::InsecureChannelCredentials()));

  VerifyTSValidityInput req_input;
  auto *handle = new timestamp::Handle;
  handle->set_session_id(*(uint64_t *)hTSHandle);
  req_input.set_allocated_handle(handle);

  VerifyTSValidityOutput res = greeter.VerifyTSValidity(req_input);
  if(res.code() == GRPC_STF_TS_LINK_FAILED){
    return STF_TS_SERVER_ERROR;//连接服务器错误
  }
  else if (res.code() != timestamp::GRPC_STF_TS_OK) {
    return res.code();
  }
  //正常情况


  return STF_TS_OK;
}

GetTSInfoOutput TimeStampClient::GetTSInfo(GetTSInfoInput request) {
  GetTSInfoOutput reply;
  grpc::ClientContext context;
  grpc::Status status = stub_->GetTSInfo(&context, request, &reply);
  return reply;
}
SGD_UINT32 STF_GetTSInfo(void *hTSHandle, UNUSED SGD_UINT8 *pucTSResponse,
                         UNUSED SGD_UINT32 uiTSResponseLength,
                         UNUSED SGD_UINT8 *pucIssuerName,
                         UNUSED SGD_UINT32 *puiIssuerNameLength,
                         UNUSED SGD_UINT8 *pucTime,
                         UNUSED SGD_UINT32 *puiTimeLength) {
  // 基本检查
  if (hTSHandle == nullptr) {
    return STF_TS_INVALID_REQUEST; //非法请求
  }
  if (!load_config()) {
    return STF_TS_CONFIG_ERROR;
  }
  TimeStampClient greeter(grpc::CreateChannel(
      ndsec_tsa_config, grpc::InsecureChannelCredentials()));

  GetTSInfoInput req_input;
  auto *handle = new timestamp::Handle;
  handle->set_session_id(*(uint64_t *)hTSHandle);
  req_input.set_allocated_handle(handle);

  GetTSInfoOutput res = greeter.GetTSInfo(req_input);
  if(res.code() == GRPC_STF_TS_LINK_FAILED){
    return STF_TS_SERVER_ERROR;//连接服务器错误
  }
  else if (res.code() != timestamp::GRPC_STF_TS_OK) {
    return res.code();
  }
  //正常情况


  return STF_TS_OK;
}

GetTSDetailOutput
TimeStampClient::GetTSDetail(GetTSDetailInput request) {
  GetTSDetailOutput reply;
  grpc::ClientContext context;
  grpc::Status status = stub_->GetTSDetail(&context, request, &reply);
  return reply;
}
SGD_UINT32 STF_GetTSDetail(void *hTSHandle, UNUSED SGD_UINT8 *pucTSResponse,
                           UNUSED SGD_UINT32 uiTSResponseLength,
                           UNUSED SGD_UINT32 uiItemnumber,
                           UNUSED SGD_UINT8 *pucItemValue,
                           UNUSED SGD_UINT32 *puiItemValueLength) {
  // 基本检查
  if (hTSHandle == nullptr) {
    return STF_TS_INVALID_REQUEST; //非法请求
  }
  if (!load_config()) {
    return STF_TS_CONFIG_ERROR;
  }

  TimeStampClient greeter(grpc::CreateChannel(
      ndsec_tsa_config, grpc::InsecureChannelCredentials()));

  GetTSDetailInput req_input;
  auto *handle = new timestamp::Handle;
  handle->set_session_id(*(uint64_t *)hTSHandle);
  req_input.set_allocated_handle(handle);

  GetTSDetailOutput res = greeter.GetTSDetail(req_input);
  if(res.code() == GRPC_STF_TS_LINK_FAILED){
    return STF_TS_SERVER_ERROR;//连接服务器错误
  }
  else if (res.code() != timestamp::GRPC_STF_TS_OK) {
    return res.code();
  }
  //正常情况


  return STF_TS_OK;
}
