//
// Created by dx on 2022/1/25.
//
#include <iostream>
#include "grpc_cs/greeter_client.h"

using namespace std;
InitEnvironmentOutput TimeStampClient::InitEnvironment() {
  timestamp::InitEnvironmentInput request;

  timestamp::InitEnvironmentOutput reply;

  grpc::ClientContext context;

  grpc::Status status = stub_->InitEnvironment(&context, request, &reply);

  // Act upon its status.
  return reply;

};

int main() {
  TimeStampClient greeter(grpc::CreateChannel(
      "localhost:50051", grpc::InsecureChannelCredentials()));
  InitEnvironmentOutput res = greeter.InitEnvironment();
  cout << "Status code: " <<  res.code() << endl;
  cout << "Status code: " <<  res.handle().session_id() << endl;
  cout << "hello " << endl;
  return 0;
}