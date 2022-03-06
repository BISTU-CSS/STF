#include <iostream>

#include "stf.h"

int main(int argc, char *argv[]) {
    void *handle;
    if (argc) {}
    if(argv){}
    SGD_UINT32 retcode = STF_InitEnvironment(&handle);
    std::cout<< retcode <<std::endl;
    std::cout << handle << std::endl;
    std::cout <<  *(uint64_t *)handle << std::endl;

    std::cout<<"ret2"<<std::endl;
    SGD_UINT32 retcode_2 = STF_ClearEnvironment(handle);
    std::cout << retcode_2  <<std::endl;
    std::cout << handle << std::endl;
    std::cout << *(uint64_t *)handle << std::endl;

}
