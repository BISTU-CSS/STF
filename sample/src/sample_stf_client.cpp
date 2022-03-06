#include <iostream>

#include "stf.h"

int main(int argc, char *argv[]) {
    void *handle;
    if (argc) {}
    if(argv){}
    SGD_UINT32 retcode = STF_InitEnvironment(&handle);
    std::cout<<retcode<<std::endl;
    
}
