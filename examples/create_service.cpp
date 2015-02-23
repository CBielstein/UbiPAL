// Cameron Bielstein, 2/22/15
// create_service.cpp
// Creates a UbiPAL service and writes it to the given file path

#include "../src/ubipal_service.h"
#include <iostream>

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        std::cout << "Usage: ./create_service <result file>" << std::endl;
        return -1;
    }

    UbiPAL::UbipalService us;
    int status = us.SaveService(argv[1]);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << UbiPAL::GetErrorDescription(status) << std::endl;
    }
    return status;
}
