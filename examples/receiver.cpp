// Cameron Bielstein, 1/26/15
// receiver.cpp
// Receives messages on a UbipalService

// cin
#include <iostream>

// UbiPAL
#include "../src/ubipal_service.h"
#include "../src/error.h"
#include "../src/log.h"

int main(int argc, char** argv)
{
    int status = UbiPAL::SUCCESS;

    if (argc != 2)
    {
        std::cout << "Incorrect usage: ./receiver PORT" << std::endl;
        return 0;
    }

    UbiPAL::Log::SetFile("bin/examples/receiverlog.txt");
    UbiPAL::UbipalService us(nullptr, argv[1]);

    status = us.BeginRecv(UbiPAL::UbipalService::BeginRecvFlags::DONT_PUBLISH_NAME, nullptr);

    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
        us.EndRecv();
        return -1;
    }

    return 0;
}
