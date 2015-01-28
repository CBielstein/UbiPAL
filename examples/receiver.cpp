// Cameron Bielstein, 1/26/15
// receiver.cpp
// Receives messages on a UbipalService

// cin
#include <iostream>

// UbiPAL
#include "../src/ubipal_service.h"
#include "../src/error.h"
#include "../src/log.h"

int printer(std::string message, char* arg, uint32_t arg_len)
{
    // for my own sanity, ensure everything is good
    if (message.compare(std::string("PrintToScreen")) != 0)
    {
        std::cout << "Something wrong has happened. We received a message of type " << message << std::endl;
        return UbiPAL::GENERAL_FAILURE;
    }

    // now handle the argument given us how we want to
    std::string to_print(arg, arg_len);
    std::cout << to_print << std::endl;

    // tell UbiPAL everything went well
    return UbiPAL::SUCCESS;
}

int main(int argc, char** argv)
{
    int status = UbiPAL::SUCCESS;

    // user output
    if (argc != 2)
    {
        std::cout << "Incorrect usage: ./receiver PORT" << std::endl;
        return 0;
    }

    // log configuration
    UbiPAL::Log::SetFile("bin/examples/receiverlog.txt");
    UbiPAL::Log::SetPrint(true);

    // Create a UbiPAL service on the given port
    UbiPAL::UbipalService us(nullptr, argv[1]);

    // Register a callback function for the given message type
    status = us.RegisterCallback(std::string("PrintToScreen"), printer);

    // Begin receiving (with some error checking for my sake)
    status = us.BeginRecv(UbiPAL::UbipalService::BeginRecvFlags::DONT_PUBLISH_NAME);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
        us.EndRecv();
        return -1;
    }

    return status;
}
