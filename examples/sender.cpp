// Cameron Bielstein, 1/26/15
// sender.cpp
// Sends messages to a UbipalService based on keyboard input

// cin
#include <iostream>

// UbiPAL
#include "../src/ubipal_service.h"
#include "../src/error.h"
#include "../src/log.h"

int main(int argc, char** argv)
{
    int status = UbiPAL::SUCCESS;
    std::string argument;

    // Usage IO
    if (argc != 3)
    {
        std::cout << "Incorrect usage: ./sender ADDRESS PORT" << std::endl;
        return 0;
    }
    std::cout << "Enter message to send." << std::endl;

    // Configure log
    UbiPAL::Log::SetFile("bin/examples/senderlog.txt");
    UbiPAL::Log::SetPrint(true);

    // Create service
    UbiPAL::UbipalService us;

    // Create name to send to
    UbiPAL::UbipalName un;
    un.address = std::string(argv[1]);
    un.port = std::string(argv[2]);

    while(std::getline(std::cin, argument))
    {
        //std::cout << "Sending: " << argument << std::endl;
        status = us.SendMessage(0, un, std::string("PrintToScreen"), argument.c_str(), argument.size());
        if (status != UbiPAL::SUCCESS)
        {
            std::cout << "Failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
        }
    }

    return status;
}
