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
    std::string line;

    if (argc != 3)
    {
        std::cout << "Incorrect usage: ./sender ADDRESS PORT" << std::endl;
        return 0;
    }

    std::cout << "Enter messages to send separate by return." << std::endl;

    UbiPAL::Log::SetFile("bin/examples/senderlog.txt");
    UbiPAL::UbipalService us;

    std::getline(std::cin, line);
    std::cout << "Sending: " << line << std::endl;

    status = us.SendData(std::string(argv[1]), std::string(argv[2]), line.c_str(), line.size());
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
    }

    return 0;
}
