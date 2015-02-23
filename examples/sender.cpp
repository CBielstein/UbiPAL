// Cameron Bielstein, 1/26/15
// sender.cpp
// Sends messages to a UbipalService based on keyboard input

// cin
#include <iostream>

// UbiPAL
#include "../src/ubipal_service.h"
#include "../src/error.h"
#include "../src/log.h"

int print_replies(UbiPAL::UbipalService* us, UbiPAL::Message original_message, UbiPAL::Message reply_message)
{
    std::cout << "Reply: " <<  reply_message.argument << std::endl;
    return UbiPAL::SUCCESS;
}

int main(int argc, char** argv)
{
    int status = UbiPAL::SUCCESS;
    std::string argument;

    std::cout << "Enter message to send." << std::endl;

    // Configure log
    UbiPAL::Log::SetFile("bin/examples/senderlog.txt");
    UbiPAL::Log::SetPrint(true);

    // Create service
    UbiPAL::UbipalService us;

    // listen for advertised names
    status = us.BeginRecv(UbiPAL::UbipalService::BeginRecvFlags::NON_BLOCKING);
    if (status != UbiPAL::SUCCESS)
    {
        us.EndRecv();
        std::cout << "Failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
        return status;
    }

    // for each line, send to any service we have heard about
    std::vector<UbiPAL::NamespaceCertificate> services;
    while(std::getline(std::cin, argument))
    {
        status = us.SendName(0, NULL);
        if (status != UbiPAL::SUCCESS)
        {
            std::cout << "Failed to broadcast name: " << UbiPAL::GetErrorDescription(status) << std::endl;
        }

        status = us.GetNames(UbiPAL::UbipalService::GetNamesFlags::INCLUDE_UNTRUSTED | UbiPAL::UbipalService::GetNamesFlags::INCLUDE_TRUSTED, services);
        if (status != UbiPAL::SUCCESS)
        {
            std::cout << "GetNames failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
            return status;
        }
        for (size_t i = 0; i < services.size(); ++i)
        {
            status = us.SendMessage(UbiPAL::UbipalService::SendMessageFlags::NO_ENCRYPTION, services[i],
                                    std::string("PrintToScreen"), (unsigned char*)argument.c_str(), argument.size(), print_replies);
            if (status != UbiPAL::SUCCESS)
            {
                std::cout << "Failed to send message: " << UbiPAL::GetErrorDescription(status) << std::endl;
            }
        }
    }

    return status;
}
