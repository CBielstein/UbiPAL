// Cameron Bielstein, 1/26/15
// sender.cpp
// Sends messages to a UbipalService based on keyboard input

// cin
#include <iostream>

// UbiPAL
#include <ubipal/ubipal_service.h>
#include <ubipal/error.h>
#include <ubipal/log.h>


int print_replies(UbiPAL::UbipalService* us, const UbiPAL::Message* original_message, const UbiPAL::Message* reply_message)
{
    std::cout << "Reply: " <<  reply_message->argument << std::endl;
    return UbiPAL::SUCCESS;
}

int main(int argc, char** argv)
{
    int status = UbiPAL::SUCCESS;
    std::string argument;
    const std::string sender_file("examples/sender.txt");


    // Configure log
    UbiPAL::Log::SetFile("bin/examples/senderlog.txt");
    UbiPAL::Log::SetPrint(true);

    const std::string receiver = "B57C84C933FD6EB0336986F7816AFF6846BE0F06F38A91D032A445B8E4DC6EE532D984AAD8F69A80524D7856A646F0DF403FC476949C7A40B4FB7C24EA2DF7E348B3A03728F720BC406B3C11D3E5C5E84EE4F36C2F62061921F875588A37B8BBA68F3E357CD725F9A7B432D11DE2869E5AE81C15D0A5F8C0DB9E480C0086A067-03";

    // Create service
    UbiPAL::UbipalService us(sender_file);

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

    std::cout << "Enter message to send. Commands: " << std::endl
              << "    q: quit" << std::endl
              << "    s: send namespace certificate" << std::endl;
    while(std::getline(std::cin, argument))
    {
        if (argument == "q")
        {
            break;
        }
        else if (argument == "s")
        {
            std::cout << "Broadcasting namespace certificate." << std::endl;
            status = us.SendName(0, NULL);
            if (status != UbiPAL::SUCCESS)
            {
                std::cout << UbiPAL::GetErrorDescription(status) << std::endl;
            }
            continue;
        }

        status = us.GetNames(UbiPAL::UbipalService::GetNamesFlags::INCLUDE_UNTRUSTED | UbiPAL::UbipalService::GetNamesFlags::INCLUDE_TRUSTED, services);
        if (status != UbiPAL::SUCCESS)
        {
            std::cout << "GetNames failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
            return status;
        }
        for (unsigned int i = 0; i < services.size(); ++i)
        {
            if (receiver == services[i].id)
            {
                status = us.SendMessage(UbiPAL::UbipalService::SendMessageFlags::NO_ENCRYPTION, &services[i],
                                        std::string("PrintToScreen"), (unsigned char*)argument.c_str(), argument.size(), print_replies);
                if (status != UbiPAL::SUCCESS)
                {
                    std::cout << "Failed to send message: " << UbiPAL::GetErrorDescription(status) << std::endl;
                }
                break;
            }
        }
    }

    us.EndRecv();

    return status;
}
