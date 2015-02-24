// Cameron Bielstein, 2/23/15
// confirmer.cpp
// Test of confirmation on ACL conditions for UbiPAL

// cin
#include <iostream>

// UbiPAL
#include "../src/ubipal_service.h"
#include "../src/error.h"
#include "../src/log.h"

bool allow;

int confirmer(UbiPAL::UbipalService* us, UbiPAL::Message message)
{
    if (allow)
    {
        std::cout << "confirming." << std::endl;
        us->ReplyToMessage(UbiPAL::UbipalService::SendMessageFlags::NONBLOCKING | UbiPAL::UbipalService::SendMessageFlags::NO_ENCRYPTION, &message, (const unsigned char*)"CONFIRM", strlen("CONFIRM"));
    }
    else
    {
        std::cout << "not confirming." << std::endl;
    }
    return UbiPAL::SUCCESS;
}

int main(int argc, char** argv)
{
    int status = UbiPAL::SUCCESS;

    allow = false;

    // log configuration
    UbiPAL::Log::SetFile("bin/examples/confirmerlog.txt");
    UbiPAL::Log::SetPrint(true);

    // Create a UbiPAL service on the given port
    UbiPAL::UbipalService us("examples/confirmer.txt");

    std::vector<std::string> rules;
    std::string receiver = "B57C84C933FD6EB0336986F7816AFF6846BE0F06F38A91D032A445B8E4DC6EE532D984AAD8F69A80524D7856A646F0DF403FC476949C7A40B4FB7C24EA2DF7E348B3A03728F720BC406B3C11D3E5C5E84EE4F36C2F62061921F875588A37B8BBA68F3E357CD725F9A7B432D11DE2869E5AE81C15D0A5F8C0DB9E480C0086A067-03";
    std::string rule = receiver + " can send message PLEASE_CONFIRM to " + us.GetId();
    rules.push_back(rule);
    UbiPAL::AccessControlList acl_all;

    status = us.CreateAcl("all", rules, acl_all);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failed to create acl: " << UbiPAL::GetErrorDescription(status) << std::endl;
        return status;
    }

    status = us.RegisterCallback(std::string("PLEASE_CONFIRM"), confirmer);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failed to send register calback: " << UbiPAL::GetErrorDescription(status) << std::endl;
        return status;
    }

    status = us.BeginRecv(UbiPAL::UbipalService::BeginRecvFlags::NON_BLOCKING);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failed to BeginRecv: " << UbiPAL::GetErrorDescription(status) << std::endl;
        return status;
    }

std::cout << "Commands: " << std::endl
                              << "    a: Allow sender to send to receiver." << std::endl
                              << "    b: Block sender a from sending to receiver." << std::endl
                              << "    s: Send namespace certificate." << std::endl;

    char command;
    while(1)
    {
        std::cin >> command;
        switch(command)
        {
            case 'a':
                std::cout << "Allowing." << std::endl;
                allow = true;
                break;
            case 'b':
                std::cout << "Blocking." << std::endl;
                allow = false;
                break;
            case 's':
                std::cout << "Sending namespace cert." << std::endl;
                status = us.SendName(0, NULL);
                if (status != UbiPAL::SUCCESS)
                {
                    std::cout << UbiPAL::GetErrorDescription(status) << std::endl;
                }
                break;
            case 'q': return status;
            default: continue;
        }
    }

    return status;
}
