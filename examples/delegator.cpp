// Cameron Bielstein, 2/22/15
// delegator.cpp
// Delegates authorization on a UbipalService

// cin
#include <iostream>

// UbiPAL
#include "../src/ubipal_service.h"
#include "../src/error.h"
#include "../src/log.h"

int main(int argc, char** argv)
{
    int status = UbiPAL::SUCCESS;

    // log configuration
    UbiPAL::Log::SetFile("bin/examples/delegatorlog.txt");
    UbiPAL::Log::SetPrint(true);

    // Create a UbiPAL service on the given port
    UbiPAL::UbipalService us("examples/delegator.txt");

    std::vector<std::string> rules;
    std::string sender = "B1C1D8A15798E755CF33A8A2E5FD73E6B591A0357E0B5676A9637E75748123392C3D3BD408287FDDFC3640A6C2B8FA33675DB18AD07BE77FB93F46AC8884A7D00CD7FAAD45DD9869CF4ACE4D2293CB0308ACBDB3BDCC6E86515E64936C1E8EF3FD92F326A0525ACB3BC2A6C6734E558A9FA529394C2D96602F60F0FCDEB7DE95-03";
    std::string receiver = "B57C84C933FD6EB0336986F7816AFF6846BE0F06F38A91D032A445B8E4DC6EE532D984AAD8F69A80524D7856A646F0DF403FC476949C7A40B4FB7C24EA2DF7E348B3A03728F720BC406B3C11D3E5C5E84EE4F36C2F62061921F875588A37B8BBA68F3E357CD725F9A7B432D11DE2869E5AE81C15D0A5F8C0DB9E480C0086A067-03";
    std::string rule = sender + " can send message PrintToScreen to " + receiver;
    rules.push_back(rule);
    UbiPAL::AccessControlList acl_all;

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
                std::cout << "Authorizing." << std::endl;
                status = us.CreateAcl("all", rules, acl_all);
                if (status != UbiPAL::SUCCESS)
                {
                    std::cout << "Failed to create acl: " << UbiPAL::GetErrorDescription(status) << std::endl;
                    return status;
                }

                status = us.SendAcl(UbiPAL::UbipalService::SendMessageFlags::NO_ENCRYPTION, acl_all, NULL);
                if (status != UbiPAL::SUCCESS)
                {
                    std::cout << "Failed to broadcast acl: " << UbiPAL::GetErrorDescription(status) << std::endl;
                    continue;
                }
                break;
            case 'b':
                std::cout << "Revoking..." << std::endl;
                status = us.RevokeAcl(UbiPAL::UbipalService::RevokeAclFlags::NO_ENCRYPT, acl_all, NULL);
                if (status != UbiPAL::SUCCESS)
                {
                    std::cout << "Failed to revoke acl: " << UbiPAL::GetErrorDescription(status) << std::endl;
                    return status;
                }
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
