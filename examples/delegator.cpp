// Cameron Bielstein, 2/22/15
// delegator.cpp
// Delegates authorization on a UbipalService

// cin
#include <iostream>

// UbiPAL
#include <ubipal/ubipal_service.h>
#include <ubipal/error.h>
#include <ubipal/log.h>

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
    std::string rule = sender + " CAN SEND MESSAGE PrintToScreen TO " + receiver;
    rules.push_back(rule);
    UbiPAL::AccessControlList acl_all;

    std::vector<std::string> confirm_rules;
    std::string confirmer = "C1D34762A95C8FB573CF071CACC533AC98B85C646F966B1E16987466F311076B17F6CD9226946D18DD07D6B6E491F652B4F4E869319959CA41838991CA85E69C68FD98BAA21A6B873EB910C4B8A0B7DC40978D53FF1E4C39FF1BCF7A6B78B7FBC5D85A56E6E7846B05960D41244B2F3D54A9573E254CDBF459097FC260E121B7-03";
    std::string confirm_rule = sender + " CAN SEND MESSAGE PrintToScreen TO " + receiver + " if " + confirmer + " CONFIRMS PLEASE_CONFIRM";
    confirm_rules.push_back(confirm_rule);

    std::cout << "Commands: " << std::endl
                              << "    a: Allow sender to send to receiver." << std::endl
                              << "    b: Block sender a from sending to receiver." << std::endl
                              << "    s: Send namespace certificate." << std::endl
                              << "    c: Allow with confirmation by confirmer." <<std::endl;

    char command;
    while(1)
    {
        std::cin >> command;
        switch(command)
        {
            case 'a':
                std::cout << "Authorizing." << std::endl;
                status = us.CreateAcl(0, "all", rules, acl_all);
                if (status != UbiPAL::SUCCESS)
                {
                    std::cout << "Failed to create acl: " << UbiPAL::GetErrorDescription(status) << std::endl;
                    return status;
                }

                status = us.SendAcl(0, acl_all, NULL);
                if (status != UbiPAL::SUCCESS)
                {
                    std::cout << "Failed to broadcast acl: " << UbiPAL::GetErrorDescription(status) << std::endl;
                    continue;
                }
                break;
            case 'b':
                std::cout << "Revoking..." << std::endl;
                status = us.RevokeAcl(0, acl_all, NULL);
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
            case 'c':
                std::cout << "Requires confirm." << std::endl;
                status = us.CreateAcl(0, "all", confirm_rules, acl_all);
                if (status != UbiPAL::SUCCESS)
                {
                    std::cout << "Failed to create acl: " << UbiPAL::GetErrorDescription(status) << std::endl;
                    return status;
                }

                status = us.SendAcl(0, acl_all, NULL);
                if (status != UbiPAL::SUCCESS)
                {
                    std::cout << "Failed to broadcast acl: " << UbiPAL::GetErrorDescription(status) << std::endl;
                    continue;
                }
                break;
            case 'q': return status;
            default: continue;
        }
    }

    return status;
}
