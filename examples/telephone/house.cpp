// Cameron Bielstein, 3/16/15
// confirmer.cpp
// Part of the telephone example for UbiPAL

// cin
#include <iostream>

// UbiPAL
#include <ubipal/ubipal_service.h>
#include <ubipal/error.h>
#include <ubipal/log.h>

bool is_home;

int IsHome(UbiPAL::UbipalService* us, UbiPAL::Message message)
{
    if (is_home)
    {
        std::cout << "confirming." << std::endl;
        us->ReplyToMessage(UbiPAL::UbipalService::SendMessageFlags::NONBLOCKING | UbiPAL::UbipalService::SendMessageFlags::NO_ENCRYPTION, &message, (const unsigned char*)"CONFIRM", strlen("CONFIRM"));
    }
    else
    {
        std::cout << "denying." << std::endl;
        us->ReplyToMessage(UbiPAL::UbipalService::SendMessageFlags::NONBLOCKING | UbiPAL::UbipalService::SendMessageFlags::NO_ENCRYPTION, &message, (const unsigned char*)"DENY", strlen("DENY"));
    }

    return UbiPAL::SUCCESS;
}

int main(int argc, char** argv)
{
    int status = UbiPAL::SUCCESS;

    is_home = false;

    // log configuration
    UbiPAL::Log::SetFile("bin/examples/telephone/houselog.txt");
    UbiPAL::Log::SetPrint(true);

    // Create a UbiPAL service on the given port
    UbiPAL::UbipalService us("examples/telephone/house.txt");

    // create an ACL that allows anyone to use IS_HOME
    std::vector<std::string> rules;
    std::string rule = "X CAN SEND MESSAGE IS_HOME TO " + us.GetId();
    rules.push_back(rule);
    UbiPAL::AccessControlList acl_all;

    status = us.CreateAcl("all", rules, acl_all);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failed to create acl: " << UbiPAL::GetErrorDescription(status) << std::endl;
        return status;
    }

    status = us.RegisterCallback(std::string("IS_HOME"), IsHome);
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
                              << "    y: Yes, is home." << std::endl
                              << "    n: No, is not home." << std::endl
                              << "    s: Sends NamespaceCertificate." << std::endl
                              << "    q: Quits." << std::endl;

    char command;
    while(1)
    {
        std::cin >> command;
        switch(command)
        {
            case 'y':
                std::cout << "Setting home." << std::endl;
                is_home = true;
                break;
            case 'n':
                std::cout << "Setting not home." << std::endl;
                is_home = false;
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
