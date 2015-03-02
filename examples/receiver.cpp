// Cameron Bielstein, 1/26/15
// receiver.cpp
// Receives messages on a UbipalService

// cin
#include <iostream>

// UbiPAL
#include <ubipal/ubipal_service.h>
#include <ubipal/error.h>
#include <ubipal/log.h>

int printer(UbiPAL::UbipalService* us, UbiPAL::Message message)
{
    // for my own sanity, ensure everything is good
    if (message.message.compare(std::string("PrintToScreen")) != 0)
    {
        std::cout << "Something wrong has happened. We received a message of type " << message.message << std::endl;
        return UbiPAL::GENERAL_FAILURE;
    }

    // now handle the argument given us how we want to
    std::string to_print((char*)message.argument, message.arg_len);
    std::cout << to_print << std::endl;

    // reply to message
    std::string reply_string("Printed by " + us->GetId() + "!");
    us->ReplyToMessage(UbiPAL::UbipalService::SendMessageFlags::NONBLOCKING | UbiPAL::UbipalService::SendMessageFlags::NO_ENCRYPTION, &message,
                       (unsigned char*)reply_string.c_str(), reply_string.size() + 1);

    // tell UbiPAL everything went well
    return UbiPAL::SUCCESS;
}

int main(int argc, char** argv)
{
    int status = UbiPAL::SUCCESS;

    // log configuration
    UbiPAL::Log::SetFile("bin/examples/receiverlog.txt");
    UbiPAL::Log::SetPrint(false);

    // Create a UbiPAL service on the given port
    UbiPAL::UbipalService us("examples/receiver.txt");

    // Register a callback function for the given message type
    status = us.RegisterCallback(std::string("PrintToScreen"), printer);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failed to send register calback: " << UbiPAL::GetErrorDescription(status) << std::endl;
        return status;
    }

    // Begin receiving (with some error checking for my sake)
    status = us.BeginRecv(UbiPAL::UbipalService::BeginRecvFlags::NON_BLOCKING);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failed to start receiving: " << UbiPAL::GetErrorDescription(status) << std::endl;
        us.EndRecv();
        return -1;
    }

    char command;
    std::vector<UbiPAL::NamespaceCertificate> services;
    std::vector<std::string> rules;
    const std::string delegator = "CE7EFE13CCE736C6B5172F7B5C496F6AAF918F4CD49E42763B54B8A8DA52CBBDFBFEDAAC5FC5F191CA2B1BAD2AF99BC59F9ECE6605D6A5318CD60FB57B7E482E7D8B1A201FCB24900A06A71CE69A30DEC70E450F14B512DFADC2C67FB545855E47D321357E20466ABAE6C5423D13A1DFD1E06A37AE52872E0E9F4321C5F2B999-03";
    const std::string sender = "B1C1D8A15798E755CF33A8A2E5FD73E6B591A0357E0B5676A9637E75748123392C3D3BD408287FDDFC3640A6C2B8FA33675DB18AD07BE77FB93F46AC8884A7D00CD7FAAD45DD9869CF4ACE4D2293CB0308ACBDB3BDCC6E86515E64936C1E8EF3FD92F326A0525ACB3BC2A6C6734E558A9FA529394C2D96602F60F0FCDEB7DE95-03";
    const std::string allow_rule = sender + " can send message PrintToScreen to " + us.GetId();
    const std::string delegate_rule = delegator + " can say x can send message PrintToScreen to y";
    UbiPAL::AccessControlList acl;

    std::cout << "Commands: " << std::endl << "    a: allows sender to send PrintToScreen messages." << std::endl
                                           << "    b: Blocks sender from sending PrintToScreen messages." << std::endl
                                           << "    d: Delegates sender sending PrintToScreen messages to delegator." << std::endl
                                           << "    s: Broadcast namespace certificate." << std::endl;

    while(1)
    {
        std::cin >> command;
        switch(command)
        {
            case 'a':
                std::cout << "Allowing." << std::endl;
                rules.clear();
                rules.push_back(allow_rule);
                status = us.CreateAcl("all", rules, acl);
                if (status != UbiPAL::SUCCESS)
                {
                    std::cout << "Failed to create acl: " << UbiPAL::GetErrorDescription(status) << std::endl;
                    return status;
                }

                status = us.SendAcl(UbiPAL::UbipalService::SendMessageFlags::NO_ENCRYPTION, acl, NULL);
                if (status != UbiPAL::SUCCESS)
                {
                    std::cout << "Failed to broadcast acl: " << UbiPAL::GetErrorDescription(status) << std::endl;
                    continue;
                }
                break;
            case 'b':
                // note: right now, this only blocks the most recent rule made
                std::cout << "Blocking." << std::endl;
                status = us.RevokeAcl(UbiPAL::UbipalService::RevokeAclFlags::NO_ENCRYPT, acl, NULL);
                if (status != UbiPAL::SUCCESS)
                {
                    std::cout << "Failed to revoke acl: " << UbiPAL::GetErrorDescription(status) << std::endl;
                    return status;
                }
                break;
            case 'd':
                std::cout << "Delegating." << std::endl;
                rules.clear();
                rules.push_back(delegate_rule);
                status = us.CreateAcl("all", rules, acl);
                if (status != UbiPAL::SUCCESS)
                {
                    std::cout << "Failed to create acl: " << UbiPAL::GetErrorDescription(status) << std::endl;
                    return status;
                }

                status = us.SendAcl(UbiPAL::UbipalService::SendMessageFlags::NO_ENCRYPTION, acl, NULL);
                if (status != UbiPAL::SUCCESS)
                {
                    std::cout << "Failed to broadcast acl: " << UbiPAL::GetErrorDescription(status) << std::endl;
                    continue;
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
