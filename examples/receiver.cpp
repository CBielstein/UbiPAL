// Cameron Bielstein, 1/26/15
// receiver.cpp
// Receives messages on a UbipalService

// cin
#include <iostream>

// UbiPAL
#include "../src/ubipal_service.h"
#include "../src/error.h"
#include "../src/log.h"

int printer(UbiPAL::UbipalService* us, UbiPAL::Message message)
{
    // for my own sanity, ensure everything is good
    if (message.message.compare(std::string("PrintToScreen")) != 0)
    {
        std::cout << "Something wrong has happened. We received a message of type " << message.message << std::endl;
        return UbiPAL::GENERAL_FAILURE;
    }

    // now handle the argument given us how we want to
    std::string to_print(message.argument, message.arg_len);
    std::cout << to_print << std::endl;

    // reply to message
    std::string reply_string("Printed by " + us->GetId() + "!");
    us->ReplyToMessage(UbiPAL::UbipalService::SendMessageFlags::NONBLOCKING | UbiPAL::UbipalService::SendMessageFlags::NO_ENCRYPTION, &message, reply_string.c_str(), reply_string.size() + 1);

    // tell UbiPAL everything went well
    return UbiPAL::SUCCESS;
}

int main(int argc, char** argv)
{
    int status = UbiPAL::SUCCESS;

    // user output
    if (argc != 3)
    {
        std::cout << "Incorrect usage: ./receiver ADDRESS PORT" << std::endl;
        std::cout << "Announces this services to a sender at address and port." << std::endl;
        return 0;
    }

    // log configuration
    UbiPAL::Log::SetFile("bin/examples/receiverlog.txt");
    UbiPAL::Log::SetPrint(true);

    // Create a UbiPAL service on the given port
    UbiPAL::UbipalService us;

    // Announce name
    status = us.SendName(UbiPAL::UbipalService::SendMessageFlags::NONBLOCKING | UbiPAL::UbipalService::SendMessageFlags::NO_ENCRYPTION,
                         argv[1], argv[2]);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failed to send name: " << UbiPAL::GetErrorDescription(status) << std::endl;
        return status;
    }

    // Register a callback function for the given message type
    status = us.RegisterCallback(std::string("PrintToScreen"), printer);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failed to send register calback: " << UbiPAL::GetErrorDescription(status) << std::endl;
        return status;
    }

    // Begin receiving (with some error checking for my sake)
    status = us.BeginRecv(UbiPAL::UbipalService::BeginRecvFlags::DONT_PUBLISH_NAME | UbiPAL::UbipalService::BeginRecvFlags::NON_BLOCKING);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failed to start receiving: " << UbiPAL::GetErrorDescription(status) << std::endl;
        us.EndRecv();
        return -1;
    }

    char command;
    std::vector<UbiPAL::NamespaceCertificate> services;
    std::vector<std::string> rules;
    std::string rule;
    UbiPAL::AccessControlList acl_all;
    while(1)
    {
        std::cin >> command;
        switch(command)
        {
            case 'a':
                std::cout << "Allowing all." << std::endl;
                status = us.GetNames(UbiPAL::UbipalService::GetNamesFlags::INCLUDE_UNTRUSTED | UbiPAL::UbipalService::GetNamesFlags::INCLUDE_TRUSTED,
                                     services);
                if (status != UbiPAL::SUCCESS)
                {
                    std::cout << "Failed to get service names: " << UbiPAL::GetErrorDescription(status) << std::endl;
                    return status;
                }
                for (unsigned int i = 0; i < services.size(); ++i)
                {
                    rule = services[i].id;
                    rule += " can send message PrintToScreen to ";
                    rule += us.GetId();
                    rules.push_back(rule);
                }
                status = us.CreateAcl("all", rules, acl_all);
                if (status != UbiPAL::SUCCESS)
                {
                    std::cout << "Failed to create acl: " << UbiPAL::GetErrorDescription(status) << std::endl;
                    return status;
                }

                // send to the world
                for (unsigned int i = 0; i < services.size(); ++i)
                {
                    status = us.SendAcl(UbiPAL::UbipalService::SendMessageFlags::NO_ENCRYPTION, acl_all, &services[i]);
                    if (status != UbiPAL::SUCCESS)
                    {
                        std::cout << "Failed to send acl: " << UbiPAL::GetErrorDescription(status) << std::endl;
                        continue;
                    }
                }
                break;
            case 'b':
                status = us.GetNames(UbiPAL::UbipalService::GetNamesFlags::INCLUDE_UNTRUSTED | UbiPAL::UbipalService::GetNamesFlags::INCLUDE_TRUSTED,
                                     services);
                if (status != UbiPAL::SUCCESS)
                {
                    std::cout << "Failed to get service names: " << UbiPAL::GetErrorDescription(status) << std::endl;
                    return status;
                }
                for (unsigned int i = 0; i < services.size(); ++i)
                {
                    status = us.RevokeAcl(UbiPAL::UbipalService::RevokeAclFlags::NO_ENCRYPT, acl_all, &services[i]);
                    if (status != UbiPAL::SUCCESS)
                    {
                        std::cout << "Failed to revoke acl: " << UbiPAL::GetErrorDescription(status) << std::endl;
                        return status;
                    }
                }
                break;
            case 'q': return status;
            default: continue;
        }
    }

    return status;
}
