// Cameron Bielstein, 3/16/15
// bed.cpp
// Part of the telephone example for UbiPAL

// cin
#include <iostream>

// UbiPAL
#include <ubipal/ubipal_service.h>
#include <ubipal/error.h>
#include <ubipal/log.h>

bool is_asleep;

static const std::string PHONE = "9F28495B15A3F8B1AA07587F745E94FD2C32899DB151C6F4EEB6610422316C3AF2F1F44FBDA10EE0AD8A4F4BEE4428D69942F201F0E69D2E514B635EB27AA7B8A154E0C95628B1759690653B9B19EDC3406D8510D3D97E1C6D81568E03D27DFCDA6C16AC009AC93675D051E360632C3DC946E760D0F883FDA15A9A4CE660B201-03";

int IsAsleep(UbiPAL::UbipalService* us, UbiPAL::Message message)
{
    if (is_asleep == false)
    {
        std::cout << "confirming." << std::endl;
        us->ReplyToMessage(UbiPAL::UbipalService::SendMessageFlags::NONBLOCKING, &message, (const unsigned char*)"CONFIRM", strlen("CONFIRM"));
    }
    else
    {
        std::cout << "denying." << std::endl;
        us->ReplyToMessage(UbiPAL::UbipalService::SendMessageFlags::NONBLOCKING, &message, (const unsigned char*)"DENY", strlen("DENY"));
    }

    return UbiPAL::SUCCESS;
}

int main(int argc, char** argv)
{
    int status = UbiPAL::SUCCESS;

    is_asleep = false;

    // log configuration
    UbiPAL::Log::SetFile("bin/examples/telephone/bedlog.txt");
    UbiPAL::Log::SetPrint(true);

    // Create a UbiPAL service on the given port
    UbiPAL::UbipalService us("examples/telephone/bed.txt");

    // create an ACL that allows anyone to use IS_HOME
    std::vector<std::string> rules;
    std::string rule = "X CAN SEND MESSAGE IS_ASLEEP TO " + us.GetId();
    rules.push_back(rule);

    status = us.CreateAcl(0, "all", rules, NULL);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failed to create acl: " << UbiPAL::GetErrorDescription(status) << std::endl;
        return status;
    }

    status = us.RegisterCallback(std::string("IS_ASLEEP"), IsAsleep);
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
                              << "    y: Yes, is aleep." << std::endl
                              << "    n: No, is not asleep." << std::endl
                              //<< "    c: Cache the condition at telephone." << std::endl
                              << "    q: Quits." << std::endl;

    UbiPAL::NamespaceCertificate phone;
    char command;
    //unsigned char* reply_cache;
    while(1)
    {
        std::cin >> command;
        switch(command)
        {
            case 'y':
                std::cout << "Setting asleep." << std::endl;
                is_asleep = true;
                break;
            case 'n':
                std::cout << "Setting not asleep." << std::endl;
                is_asleep = false;
                break;
            /*case 'c':
                status = us.GetCertificateForName(PHONE, phone);
                if (status != UbiPAL::SUCCESS)
                {
                    std::cout << "GetCertificateForName failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
                    continue;
                }

                reply_cache = is_asleep ? (unsigned char*)"DENY" : (unsigned char*)"CONFIRM";
                status = us.CacheCondition(0, &phone, "IS_ASLEEP", reply_cache, strlen((char*)reply_cache));
                if (status != UbiPAL::SUCCESS)
                {
                    std::cout << "CacheCondition failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
                    continue;
                }

                break;*/
            /*case 'i':
                status = us.GetCertificateForName(PHONE, phone);
                if (status != UbiPAL::SUCCESS)
                {
                    std::cout << "GetCertificateForName failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
                    continue;
                }

                status = us.InvalidateCachedCondition(0, &phone, "IS_ASLEEP");
                if (status != UbiPAL::SUCCESS)
                {
                    std::cout << "InvalidateCachedCondition failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
                    continue;
                }
                break;*/
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
