// Cameron Bielstein, 3/16/15
// caller.cpp
// Part of the telephone example for UbiPAL

// cin
#include <iostream>

// UbiPAL
#include <ubipal/ubipal_service.h>
#include <ubipal/error.h>
#include <ubipal/log.h>

static const std::string PHONE = "9F28495B15A3F8B1AA07587F745E94FD2C32899DB151C6F4EEB6610422316C3AF2F1F44FBDA10EE0AD8A4F4BEE4428D69942F201F0E69D2E514B635EB27AA7B8A154E0C95628B1759690653B9B19EDC3406D8510D3D97E1C6D81568E03D27DFCDA6C16AC009AC93675D051E360632C3DC946E760D0F883FDA15A9A4CE660B201-03";

int PrintReply(UbiPAL::UbipalService* us, const UbiPAL::Message* original_message, const UbiPAL::Message* reply_message)
{
    if (reply_message != nullptr && reply_message->argument != nullptr && reply_message->arg_len > 0)
    {
        std::string reply((char*)reply_message->argument, reply_message->arg_len);
        std::cout << "Reply: " << reply << std::endl;
    }

    return UbiPAL::SUCCESS;
}

int main(int argc, char** argv)
{
    int status = UbiPAL::SUCCESS;

    // log configuration
    UbiPAL::Log::SetFile("bin/examples/telephone/callerlog.txt");
    UbiPAL::Log::SetPrint(true);

    // Create a UbiPAL service on the given port
    UbiPAL::UbipalService us;

    // begin receiving (for namespace certificates)
    status = us.BeginRecv(UbiPAL::UbipalService::BeginRecvFlags::NON_BLOCKING);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failed to BeginRecv: " << UbiPAL::GetErrorDescription(status) << std::endl;
        return status;
    }

    std::cout << "Commands: " << std::endl
                              << "    c: Calls." << std::endl
                              << "    q: Quits." << std::endl;

    char command;
    std::string name;
    UbiPAL::NamespaceCertificate phone;
    while(1)
    {
        std::cin >> command;
        switch(command)
        {
            case 'c':
                // Get caller name
                std::cout << "Call from?" << std::endl;
                std::cin >> name;

                // fetch phone certificate
                status = us.GetCertificateForName(PHONE, phone);
                if (status != UbiPAL::SUCCESS)
                {
                    std::cout << "GetCertificateForName failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
                    continue;
                }

                // send message
                status = us.SendMessage(0, &phone, "CALL", (unsigned char*)name.c_str(), name.size(), PrintReply);
                if (status != UbiPAL::SUCCESS)
                {
                    std::cout << "SendMessage failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
                    continue;
                }
                break;
            case 'q': return status;
            default: continue;
        }
    }

    return status;
}
