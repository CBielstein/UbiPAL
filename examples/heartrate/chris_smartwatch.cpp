// Cameron Bielstein 4/21/15
// chris_smartwatch.cpp
// Chris' smartwatch for the heartrate example of UbiPAL

#include <ubipal/ubipal_service.h>
#include <ubipal/log.h>
#include <string>
#include <iostream>
#include <unistd.h>
#include <sstream>

const std::string SMARTWATCH = "E46F6B968F1EC0E0FFF9768A31D274AC3311634A7A2EDF43C38E417D9BB4F49B4B7E5FA919E3FC1801AC8CEBBBD494C00D346A50412074F572E74FD96505420E68370586E1B109825B40722DDEEFEDBBCC8B941E6AC4D96D986BB72D95001F16DF0FD8EC99B170FF8C2747D269B50EC978B827805463C312E89A53763BCF7B6D-03";
const std::string HRM_NAME  = "CC89D7CD396A0A50869607A4C8AB21499254ADC508D8D9B33E0AE3ECA4BACB04045A576C49006D93D555CA59BE8CAD759379A1255D3184DD2BB737578A9CC0BE57A4F57BC3D65CBB48FD240C9BF4F7842886CD9024E068A399BDF290D400F092AC69ED513E55460DC34D812602FEF2FE370528D5E0B86518909131E8F72E1745-03";

int HandleAlert(UbiPAL::UbipalService* us, const UbiPAL::Message message)
{
    std::string arg((char*)message.argument, message.arg_len);

    std::cout << "Alert! Heartrate is " << arg << std::endl;

    return UbiPAL::SUCCESS;
}

int main(int argc, char** argv)
{
    int status = UbiPAL::SUCCESS;

    // log configuration
    UbiPAL::Log::SetFile("bin/examples/heartrate/chris_smartwatch_log.txt");
    UbiPAL::Log::SetPrint(true);

    // Restore the service from the file
    UbiPAL::UbipalService us("examples/heartrate/chris_smartwatch.txt");

    // Read in the ACL from a file
    UbiPAL::AccessControlList acl;
    status = us.CreateAcl(0, "chris_smartwatch_rules", "examples/heartrate/chris_smartwatch_rules.txt", &acl);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "CreateAcl failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
        return status;
    }

    // Register callback
    status = us.RegisterCallback("Alert", HandleAlert);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "RegisterCallback failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
        return status;
    }

    // Begin receiving
    status = us.BeginRecv(UbiPAL::UbipalService::BeginRecvFlags::NON_BLOCKING);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failed to BeginRecv: " << UbiPAL::GetErrorDescription(status) << std::endl;
        return status;
    }

    std::cout << "yes sets OKAY mode, no sets NOT OKAY, s broadcasts NC, quit quits." << std::endl;
    std::string command;
    while (std::getline(std::cin, command))
    {
        if (command == "yes" || command == "no")
        {
            std::string message_arg = (command == "yes") ? "CONFIRM" : "DENY";
            status = us.SetMessageReply(0, "RequestHeartRate", (const unsigned char*)message_arg.c_str(), message_arg.size());
            if (status != UbiPAL::SUCCESS)
            {
                std::cout << "SetMessageReply failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
            }
        }
        else if (command == "quit")
        {
            us.EndRecv();
            return 0;
        }
        else if (command == "s")
        {
            status = us.SendName(0, NULL);
            if (status != UbiPAL::SUCCESS)
            {
                std::cout << "SendName failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
                continue;
            }

            status = us.SendAcl(0, acl, NULL);
            if (status != UbiPAL::SUCCESS)
            {
                std::cout << "SendAcl failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
            }
        }
    }

    return status;
}
