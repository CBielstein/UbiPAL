// Cameron Bielstein 4/21/15
// chris_smartphone.cpp
// Chris' smartphone for the heartrate example of UbiPAL

#include <ubipal/ubipal_service.h>
#include <ubipal/log.h>
#include <string>
#include <iostream>
#include <unistd.h>
#include <sstream>

const std::string SMARTWATCH = "E46F6B968F1EC0E0FFF9768A31D274AC3311634A7A2EDF43C38E417D9BB4F49B4B7E5FA919E3FC1801AC8CEBBBD494C00D346A50412074F572E74FD96505420E68370586E1B109825B40722DDEEFEDBBCC8B941E6AC4D96D986BB72D95001F16DF0FD8EC99B170FF8C2747D269B50EC978B827805463C312E89A53763BCF7B6D-03";
const std::string HRM_NAME  = "CC89D7CD396A0A50869607A4C8AB21499254ADC508D8D9B33E0AE3ECA4BACB04045A576C49006D93D555CA59BE8CAD759379A1255D3184DD2BB737578A9CC0BE57A4F57BC3D65CBB48FD240C9BF4F7842886CD9024E068A399BDF290D400F092AC69ED513E55460DC34D812602FEF2FE370528D5E0B86518909131E8F72E1745-03";

int HandleHrmMsg(UbiPAL::UbipalService* us, const UbiPAL::Message* original_message, const UbiPAL::Message* reply_message)
{
    int status = UbiPAL::SUCCESS;

    // if the message is outside of our normal bounds
    std::string arg((char*)reply_message->argument, reply_message->arg_len);
    std::cout << arg << std::endl;

    // set to a sentinel value
    int heartrate;
    std::istringstream(arg) >> heartrate;

    if (heartrate > 120 || heartrate < 60)
    {
        // if this service knows the certificate for the smartwatch, send a message
        UbiPAL::NamespaceCertificate smartwatch;
        if (us->GetCertificateForName(SMARTWATCH, smartwatch) == 0)
        {
            status = us->SendMessage(0, &smartwatch, "Alert", (unsigned char*)arg.c_str(), arg.size());
            if (status != UbiPAL::SUCCESS)
            {
                std::cout << "SendMessage failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
            }
        }
        else
        {
            // try to request the certificate and send again
            status = us->SendName(0, NULL);
            if (status != UbiPAL::SUCCESS)
            {
                std::cout << "SendName failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
            }

            sleep(1);

            status = us->RequestCertificate(0, SMARTWATCH, NULL);
            if (status != UbiPAL::SUCCESS)
            {
                std::cout << "RequestCertificate failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
            }

            if (us->GetCertificateForName(SMARTWATCH, smartwatch) == 0)
            {
                status = us->SendMessage(0, &smartwatch, "Alert", (unsigned char*)arg.c_str(), arg.size());
                if (status != UbiPAL::SUCCESS)
                {
                    std::cout << "SendMessage failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
                }
            }
        }
    }

    return status;
}

int main(int argc, char** argv)
{
    int status = UbiPAL::SUCCESS;

    // log configuration
    UbiPAL::Log::SetFile("bin/examples/heartrate/chris_smartphone_log.txt");
    UbiPAL::Log::SetPrint(true);

    // Restore the service from the file
    UbiPAL::UbipalService us("examples/heartrate/chris_smartphone.txt");

    // Read in the ACL from a file
    us.CreateAcl(0, "chris_smartphone_rules", "examples/heartrate/chris_smartphone_rules.txt", NULL);

    // Begin receiving
    status = us.BeginRecv(UbiPAL::UbipalService::BeginRecvFlags::NON_BLOCKING);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failed to BeginRecv: " << UbiPAL::GetErrorDescription(status) << std::endl;
        return status;
    }

    // Discover the heartrate monitor
    UbiPAL::NamespaceCertificate hrm;
    while (us.GetCertificateForName(HRM_NAME, hrm))
    {
        // if this service hasn't heard of the hrm, request and sleep a few seconds, then try again
        status = us.SendName(0, NULL);
        if (status != UbiPAL::SUCCESS)
        {
            std::cout << "SendName failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
        }

        sleep(1);

        status = us.RequestCertificate(0, HRM_NAME, NULL);
        if (status != UbiPAL::SUCCESS)
        {
            std::cout << "RequestCertificate failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
        }

        sleep(1);
        sched_yield();
    }

    // Now register for updates
    status = us.RegisterForUpdates(0, hrm, "RequestHeartRate", HandleHrmMsg);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "RegisterForUpdates failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
    }

    std::cout << "s broadcasts NC, quit quits." << std::endl;
    std::string command;
    while (std::getline(std::cin, command))
    {
        if (command == "quit")
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
        }
    }

    return status;
}
