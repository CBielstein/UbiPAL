// Cameron Bielstein 4/21/15
// dr_alice.cpp
// Dr. Alice's computer for the heartrate example of UbiPAL

#include <ubipal/ubipal_service.h>
#include <ubipal/log.h>
#include <string>
#include <iostream>
#include <unistd.h>
#include <sstream>

const std::string HRM_NAME  = "CC89D7CD396A0A50869607A4C8AB21499254ADC508D8D9B33E0AE3ECA4BACB04045A576C49006D93D555CA59BE8CAD759379A1255D3184DD2BB737578A9CC0BE57A4F57BC3D65CBB48FD240C9BF4F7842886CD9024E068A399BDF290D400F092AC69ED513E55460DC34D812602FEF2FE370528D5E0B86518909131E8F72E1745-03";
const std::string DR_BOB = "C39E94D59E2C1D9019BC991C810E0DFE46E5EC0B6CBBEBC9CE7646D84B3061B2B771B4914AEE40B6CAA7AA583660A03F75A73B4FD276BAB6FB2DEBB5CD76E29EA39D03433F89E56BA6DD64808764292992F90E644049231406AC5FC7DAD975F6706F5B95515E4F07A16AF1A46AE9E6A525557E61617B86B35D73692AEFA55945-03";

int HandleHrmMsg(UbiPAL::UbipalService* us, const UbiPAL::Message* original_message, const UbiPAL::Message* reply_message)
{
    int status = UbiPAL::SUCCESS;

    // if the message is outside of our normal bounds
    std::string arg((char*)reply_message->argument, reply_message->arg_len);

    int heartrate;
    std::istringstream(arg) >> heartrate;
    std::string page_message = "Chris' heartrate is " + arg;
    std::cout << page_message << std::endl;

    if (heartrate > 120 || heartrate < 60)
    {
        // if this service knows the certificate for Dr. Bob, send a page with the heartrate info
        UbiPAL::NamespaceCertificate drbob;
        if (us->GetCertificateForName(DR_BOB, drbob) == 0)
        {
            status = us->SendMessage(0, &drbob, "Page", (unsigned char*)page_message.c_str(), page_message.size());
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

            status = us->RequestCertificate(0, DR_BOB, NULL);
            if (status != UbiPAL::SUCCESS)
            {
                std::cout << "RequestCertificate failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
            }

            sleep(1);

            if (us->GetCertificateForName(DR_BOB, drbob) == 0)
            {
                status = us->SendMessage(0, &drbob, "Page", (unsigned char*)page_message.c_str(), page_message.size());
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
    UbiPAL::Log::SetFile("bin/examples/heartrate/dr_alice_log.txt");
    UbiPAL::Log::SetPrint(true);

    // Restore the service from the file
    UbiPAL::UbipalService us("examples/heartrate/dr_alice.txt");

    // Read in the ACL from a file
    UbiPAL::AccessControlList acl;
    status = us.CreateAcl(0, "dr_alice_rules", "examples/heartrate/dr_alice_rules.txt", &acl);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "CreateAcl failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
        return status;
    }

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

            status = us.SendAcl(0, acl, NULL);
            if (status != UbiPAL::SUCCESS)
            {
                std::cout << "SendAcl failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
            }
        }
    }

    return status;
}
