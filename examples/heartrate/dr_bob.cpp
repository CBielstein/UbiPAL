// Cameron Bielstein 4/21/15
// dr_bob.cpp
// Dr. Bob's pager for the heartrate example of UbiPAL

#include <ubipal/ubipal_service.h>
#include <ubipal/log.h>
#include <string>
#include <iostream>
#include <unistd.h>
#include <sstream>

int HandlePage(UbiPAL::UbipalService* us, const UbiPAL::Message message)
{
    std::string arg((char*)message.argument, message.arg_len);

    std::cout << "Received page: " << arg << std::endl;

    return UbiPAL::SUCCESS;
}

int main(int argc, char** argv)
{
    int status = UbiPAL::SUCCESS;

    // log configuration
    UbiPAL::Log::SetFile("bin/examples/heartrate/dr_bob_log.txt");
    UbiPAL::Log::SetPrint(true);

    // Restore the service from the file
    UbiPAL::UbipalService us("examples/heartrate/dr_bob.txt");

    // Read in the ACL from a file
    UbiPAL::AccessControlList acl;
    status = us.CreateAcl(0, "dr_bob_rules", "examples/heartrate/dr_bob_rules.txt", &acl);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "CreateAcl failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
        return status;
    }

    status = us.RegisterCallback("Page", HandlePage);
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
