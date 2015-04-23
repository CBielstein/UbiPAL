// Cameron Bielstein 4/21/15
// chris_heartrate_monitor.cpp
// Chris' HRM for the heartrate example of UbiPAL

#include <ubipal/ubipal_service.h>
#include <ubipal/log.h>
#include <string>
#include <iostream>

int main(int argc, char** argv)
{
    int status = UbiPAL::SUCCESS;

    // log configuration
    UbiPAL::Log::SetFile("bin/examples/heartrate/chris_heartrate_monitor_log.txt");
    UbiPAL::Log::SetPrint(true);
    UbiPAL::Log::SetLevel(UbiPAL::Log::Level::DEBUG);

    // Restore the service from the file
    UbiPAL::UbipalService us("examples/heartrate/chris_heartrate_monitor.txt");

    // Read in the ACL from a file
    UbiPAL::AccessControlList acl;
    us.CreateAcl(0, "chris_hrm_rules", "examples/heartrate/chris_heartrate_monitor_rules.txt", &acl);
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

    std::cout << "Enter integer to set heartrate. Normal is considered 60-120 for this example. s broadcasts NC, quit quits." << std::endl;

    // initialize message response
    std::string command = "80";
    status = us.SetMessageReply(0, "RequestHeartRate", (unsigned char*)command.c_str(), command.size());
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "SetMessageReply failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
    }

    // handle user input
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
        else
        {
            // update the response and send update messages to registered services
            status = us.SetMessageReply(0, "RequestHeartRate", (unsigned char*)command.c_str(), command.size());
            if (status != UbiPAL::SUCCESS)
            {
                std::cout << "SetMessageReply failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
                continue;
            }
        }
    }

    return status;
}
