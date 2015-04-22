// Cameron Bielstein, 3/24/15
// producer.cpp
// This is the producer for the push example. Some value is held as a measurement and can be polled or pushed to the client.
// Readings are delegated to the gateway.

#include <ubipal/ubipal_service.h>
#include <ubipal/log.h> // ubipal log
#include <iostream>     // cout
#include <string>

int main ()
{
    int status = UbiPAL::SUCCESS;

    // set logging
    UbiPAL::Log::SetFile("bin/examples/push/producerlog.txt");
    UbiPAL::Log::SetPrint(true);

    // Create service
    UbiPAL::UbipalService us("examples/push/producer.txt");

    // add rules
    UbiPAL::AccessControlList rules;
    us.CreateAcl(0, "rules", "examples/push/producer_rules.txt", &rules);

    // Start receiving
    status = us.BeginRecv(UbiPAL::UbipalService::BeginRecvFlags::NON_BLOCKING);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failed to start receiving: " << UbiPAL::GetErrorDescription(status) << std::endl;
        us.EndRecv();
        return status;
    }

    std::string command = "begin value";
    do {
        if (command == "quit")
        {
            us.EndRecv();
            return 0;
        }

        status = us.SetMessageReply(0, "VALUE", (unsigned char*)command.c_str(), command.size());
        if (status != UbiPAL::SUCCESS)
        {
            std::cout << "SetMessageReply failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
            continue;
        }
    } while (std::getline(std::cin, command));

    return status;
}
