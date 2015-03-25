// Cameron Bielstein, 3/24/15
// consumer.cpp
// Consumes whatever is put out by the producer for push example of UbiPAL.

#include <ubipal/ubipal_service.h>
#include <ubipal/log.h> // ubipal log
#include <iostream>     // cout
#include <sched.h>      // sched_yield
#include <unistd.h>     // sleep

// hard coded for convenience in this example
const std::string PRODUCER = "A97EA0497245B7D300E5845A79B7E3A13E1EB1E516C836484274A52C44496686E6B40089A7454A0C87FE68A5C9E87CE700597524AAB1F219A7D35C08D27320FC114C3F825BA2CE3A5EC54B0A96DB5A404030D0AA726A8C209BC07036D63A2616E740C0DE388884E2349E59927A7FDB38B115F74503081F375C8F9851721327D5-03";

// Prints the value of any update or reply message sent to us about this message
int PrintValue(UbiPAL::UbipalService* us, const UbiPAL::Message* original_message, const UbiPAL::Message* reply_message)
{
    if (reply_message == nullptr || reply_message->argument == nullptr)
    {
        std::cout << "Reply message had no argument." << std::endl;
        return UbiPAL::GENERAL_FAILURE;
    }

    std::string value((char*)reply_message->argument, reply_message->arg_len);
    std::cout << value << std::endl;
    return UbiPAL::SUCCESS;
}

int main (int argc, char** argv)
{
    int status = UbiPAL::SUCCESS;
    bool push = false;

    if (argc == 2 && strcmp(argv[1], "-push") == 0)
    {
        std::cout << "Setting push." << std::endl;
        push = true;
    }

    // set logging
    UbiPAL::Log::SetFile("bin/examples/sinewave/consumerlog.txt");
    UbiPAL::Log::SetPrint(true);

    // Create service
    UbiPAL::UbipalService us;

    // Start receiving for message replies
    status = us.BeginRecv(UbiPAL::UbipalService::BeginRecvFlags::NON_BLOCKING);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failed to start receiving: " << UbiPAL::GetErrorDescription(status) << std::endl;
        us.EndRecv();
        return status;
    }

    // loop while looking for a name
    UbiPAL::NamespaceCertificate send_to;
    while (true)
    {
        status = us.GetCertificateForName(PRODUCER, send_to);
        if (status == UbiPAL::SUCCESS)
        {
            break;
        }
    }

    if (push == true)
    {
        // register for updates
        status = us.RegisterForUpdates(0, send_to, "VALUE", PrintValue);
        if (status != UbiPAL::SUCCESS)
        {
            std::cout << "Failed to register for updates: " << UbiPAL::GetErrorDescription(status) << std::endl;
        }
    }

    // loop until quitting. Request updates!
    while (true)
    {
        sleep(1);
        status = us.SendMessage(0, &send_to, "VALUE", NULL, 0, PrintValue);
        if (status != UbiPAL::SUCCESS)
        {
            std::cout << "Failed to send messaeg VALUE." << std::endl;
        }
    }

    return status;
}
