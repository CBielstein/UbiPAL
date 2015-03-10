// Cameron Bielstein, 3/9/15
// producer.cpp
// This is the producer for the sine wave example. A sine wave is produced and sent to any service requesting the reading.
// Readings are delegated to the gateway.

#include <ubipal/ubipal_service.h>
#include <ubipal/log.h> // ubipal log
#include <cmath>   // sin, M_PI
#include <ctime>   // std::clock
#include <iostream>// cout
#include <sched.h> // sched_yield()
#include <arpa/inet.h> // htoln
#include <fstream> // file io
#include <string>  //std::string
#include <vector>  //std::vector

#define UNENCRYPTED UbiPAL::UbipalService::SendMessageFlags::NO_ENCRYPTION
// X CAN SAY Y CAN SEND MESSAGE SINE TO Z if Z IS me, Y is delegator

int ReplySine(UbiPAL::UbipalService* us, UbiPAL::Message message)
{
    uint32_t sinewave = htonl(10*sin(std::clock()/(CLOCKS_PER_SEC/8)/(2*M_PI)));
    return us->ReplyToMessage(UNENCRYPTED, &message, (unsigned char*)&sinewave, sizeof(uint32_t));
}

std::vector<std::string> ReadRulesFile(const std::string& file)
{
    std::vector<std::string> rules;
    std::fstream rules_file;
    rules_file.open(file);
    if (rules_file.is_open() == false)
    {
        std::cout << "Error opening rules file: " << file << std::endl;
        return rules;
    }

    std::string one_rule;
    while (std::getline(rules_file, one_rule))
    {
        rules.push_back(one_rule);
    }

    return rules;
}


int main ()
{
    int status = UbiPAL::SUCCESS;

    // set logging
    UbiPAL::Log::SetFile("bin/examples/sinewave/producerlog.txt");
    UbiPAL::Log::SetPrint(true);

    // Create service
    UbiPAL::UbipalService us("examples/sinewave/producer.txt");

    // add rules
    UbiPAL::AccessControlList delegate;
    us.CreateAcl("delegation", ReadRulesFile("examples/sinewave/producer_rules.txt"), delegate);

    // Set callback
    status = us.RegisterCallback("SINE", ReplySine);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failed to send register calback: " << UbiPAL::GetErrorDescription(status) << std::endl;
        return status;
    }

    // Start receiving
    status = us.BeginRecv(UbiPAL::UbipalService::BeginRecvFlags::NON_BLOCKING);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failed to start receiving: " << UbiPAL::GetErrorDescription(status) << std::endl;
        us.EndRecv();
        return status;
    }

    // every ten seconds, broadcast namespace certificate
    time_t timeout = std::clock() + 10 * CLOCKS_PER_SEC;
    while (true)
    {
        if (std::clock() > timeout)
        {
            status = us.SendName(UNENCRYPTED, NULL);
            if (status != UbiPAL::SUCCESS)
            {
                std::cout << "Failed to broadcast name: " << UbiPAL::GetErrorDescription(status) << std::endl;
            }

            timeout = std::clock() + 10 * CLOCKS_PER_SEC;
        }
        sched_yield();
    }

}
