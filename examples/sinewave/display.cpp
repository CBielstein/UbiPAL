// Cameron Bielstein, 3/9/15
// producer.cpp
// This is the producer for the sine wave example. A sine wave is produced and sent to any service requesting the reading.
// Readings are delegated to the gateway.

#include <ubipal/ubipal_service.h>
#include <ubipal/log.h> // ubipal log
#include <iostream>// cout
#include <sched.h> // sched_yield()
#include <cstdlib> // std::system
#include <arpa/inet.h> // htoln
#include <fstream> // file io
#include <string>  //std::string
#include <vector>  //std::vector

#define UNENCRYPTED UbiPAL::UbipalService::SendMessageFlags::NO_ENCRYPTION
#define ALL_NAMES UbiPAL::UbipalService::GetNamesFlags::INCLUDE_UNTRUSTED | UbiPAL::UbipalService::GetNamesFlags::INCLUDE_TRUSTED

const std::string PRODUCER_NAME = "B385F85CC9A3EE3AFE3764C71263E904C61A389B7B0E273F9BC8AD43A7310C23FEF95FA558C4BF1FB2E1D93327B6DA5540F793D8EF02972568E9B7AD16F42C84BF50354305DFC6459C30475E6C07BBFD481FAF2AAC8E658FE9BEC788B2ED1074E08760CDE128DD8506A37AF2B69036711A4714CBEDAD1A0FBFFC8A33FC467A19-03";

int PrintSine(UbiPAL::UbipalService* us, const UbiPAL::Message* original_message, const UbiPAL::Message* message)
{
    if (message->argument == nullptr)
    {
        std::cout << "Reply message had no argument." << std::endl;
        return UbiPAL::GENERAL_FAILURE;
    }

    int32_t sinewave = (int32_t)ntohl(*((uint32_t*)message->argument));
    int returned_value = std::system("clear");
    if (returned_value != 0)
    {
        std::cout << "Failed to clear screen." << std::endl;
        return UbiPAL::GENERAL_FAILURE;
    }
    std::cout << sinewave << std::endl;
    return UbiPAL::SUCCESS;
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
    UbiPAL::Log::SetFile("bin/examples/sinewave/displaylog.txt");
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

    // every ten seconds, broadcast namespace certificate
    time_t name_resend = std::clock() + 10 * CLOCKS_PER_SEC;
    time_t update_sine = std::clock() + CLOCKS_PER_SEC;
    while (true)
    {
        if (std::clock() > update_sine)
        {
            std::vector<UbiPAL::NamespaceCertificate> names;
            status = us.GetNames(ALL_NAMES, names);
            if (status != UbiPAL::SUCCESS)
            {
                std::cout << "GetNames failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
            }

            for (unsigned int i = 0; i < names.size(); ++i)
            {
                if (PRODUCER_NAME == names[i].id)
                {
                    status = us.SendMessage(UNENCRYPTED, &names[i], "SINE", NULL, 0, PrintSine);
                    if (status != UbiPAL::SUCCESS)
                    {
                        std::cout << "SendMessage failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
                    }
                    break;
                }
            }

            update_sine = std::clock() + CLOCKS_PER_SEC;
        }
        if (std::clock() > name_resend)
        {
            status = us.SendName(UNENCRYPTED, NULL);
            if (status != UbiPAL::SUCCESS)
            {
                std::cout << "SendName failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
            }

            name_resend = std::clock() + 10 * CLOCKS_PER_SEC;
        }
        sched_yield();
    }

}
