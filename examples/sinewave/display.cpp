// Cameron Bielstein, 3/9/15
// display.cpp
// This is the display for the sine wave example. A sine wave is produced and sent to any service requesting the reading.
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
#include <set>     //std::set
#include <map>     //std::map

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
    time_t quit = std::clock() + 30 * CLOCKS_PER_SEC;
    while (true)
    {
        if (std::clock() > quit)
        {
            return status;
        }
        // on each interval
        if (std::clock() > update_sine)
        {
            // look for any service to which we can send SINE
            std::map<std::string, std::set<std::string>> names;
            status = us.FindNamesForStatements(us.GetId() + " CAN SEND MESSAGE SINE TO X", names);
            if (status != UbiPAL::SUCCESS)
            {
                std::cout << "FineNamesForStatements failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
                update_sine = std::clock() + CLOCKS_PER_SEC;
                continue;
            }
            if (names["X"].size() == 0)
            {
                std::cout << "Found no names to send to." << std::endl;
                update_sine = std::clock() + CLOCKS_PER_SEC;
                continue;
            }

            // for each service
            for (std::set<std::string>::iterator itr = names["X"].begin(); itr != names["X"].end(); ++itr)
            {
                // look up the namespace certificate
                UbiPAL::NamespaceCertificate nc;
                status = us.GetCertificateForName(*itr, nc);
                if (status != UbiPAL::SUCCESS)
                {
                    std::cout << "GetCertificateForName failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
                    continue;
                }

                // then send to that name
                status = us.SendMessage(0, &nc, "SINE", NULL, 0, PrintSine);
                if (status != UbiPAL::SUCCESS)
                {
                    std::cout << "SendMessage to " << *itr << " failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
                    continue;
                }
            }

            update_sine = std::clock() + CLOCKS_PER_SEC;
        }

        // on each interval
        if (std::clock() > name_resend)
        {
            // resend the name certificate to allow for replies
            status = us.SendName(0, NULL);
            if (status != UbiPAL::SUCCESS)
            {
                std::cout << "SendName failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
            }

            name_resend = std::clock() + 10 * CLOCKS_PER_SEC;
        }
        sched_yield();
    }

}
