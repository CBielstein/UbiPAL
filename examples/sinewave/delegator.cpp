// Cameron Bielstein, 3/9/15
// delegator.cpp
// This is the delegator for the sine wave example. A sine wave is produced and sent to any service requesting the reading.
// Readings are delegated to the gateway.

#include <ubipal/ubipal_service.h>
#include <ubipal/log.h> // ubipal log
#include <iostream>// cout
#include <fstream> // file io
#include <string>  //std::string
#include <vector>  //std::vector
#include <algorithm> // std::sort

#define UNENCRYPTED UbiPAL::UbipalService::SendMessageFlags::NO_ENCRYPTION
#define ALL_NAMES UbiPAL::UbipalService::GetNamesFlags::INCLUDE_UNTRUSTED | UbiPAL::UbipalService::GetNamesFlags::INCLUDE_TRUSTED

const std::string PRODUCER = "B385F85CC9A3EE3AFE3764C71263E904C61A389B7B0E273F9BC8AD43A7310C23FEF95FA558C4BF1FB2E1D93327B6DA5540F793D8EF02972568E9B7AD16F42C84BF50354305DFC6459C30475E6C07BBFD481FAF2AAC8E658FE9BEC788B2ED1074E08760CDE128DD8506A37AF2B69036711A4714CBEDAD1A0FBFFC8A33FC467A19-03";

bool descending (int i, int j) { return (i > j); }

void ShowHelp()
{
    std::cout << "Commands: " << std::endl
              << "    add: Shows a list of known services which currently do not have access to allow for adding." << std::endl
              << "    remove: Shows a list of services with access to allow for removing." << std::endl
              << "    help: Shows this help again." << std::endl
              << "    quit: Quits." << std::endl;
}

int main ()
{
    int status = UbiPAL::SUCCESS;

    // set logging
    UbiPAL::Log::SetFile("bin/examples/sinewave/producerlog.txt");
    UbiPAL::Log::SetPrint(true);

    // Create service
    UbiPAL::UbipalService us("examples/sinewave/delegator.txt");

    // Start receiving
    status = us.BeginRecv(UbiPAL::UbipalService::BeginRecvFlags::NON_BLOCKING);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failed to start receiving: " << UbiPAL::GetErrorDescription(status) << std::endl;
        us.EndRecv();
        return status;
    }

    ShowHelp();

    std::string command;
    UbiPAL::AccessControlList acl;
    std::vector<std::string> new_acl_rules;
    std::vector<std::string> allowed_names;
    while(std::cin >> command)
    {
        if (command == "add")
        {
            // print all namespace that aren't in our acl
            std::vector<std::string> names_to_consider;

            // get all names we've heard
            std::vector<UbiPAL::NamespaceCertificate> names;
            status = us.GetNames(ALL_NAMES, names);
            if (status != UbiPAL::SUCCESS)
            {
                std::cout << "GetNames failed: " << UbiPAL::GetErrorDescription(status) << std::endl;
            }

            // narrow down to only ones not already in acls
            for (unsigned int i = 0; i < names.size(); ++i)
            {
                bool name_in_allowed = false;
                for (unsigned int j = 0; j < allowed_names.size(); ++j)
                {
                    if (names[i].id == allowed_names[j])
                    {
                        name_in_allowed = true;
                        break;
                    }
                }

                if (name_in_allowed == false)
                {
                    names_to_consider.push_back(names[i].id);
                }
            }

            // print the candidates for addition
            for (unsigned int i = 0; i < names_to_consider.size(); ++i)
            {
                std::cout << i << ": " << names_to_consider[i] << std::endl;
            }
            std::cout << "Enter number to add to acl. -1 to stop." << std::endl;

            // take user input on names
            int add_id = 0;
            while (add_id != -1)
            {
                // take number of service to add
                std::cin >> add_id;
                if (add_id == -1)
                {
                    break;
                }
                if (add_id >= (int)names_to_consider.size() || add_id < -1)
                {
                    std::cout << "Number out of range." << std::endl;
                    continue;
                }
                else
                {
                    allowed_names.push_back(names_to_consider[add_id]);
                }
            }

            // create the new rules
            std::vector<std::string> new_rules;
            std::string rule_middle = std::string(" CAN SEND MESSAGE SINE TO ");
            for (unsigned int i = 0; i < allowed_names.size(); ++i)
            {
                std::string new_rule = allowed_names[i] + rule_middle + PRODUCER;
                new_rules.push_back(new_rule);
            }

            status = us.RevokeAcl(UbiPAL::UbipalService::RevokeAclFlags::NO_ENCRYPT, acl, NULL);
            if (status != UbiPAL::SUCCESS)
            {
                std::cout << "Failed to revoke old acl: " << UbiPAL::GetErrorDescription(status) << std::endl;
            }

            status = us.CreateAcl("acl", new_rules, acl);
            if (status != UbiPAL::SUCCESS)
            {
                std::cout << "Failed to create acl: " << UbiPAL::GetErrorDescription(status) << std::endl;
            }

            status = us.SendAcl(UNENCRYPTED, acl, NULL);
            if (status != UbiPAL::SUCCESS)
            {
                std::cout << "Failed to broadcast acl: " << UbiPAL::GetErrorDescription(status) << std::endl;
            }
        }
        else if (command == "remove")
        {
            // print allowed names
            for (unsigned int i = 0; i < allowed_names.size(); ++i)
            {
                std::cout << i << ": " << allowed_names[i] << std::endl;
            }

            // take user input
            std::vector<int> rm_nums;
            int rm_id = 0;
            while (rm_id != -1)
            {
                // take number of service to add
                std::cin >> rm_id;
                if (rm_id == -1)
                {
                    break;
                }
                if (rm_id >= (int)allowed_names.size() || rm_id < -1)
                {
                    std::cout << "Number out of range." << std::endl;
                    continue;
                }
                else
                {
                    rm_nums.push_back(rm_id);
                }
            }

            // remove from allowed names
            std::sort(rm_nums.begin(), rm_nums.end(), descending);
            for (unsigned int i = 0; i < rm_nums.size(); ++i)
            {
                allowed_names.erase(allowed_names.begin() + rm_nums[i]);
            }

            // create the new rules
            std::vector<std::string> new_rules;
            std::string rule_middle = std::string(" CAN SEND MESSAGE SINE TO ");
            for (unsigned int i = 0; i < allowed_names.size(); ++i)
            {
                std::string new_rule = allowed_names[i] + rule_middle + PRODUCER;
                new_rules.push_back(new_rule);
            }

            status = us.RevokeAcl(UbiPAL::UbipalService::RevokeAclFlags::NO_ENCRYPT, acl, NULL);
            if (status != UbiPAL::SUCCESS)
            {
                std::cout << "Failed to revoke old acl: " << UbiPAL::GetErrorDescription(status) << std::endl;
            }

            status = us.CreateAcl("acl", new_rules, acl);
            if (status != UbiPAL::SUCCESS)
            {
                std::cout << "Failed to create acl: " << UbiPAL::GetErrorDescription(status) << std::endl;
            }

            status = us.SendAcl(UNENCRYPTED, acl, NULL);
            if (status != UbiPAL::SUCCESS)
            {
                std::cout << "Failed to broadcast acl: " << UbiPAL::GetErrorDescription(status) << std::endl;
            }


        }
        else if (command == "quit")
        {
            return 0;
        }
        else if (command == "help")
        {
            ShowHelp();
        }
        else
        {
            std::cout << "Invalid command." << std::endl;
            ShowHelp();
        }
    }
}
