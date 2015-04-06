// Cameron Bielstein, 4/5/15
// discover.cpp
// Discovers other services on the network for the discovery example

#include <ubipal/ubipal_service.h>
#include <ubipal/log.h>
#include <iostream>// cout
#include <sched.h> // sched_yield()
#include <string>  //std::string
#include <vector>  //std::vector

int FetchAcls(UbiPAL::UbipalService* us, const UbiPAL::Message* original_message, const UbiPAL::Message* reply_message)
{
    int status = UbiPAL::SUCCESS;

    if (us == nullptr || original_message == nullptr || reply_message == nullptr)
    {
        return UbiPAL::NULL_ARG;
    }

    std::string service_acls((char*)reply_message->argument, reply_message->arg_len);
    size_t start = 0;
    size_t end = service_acls.find(",");

    UbiPAL::NamespaceCertificate service;
    status = us->GetCertificateForName(reply_message->from, service);

    while (start < service_acls.size())
    {
        status = us->RequestAcl(0, service_acls.substr(start, end - start), &service);
        if (status != UbiPAL::SUCCESS)
        {
            std::cout << "Failed to request specific ACL " << service_acls.substr(start, end - start) << " from " << service.id << std::endl;
        }
        if (end == std::string::npos)
        {
            break;
        }
        start = end + 1;
        end = service_acls.find(",", start);
    }

    return status;
}

int main ()
{
    int status = UbiPAL::SUCCESS;

    // Create service
    UbiPAL::UbipalService us;
    std::cout << "Started service " << us.GetId() << std::endl;
    UbiPAL::Log::SetPrint(true);

    // Start receiving for message replies
    status = us.BeginRecv(UbiPAL::UbipalService::BeginRecvFlags::NON_BLOCKING);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failed to start receiving: " << UbiPAL::GetErrorDescription(status) << std::endl;
        us.EndRecv();
        return status;
    }

    // every 3 seconds, broadcast namespace certificate request
    time_t name_request = std::clock() + 3 * CLOCKS_PER_SEC;
    while (true)
    {
        // on each interval
        if (std::clock() > name_request)
        {
            // update the interval
            name_request = std::clock() + 3 * CLOCKS_PER_SEC;

            // first send THIS name so other services can reply
            status = us.SendName(0, NULL);
            if (status != UbiPAL::SUCCESS)
            {
                std::cout << "Failed to broadcast name: " << UbiPAL::GetErrorDescription(status) << std::endl;
                continue;
            }

            // then request names from other services
            status = us.RequestCertificate(0, std::string(), NULL);
            if (status != UbiPAL::SUCCESS)
            {
                std::cout << "Failed to send namespace certificate: " << UbiPAL::GetErrorDescription(status) << std::endl;
                continue;
            }

            // fetch the names
            std::vector<UbiPAL::NamespaceCertificate> names;
            status = us.GetNames(UbiPAL::UbipalService::GetNamesFlags::INCLUDE_UNTRUSTED | UbiPAL::UbipalService::GetNamesFlags::INCLUDE_TRUSTED, names);
            if (status != UbiPAL::SUCCESS)
            {
                std::cout << "Failed to get names: " << UbiPAL::GetErrorDescription(status) << std::endl;
                continue;
            }

            // request all ACLs from each
            for (unsigned int i = 0; i < names.size(); ++i)
            {
                status = us.RequestAclsFromName(0, names[i].id, &names[i], FetchAcls);
                if (status != UbiPAL::SUCCESS)
                {
                    std::cout << "Failed to request acls for " << names[i].id << std::endl;
                }
            }

            // and print them to the screen
            std::cout << "This service knows " << names.size() << " other services." << std::endl;
            std::vector<UbiPAL::AccessControlList> acls;
            for (unsigned int i = 0; i < names.size(); ++i)
            {
                acls.clear();
                status = us.GetAclsForName(names[i].id, acls);
                if (status != UbiPAL::SUCCESS && status != UbiPAL::NOT_FOUND)
                {
                    std::cout << "GetAclsForName: " << UbiPAL::GetErrorDescription(status) << std::endl;
                    continue;
                }
                std::cout << i << ": " << names[i].id << std::endl;
                std::cout << "    Service has " << acls.size() << " ACLs." << std::endl;
            }
        }

        sched_yield();
    }

}
