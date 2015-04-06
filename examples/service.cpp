// Cameron Bielstein, 4/5/15
// service.cpp
// A simple service to be discovered

#include <ubipal/ubipal_service.h>
#include <iostream>// cout
#include <vector>  // vector

int main ()
{
    int status = UbiPAL::SUCCESS;

    // Create service
    UbiPAL::UbipalService us;
    std::cout << "Started service " << us.GetId() << std::endl;

    UbiPAL::AccessControlList acl;
    std::vector<std::string> empty;
    us.CreateAcl(0, "first", empty, acl);
    us.CreateAcl(UbiPAL::UbipalService::CreateAclFlags::PRIVATE, "second", empty, acl);
    us.CreateAcl(0, "second", empty, acl);

    // Start receiving for message replies
    status = us.BeginRecv(UbiPAL::UbipalService::BeginRecvFlags::DONT_PUBLISH_NAME);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failed to start receiving: " << UbiPAL::GetErrorDescription(status) << std::endl;
        us.EndRecv();
        return status;
    }

    return status;
}
