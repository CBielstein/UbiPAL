// Cameron Bielstein, 3/16/15
// phone.cpp
// Part of the telephone example for UbiPAL

// cin
#include <iostream>

// UbiPAL
#include <ubipal/ubipal_service.h>
#include <ubipal/error.h>
#include <ubipal/log.h>

static const std::string HOUSE = "D41F2A49804D10A478A6E895D92F09B257A70DFDE3560DCC53A131E28C7A127B6A2CF07F52BE069918522967F6A854CDB9C3E5B20770EA92774E44764CB1CEC7DBB48403F4AEC12E3852A5FEBC0B8D9F8E9D8CADC0E60594BE9F3DB974587ECF5633E2C4A0D17D996D9FD3C563AC3CF14DCBE138B7C6D5E58B0CCB744E84F829-03";
static const std::string BED = "CB51A2D122CC732F4EB7F106B36CD670F2086AFB5F3F91625E87292871797D7F2CC6E3F35384F48DB9AC482F8AD05DA5C43F3BC593D3BBF56B3F3DADFAFA33A1355ED6A390F294B8636F9FF3D5BFB3D4BE67EE68B53C4D1A689B0D9449FB3ACA3A5BECAB4133202AA0674059F68B940E3E5C3C34DC5B38F3F40AF5F0342F258D-03";

int Ring(UbiPAL::UbipalService* us, UbiPAL::Message message)
{
    std::string caller_id((char*)message.argument, message.arg_len);

    std::cout << "Ring! Ring! Call from: " << caller_id << std::endl;
    if (us != nullptr)
    {
        us->ReplyToMessage(0, &message, (const unsigned char*)"Ring...ring...", strlen("Ring...ring..."));
    }

    return UbiPAL::SUCCESS;
}

int main(int argc, char** argv)
{
    int status = UbiPAL::SUCCESS;

    // log configuration
    UbiPAL::Log::SetFile("bin/examples/telephone/phonelog.txt");
    UbiPAL::Log::SetPrint(true);

    // Create a UbiPAL service on the given port
    UbiPAL::UbipalService us("examples/telephone/phone.txt");

    // create an ACL that allows anyone to use IS_HOME
    std::vector<std::string> rules;
    std::string rule = "X CAN SEND MESSAGE CALL TO " + us.GetId() + " if " + HOUSE + " CONFIRMS IS_HOME, " + BED + " CONFIRMS IS_ASLEEP";
    rules.push_back(rule);
    UbiPAL::AccessControlList acl_all;

    status = us.CreateAcl(0, "all", rules, acl_all);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failed to create acl: " << UbiPAL::GetErrorDescription(status) << std::endl;
        return status;
    }

    status = us.RegisterCallback(std::string("CALL"), Ring);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failed to send register calback: " << UbiPAL::GetErrorDescription(status) << std::endl;
        return status;
    }

    status = us.BeginRecv(UbiPAL::UbipalService::BeginRecvFlags::NON_BLOCKING);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failed to BeginRecv: " << UbiPAL::GetErrorDescription(status) << std::endl;
        return status;
    }

    std::cout << "Commands: " << std::endl
                              << "    s: Sends NamespaceCertificate." << std::endl
                              << "    q: Quits." << std::endl;

    char command;
    while(1)
    {
        std::cin >> command;
        switch(command)
        {
            case 'q': return status;
            case 's':
                std::cout << "Sending namespace cert." << std::endl;
                status = us.SendName(0, NULL);
                if (status != UbiPAL::SUCCESS)
                {
                    std::cout << UbiPAL::GetErrorDescription(status) << std::endl;
                }
                break;
            default: continue;
        }
    }

    return status;
}
