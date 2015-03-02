// Cameron Bielstein, 2/22/15
// print_id.cpp
// Prints the id of a given UbiPAL service from a file

#include <ubipal/ubipal_service.h>
#include <iostream>

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        std::cout << "Usage: ./create_service <file>" << std::endl;
        return -1;
    }

    UbiPAL::UbipalService us(argv[1]);

    std::cout << us.GetId() << std::endl;

    return 0;
}
