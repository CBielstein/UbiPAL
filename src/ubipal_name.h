// Cameron Bielstein, 1/19/15
// ubipal_name.h
// Representation of a name in the UbiPAL namespace

#ifndef UBIPAL_SRC_UBIPAL_NAME_H
#define UBIPAL_SRC_UBIPAL_NAME_H

// Standard
#include <string>

// OpenSSL
#include <openssl/rsa.h>

namespace UbiPAL
{
    // UbipalName
    // Representation of a remote name in the namespace
    // Similar to a UbipalService, but only represents a name, cannot send or receive messages
    class UbipalName
    {
        public:
            // key works as a unique identifier
            std::string id;
            std::string description;
            std::string address;
            std::string port;

            // default constructor
            UbipalName();

            // copy constructor
            UbipalName(const UbipalName& other);
    };
}

#endif
