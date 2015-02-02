// Cameron Bielstein, 1/19/15
// ubipal_name.cpp
// Representation of a name in the UbiPAL namespace

// Header
#include "ubipal_name.h"

// UbiPAL
#include "log.h"

// Standard
#include <string.h>

// OpenSSL
#include <openssl/rsa.h>
#include <openssl/err.h>

namespace UbiPAL
{
    UbipalName::UbipalName() :
        id(), description(), address(), port() {}

    UbipalName::UbipalName(const UbipalName& other) :
        id(other.id), description(other.description), address(other.address), port(other.port) {}
}
