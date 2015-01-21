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
        public_key(nullptr), address(), port() {}

    UbipalName::UbipalName(const UbipalName& other) :
        address(other.address), port(other.port)
    {
        public_key = RSA_new();
        if (public_key == nullptr)
        {
            Log::Line(Log::EMERG,
                      "UbipalName::UbipalName: Copy constructor failed to allocate new RSA key for public_key. RSA_new error: %s",
                      ERR_error_string(ERR_get_error(), NULL));
        }

        memcpy(public_key, other.public_key, sizeof(RSA));
    }

    UbipalName::~UbipalName()
    {
        RSA_free(public_key);
    }
}
