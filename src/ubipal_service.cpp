// Cameron Bielstein, 1/19/15
// ubipal_service.cpp
// Representation of a service in the UbiPAL namespace

// Header
#include "ubipal_service.h"

// UbiPAL
#include "log.h"
#include "error.h"
#include "rsa_wrappers.h"

// Standard
#include <string.h>

// OpenSSL
#include <openssl/err.h>

namespace UbiPAL
{
    UbipalService::UbipalService()
    {
        int status = RsaWrappers::GenerateRsaKey(private_key);
        if (status != SUCCESS)
        {
            Log::Line(Log::EMERG, "UbipalService::UbipalService: Default constructor failed to generate rsa key: %d, %s",
                      status, GetErrorDescription(status));
        }

        // open socket
    }

    UbipalService::UbipalService(const RSA* const _private_key)
    {
        private_key = RSA_new();
        if (private_key == nullptr)
        {
            Log::Line(Log::EMERG,
                      "UbipalService::UbipalService: Copy constructor failed to allocate new RSA key for private_key. RSA_new error: %s",
                      ERR_error_string(ERR_get_error(), NULL));
        }

        memcpy(private_key, _private_key, sizeof(RSA));

        // open socket
    }

    UbipalService::~UbipalService()
    {
        RSA_free(private_key);

        // close socket
    }
}
