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
#include <unistd.h>

// OpenSSL
#include <openssl/err.h>

namespace UbiPAL
{
    UbipalService::UbipalService() : UbipalService(NULL, NULL) {}

    UbipalService::UbipalService(const RSA* const _private_key, const char* const port)
    {
        private_key = RSA_new();
        if (private_key == nullptr)
        {
            Log::Line(Log::EMERG,
                      "UbipalService::UbipalService: Constructor failed to allocate private_key. RSA_new error: %s",
                      ERR_error_string(ERR_get_error(), NULL));
            goto exit;
        }

        // either generate or copy the private key
        if (_private_key == nullptr)
        {
            int status = RsaWrappers::GenerateRsaKey(private_key);
            if (status != SUCCESS)
            {
                Log::Line(Log::EMERG, "UbipalService::UbipalService: Default constructor failed to generate rsa key: %d, %s",
                          status, GetErrorDescription(status));
                goto exit;
            }
        }
        else
        {
            memcpy(private_key, _private_key, sizeof(RSA));
        }

        // open socket

        exit:
            return;
    }

    UbipalService::~UbipalService()
    {
        // free the private key
        RSA_free(private_key);

        // close socket
        close(sockfd);
    }
}
