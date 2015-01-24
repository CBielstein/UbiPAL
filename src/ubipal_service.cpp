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

// Networking
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

// OpenSSL
#include <openssl/err.h>

namespace UbiPAL
{
    UbipalService::UbipalService() : UbipalService(NULL, NULL) {}

    UbipalService::UbipalService(const RSA* const _private_key, const char* const _port)
    {
        int status = SUCCESS;
        int returned_value;
        struct addrinfo hints;
        struct addrinfo* server_info = nullptr;
        struct addrinfo* itr = nullptr;
        const int yes = 1;
        struct sockaddr_in bound_sock;
        socklen_t addr_len = 0;

        // either generate or copy the private key
        if (_private_key == nullptr)
        {
            status = RsaWrappers::GenerateRsaKey(private_key);
            if (status != SUCCESS)
            {
                Log::Line(Log::EMERG, "UbipalService::UbipalService: Constructor failed to generate rsa key: %d, %s",
                          status, GetErrorDescription(status));
                goto exit;
            }
        }
        else
        {
            status = RsaWrappers::CopyKey(_private_key, private_key);
            if (status != SUCCESS)
            {
                Log::Line(Log::EMERG, "UbipalService::UbipalService: CopyKey failed: %s", GetErrorDescription(status));
                goto exit;
            }
        }

        // open socket
        // Code relied on examples from http://beej.us/guide/bgnet/output/html/multipage/clientserver.html#simpleserver

        //set hints
        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;

        // binding to zero gives an OS assigned port
        if (_port == nullptr)
        {
            returned_value = getaddrinfo(NULL, "0", &hints, &server_info);
        }
        else
        {
            returned_value = getaddrinfo(NULL, _port, &hints, &server_info);
        }

        if (returned_value != 0)
        {
            Log::Line(Log::EMERG, "UbipalService::UbipalService: Constructor failed to getaddrinfo: %d, %s",
                      returned_value, gai_strerror(returned_value));
            goto exit;
        }

        // iterate through results and bind to the first successful result
        for (itr = server_info; itr != nullptr; itr = itr->ai_next)
        {
            sockfd = socket(itr->ai_family, itr->ai_socktype, itr->ai_protocol);
            if (sockfd == -1)
            {
                Log::Line(Log::DEBUG, "UbipalService::UbipalService: Failed to create a socket: %d, %s", errno, strerror(errno));
                continue;
            }

            returned_value = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
            if (returned_value == -1)
            {
                Log::Line(Log::DEBUG, "UbipalService::UbipalService: Failed to set socket option SOL_SOCKET, SO_REUSEADDR, yes: %d, %s", errno, strerror(errno));
                continue;
            }

            returned_value = bind(sockfd, itr->ai_addr, itr->ai_addrlen);
            if (returned_value == -1)
            {
                Log::Line(Log::DEBUG, "UbipalService::UbipalService: Failed to bind to a port: %d, %s", errno, strerror(errno));
                continue;
            }

            break;
        }

        if (itr == nullptr)
        {
            Log::Line(Log::EMERG, "UbipalService::UbipalService: All attempts to bind a socket have failed. This UbipalService was not initialized correctly.");
            sockfd = -2;
            goto exit;
        }

        addr_len = sizeof(struct sockaddr_in);
        returned_value = getsockname(sockfd, (struct sockaddr*)&bound_sock, &addr_len);
        if (returned_value == -1)
        {
            Log::Line(Log::EMERG, "UbipalService::UbipalService:: getsockname failed: %d, %s", returned_value, strerror(returned_value));
            goto exit;
        }

        port = std::to_string(ntohs(bound_sock.sin_port));

        exit:
            freeaddrinfo(server_info);
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
