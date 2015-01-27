// Cameron Bielstein, 1/19/15
// ubipal_service.cpp
// Representation of a service in the UbiPAL namespace

// Header
#include "ubipal_service.h"

// UbiPAL
#include "log.h"
#include "error.h"
#include "rsa_wrappers.h"
#include "macros.h"
#include "messages.h"

// Standard
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

// Networking
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

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
        char current_addr[INET6_ADDRSTRLEN];

        // initially not receiving
        receiving = false;

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
        address = std::string(inet_ntop(AF_INET, &(bound_sock.sin_addr), current_addr, INET6_ADDRSTRLEN));
        if (address.empty())
        {
            Log::Line(Log::EMERG, "UbipalService::UbipalService: inet_ntop failed: %d, %s", errno, strerror(errno));
            goto exit;
        }

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

    int UbipalService::BeginRecv(const uint32_t flags, const UbipalCallback& received_callback)
    {
        FUNCTION_START;
        void* returned_ptr = nullptr;

        if ((flags & ~(BeginRecvFlags::DONT_PUBLISH_NAME)) != 0)
        {
            Log::Line(Log::WARN, "UbipalService::BeginRecv: Invalid flags.");
            RETURN_STATUS(INVALID_ARG);
        }

        // use mutual exclusion and state variables to ensure only one thread is receiving at once
        receiving_mutex.lock();
            if (receiving)
            {
                Log::Line(Log::INFO, "UbipalService::BeginRecv: Already receiving. Return!");
                receiving_mutex.unlock();
                RETURN_STATUS(MULTIPLE_RECV);
            }
            else
            {
                receiving = true;
                Log::Line(Log::INFO, "UbipalService::BeginRecv: Beginning receiving on port %s", port.c_str());
            }
        receiving_mutex.unlock();

        if (received_callback == nullptr)
        {
            Log::Line(Log::DEBUG, "UbipalService::BeginRecv: No callback specified.");
        }

        // if flag isn't specified, go ahead and broadcast the name
        if ((flags & BeginRecvFlags::DONT_PUBLISH_NAME) != 0)
        {
            status = SendName(NULL);
            if (status != SUCCESS)
            {
                Log::Line(Log::EMERG, "UbipalService::BeginRecv: SendName(NULL) failed: %s", GetErrorDescription(status));
                RETURN_STATUS(status);
            }
        }

        // spin a new thread to begin receiving, probably in a different function?
        if ((flags & BeginRecvFlags::NON_BLOCKING) != 0)
        {
            threads_mutex.lock();
            recv_threads.emplace(recv_threads.end());
            returned_value = pthread_create(&recv_threads[recv_threads.size() - 1], NULL, Recv, this);
            threads_mutex.unlock();
            if (returned_value != 0)
            {
                Log::Line(Log::EMERG, "UbipalService::BeginRecv: pthread_create failed: %d", returned_value);
                RETURN_STATUS(THREAD_FAILURE);
            }
        }
        else
        {
            returned_ptr  = Recv(this);
            if (returned_ptr != nullptr)
            {
                status = *((int*)returned_ptr);
                if (status != SUCCESS)
                {
                    Log::Line(Log::EMERG, "UbipalService:BeginRecv: blocking Recv not successful: %s", GetErrorDescription(status));
                    RETURN_STATUS(status);
                }
            }
            else
            {
                Log::Line(Log::EMERG, "UbipalService::BeginRecv: blocking Recv returned null");
                RETURN_STATUS(NETWORKING_FAILURE);
            }
        }

        exit:
            FUNCTION_END;
    }

    int UbipalService::EndRecv()
    {
        receiving_mutex.lock();
            receiving = false;
        receiving_mutex.unlock();
        return SUCCESS;
    }

    void* UbipalService::Recv(void* arg)
    {
        FUNCTION_START;
        int connect_fd = 0;
        UbipalService* us = nullptr;
        HandleConnectionArguments* hc_args = nullptr;

        if (arg == nullptr)
        {
            Log::Line(Log::WARN, "UbipalService::Recv: null argument.");
            RETURN_STATUS(NULL_ARG);
        }

        us = (UbipalService*)arg;

        // listen on sockfd for 10 queued connections
        returned_value = listen(us->sockfd, 10);
        if (returned_value != 0)
        {
            Log::Line(Log::EMERG, "UbipalService::Recv: listen failed: %d, %s", errno, strerror(errno));
            RETURN_STATUS(NETWORKING_FAILURE);
        }

        // while this service is receiving
        while(us->receiving)
        {
            connect_fd = accept(us->sockfd, NULL, NULL);
            if (connect_fd == -1)
            {
                // if there was an error, log it and give up on this connection, there are other connections in the sea
                Log::Line(Log::WARN, "UbipalService::Recv: A call to accept failed: %d, %s", errno, strerror(errno));
                continue;
            }

            // new thread!!
            us->threads_mutex.lock();
            hc_args = new HandleConnectionArguments(us, connect_fd);
            us->recv_threads.emplace(us->recv_threads.end());
            returned_value = pthread_create(&(us->recv_threads[us->recv_threads.size() - 1]), NULL, HandleConnection, hc_args);
            us->threads_mutex.unlock();
            if (returned_value != 0)
            {
                Log::Line(Log::EMERG, "UbipalService::Recv: pthread_create failed: %d", returned_value);
                RETURN_STATUS(THREAD_FAILURE);
            }

        }

        exit:
            if (us == nullptr)
            {
                return NULL;
            }
            else
            {
                us->recv_status = status;
                return &us->recv_status;
            }
    }

    void* UbipalService::HandleConnection(void* hc_args)
    {
        FUNCTION_START;
        char msg[MAX_MESSAGE_SIZE];
        //UbipalService* us = nullptr;
        int conn_fd = 0;

        if (hc_args == nullptr)
        {
            Log::Line(Log::WARN, "UBipalService::HandleConnection: null arg");
            RETURN_STATUS(NULL_ARG);
        }

        //us = ((HandleConnectionArguments*)hc_args)->us;
        conn_fd = ((HandleConnectionArguments*)hc_args)->conn_fd;

        returned_value = recv(conn_fd, msg, MAX_MESSAGE_SIZE, 0);
        if (returned_value < 0)
        {
            Log::Line(Log::INFO, "UbipalService::HandleConnection: receive failed: %s", strerror(errno));
            RETURN_STATUS(NETWORKING_FAILURE);
        }

        // this is for debugging
        Log::Line(Log::DEBUG, "UbipalService::HandleConnection");
        fprintf(stderr, "I'm here.\n");
        fprintf(stderr, "%s\n", msg);

        exit:
            if (status != SUCCESS)
            {
                Log::Line(Log::DEBUG, "UbipalService::HandleConnection: Exiting failure: %s", GetErrorDescription(status));
            }
            return NULL;
    }

    int UbipalService::SendData(const std::string& address, const std::string& port, const char* const data, const uint32_t data_len)
    {
        FUNCTION_START;
        int conn_fd = 0;
        struct addrinfo* dest_info = nullptr;
        struct addrinfo* itr = nullptr;
        struct addrinfo hints;
        void* returned_ptr = nullptr;

        // set hints
        returned_ptr = memset(&hints, 0, sizeof(struct addrinfo));
        if (returned_ptr == nullptr)
        {
            Log::Line(Log::EMERG, "UbipalService::SendData: memset failed.");
            RETURN_STATUS(MALLOC_FAILURE);
        }
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        returned_value = getaddrinfo(address.c_str(), port.c_str(), &hints, &dest_info);
        if (returned_value != 0)
        {
            Log::Line(Log::EMERG, "UbipalService::SendData: getaddrinfo failed: %s", gai_strerror(returned_value));
            RETURN_STATUS(NETWORKING_FAILURE);
        }

        // bind and connect
        for (itr = dest_info; itr != nullptr; itr = itr->ai_next)
        {
            conn_fd = socket(itr->ai_family, itr->ai_socktype, itr->ai_protocol);
            if (returned_value == -1)
            {
                Log::Line(Log::DEBUG, "UbipalService::SendData: Failed an attempt to bind.");
                continue;
            }

            returned_value = connect(conn_fd, itr->ai_addr, itr->ai_addrlen);
            if (returned_value != 0)
            {
                Log::Line(Log::DEBUG, "UbipalService::SendData: Failed an attempt to connect: %s", strerror(errno));
                close(conn_fd);
                continue;
            }

            break;
        }

        if (itr == nullptr)
        {
            Log::Line(Log::WARN, "UbipalService::SendData: Completely failed to connect to %s:%s", address.c_str(), port.c_str());
            RETURN_STATUS(NETWORKING_FAILURE);
        }

        // send data
        returned_value = send(conn_fd, data, data_len, 0);
        if (returned_value == -1)
        {
            Log::Line(Log::EMERG, "UbipalService::SendData: send failed: %s", strerror(errno));
            RETURN_STATUS(NETWORKING_FAILURE);
        }

        exit:
            close(conn_fd);
            freeaddrinfo(dest_info);
            FUNCTION_END;
    }

    int UbipalService::SetAddress(const std::string& addr)
    {
        address = addr;
        return SUCCESS;
    }

    int UbipalService::SetPort(const std::string& prt)
    {
        port = prt;
        return SUCCESS;
    }
}
