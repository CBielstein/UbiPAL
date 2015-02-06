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

// Standard
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sstream>

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
        std::stringstream pub_key_string;

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

        status = RsaWrappers::PublicKeyToString(private_key, id);
        if (status != SUCCESS)
        {
            Log::Line(Log::EMERG, "UbipalService::UbipalSErvice: Constructor failed to set ID from private key: %s", GetErrorDescription(status));
            goto exit;
        }

        // open socket
        // Code relies on examples from http://beej.us/guide/bgnet/output/html/multipage/clientserver.html#simpleserver
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

    int UbipalService::BeginRecv(const uint32_t flags)
    {
        FUNCTION_START;
        void* returned_ptr = nullptr;

        if ((flags & ~(BeginRecvFlags::DONT_PUBLISH_NAME | BeginRecvFlags::NON_BLOCKING)) != 0)
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

        // if flag isn't specified, go ahead and broadcast the name
        if ((flags & BeginRecvFlags::DONT_PUBLISH_NAME) != 0)
        {
            // TODO
            /*status = SendName(NULL);
            if (status != SUCCESS)
            {
                Log::Line(Log::EMERG, "UbipalService::BeginRecv: SendName(NULL) failed: %s", GetErrorDescription(status));
                RETURN_STATUS(status);
            }*/
        }

        // spin a new thread to begin receiving, probably in a different function?
        if ((flags & BeginRecvFlags::NON_BLOCKING)!= 0)
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
        char buf[MAX_MESSAGE_SIZE];
        UbipalService* us = nullptr;
        std::unordered_map<std::string, UbipalCallback>::iterator found;
        int conn_fd = 0;
        BaseMessage base_message;
        Message message;
        NamespaceCertificate name_cert;
        AccessControlList acl;
        uint32_t size = 0;
        std::unordered_map<std::string, NamespaceCertificate>::iterator trusted_itr;
        std::unordered_map<std::string, NamespaceCertificate>::iterator untrusted_itr;
        std::unordered_map<std::string, std::vector<AccessControlList>>::iterator acl_itr;
        std::pair<std::unordered_map<std::string, std::vector<AccessControlList>>::iterator, bool> emplace_ret;
        std::vector<AccessControlList> acl_vector;

        if (hc_args == nullptr)
        {
            Log::Line(Log::WARN, "UBipalService::HandleConnection: null arg");
            RETURN_STATUS(NULL_ARG);
        }

        us = ((HandleConnectionArguments*)hc_args)->us;
        conn_fd = ((HandleConnectionArguments*)hc_args)->conn_fd;

        returned_value = recv(conn_fd, buf, MAX_MESSAGE_SIZE, 0);
        if (returned_value < 0)
        {
            Log::Line(Log::INFO, "UbipalService::HandleConnection: receive failed: %s", strerror(errno));
            RETURN_STATUS(NETWORKING_FAILURE);
        }
        size = returned_value;

        // TODO crypto!
        // check if raw bytes need to be decrypted
        // check if signature matches? maybe lower down

        // interpret message
        status = base_message.Decode(buf, returned_value);
        if (status < 0)
        {
            Log::Line(Log::WARN, "UbipalService::HandleConnection: BaseMessage::Decode failed: %s", GetErrorDescription(status));
            RETURN_STATUS(status)
        }

        switch(base_message.type)
        {
            case MessageType::MESSAGE:
                // decode as Message
                status = message.Decode(buf, size);
                if (status < 0)
                {
                    Log::Line(Log::WARN, "UbipalService::HandleConnection: Message::Decode failed: %s", GetErrorDescription(status));
                    RETURN_STATUS(status);
                }

                // TODO check against ACLs

                // find function to call
                found = us->callback_map.find(message.message);
                if (found == us->callback_map.end())
                {
                    Log::Line(Log::WARN, "UbipalService::HandleConnection: Does not have the appropriate callback.");
                    RETURN_STATUS(GENERAL_FAILURE);
                }

                status = found->second(message.message, message.argument, message.arg_len);
                if (status != SUCCESS)
                {
                    Log::Line(Log::WARN, "UbipalService::HandleConnection: Callback returned %d, %s", status, GetErrorDescription(status));
                    RETURN_STATUS(status);
                }

                break;
            case MessageType::NAMESPACE_CERTIFICATE:
                // decode as namespace certificate
                status = name_cert.Decode(buf, size);
                if (status < 0)
                {
                    Log::Line(Log::WARN, "UbipalService::HandleConnection: NamespaceCertificate::Decode failed: %s", GetErrorDescription(status));
                    RETURN_STATUS(status);
                }

                // check if it was sent by a trusted source
                trusted_itr = us->trusted_services.find(name_cert.from);
                if (trusted_itr != us->trusted_services.end())
                {
                    // we trust the sender, see if the actual name is in our trusted list.
                    trusted_itr = us->trusted_services.find(name_cert.id);
                    if (trusted_itr != us->trusted_services.end())
                    {
                        // it is, so update it
                        trusted_itr->second = name_cert;
                    }
                    else
                    {
                        // it isn't, so add it
                        us->trusted_services.emplace(name_cert.id, name_cert);
                    }
                }
                else
                {
                    // check if the actual name is in the untrusted
                    untrusted_itr = us->untrusted_services.find(name_cert.id);
                    if (untrusted_itr != us->trusted_services.end())
                    {
                        // it is, so update it
                        untrusted_itr->second = name_cert;
                    }
                    else
                    {
                        // it isn't, so add it
                        us->untrusted_services.emplace(name_cert.id, name_cert);
                    }
                }

                break;
            case MessageType::ACCESS_CONTROL_LIST:
                // decode as namespace certificate
                status = acl.Decode(buf, size);
                if (status < 0)
                {
                    Log::Line(Log::WARN, "UbipalService::HandleConnection: AccessControlList::Decode failed: %s", GetErrorDescription(status));
                    RETURN_STATUS(status);
                }

                // find all the acls from this service
                acl_itr = us->external_acls.find(acl.id);
                if (acl_itr == us->external_acls.end())
                {
                    // wasnt found, so add it
                    acl_vector.push_back(acl);
                    emplace_ret = us->external_acls.emplace(acl.id, acl_vector);
                    if (emplace_ret.second == false)
                    {
                        Log::Line(Log::EMERG, "UbipalService::HandleConnection: external_acls.emplace failed");
                        RETURN_STATUS(GENERAL_FAILURE);
                    }
                }
                else
                {
                    // was found, so check through the associated vector to see if this is an update (based on ID)
                    for (unsigned int i = 0; i < acl_itr->second.size(); ++i)
                    {
                        if (acl_itr->second[i].msg_id.compare(acl.msg_id))
                        {
                            // we've already heard this one, so we're done.
                            RETURN_STATUS(SUCCESS);
                        }
                    }

                    // if we get here, we haven't heard it, so we're adding it
                    acl_itr->second.push_back(acl);
                }

                fprintf(stderr, "ACLs received: %lu\n", us->external_acls.size());
                break;
            default: RETURN_STATUS(GENERAL_FAILURE);
        }

        exit:
            if (status != SUCCESS)
            {
                Log::Line(Log::DEBUG, "UbipalService::HandleConnection: Exiting failure: %s", GetErrorDescription(status));
            }
            return NULL;
    }

    int UbipalService::SendData(const std::string& address, const std::string& port, const char* const data, const uint32_t data_len) const
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

    int UbipalService::RegisterCallback(const std::string& message, const UbipalCallback callback)
    {
        int status = SUCCESS;
        std::pair<std::unordered_map<std::string, UbipalCallback>::iterator, bool> returned_pair;

        callbacks_mutex.lock();

            // try to insert
            returned_pair = callback_map.emplace(message, callback);
            if (returned_pair.second == true)
            {
                callbacks_mutex.unlock();
                return status;
            }

            // if there's a collision on message, update the entry
            returned_pair.first->second = callback;

        callbacks_mutex.unlock();

        return status;
    }

    int UbipalService::SendMessage(const uint32_t flags, const NamespaceCertificate& to, const std::string& message, const char* const arg, const uint32_t arg_len)
    {
        FUNCTION_START;
        Message* msg = nullptr;
        HandleSendMessageArguments* sm_args = nullptr;

        // check args
        if (to.address.empty() || to.port.empty())
        {
            Log::Line(Log::WARN, "UbipalService::SendMessage: to doesn't have sufficient information");
            RETURN_STATUS(INVALID_ARG);
        }
        else if (message.empty())
        {
            Log::Line(Log::WARN, "UbipalService::SendMessage: message is empty");
            RETURN_STATUS(INVALID_ARG);
        }
        else if ((flags & ~(SendMessageFlags::NONBLOCKING)) != 0)
        {
            Log::Line(Log::WARN, "UbipalService::SendMessage: called with invalid flags");
            RETURN_STATUS(INVALID_ARG);
        }

        msg = new Message(arg, arg_len);
        msg->to = to.id;
        msg->from = id;
        msg->message = message;

        sm_args = new HandleSendMessageArguments(this);
        sm_args->address = to.address;
        sm_args->port = to.port;
        sm_args->msg = msg;

        if ((flags & SendMessageFlags::NONBLOCKING) != 0)
        {
            // if nonblocking, spin off a thread
            threads_mutex.lock();
            send_threads.emplace(send_threads.end());
            returned_value = pthread_create(&send_threads[send_threads.size() - 1], NULL, HandleSendMessage, sm_args);
            threads_mutex.unlock();
            if (returned_value != 0)
            {
                Log::Line(Log::EMERG, "UbipalService::SendMessage: pthread_create failed: %d", returned_value);
                RETURN_STATUS(THREAD_FAILURE);
            }
        }
        else
        {
            // call from here!
            HandleSendMessage(sm_args);
        }

        exit:
            FUNCTION_END;
    }

    UbipalService::HandleSendMessageArguments::HandleSendMessageArguments() : us(nullptr) {}
    UbipalService::HandleSendMessageArguments::HandleSendMessageArguments(const UbipalService* const _us) : us(_us) {}

    void* UbipalService::HandleSendMessage(void* args)
    {
        FUNCTION_START;
        HandleSendMessageArguments* sm_args = nullptr;
        char* bytes = nullptr;
        int bytes_length = 0;

        if (args == nullptr)
        {
            Log::Line(Log::WARN, "UbipalService::HandleSendMessage: null argument");
            RETURN_STATUS(NULL_ARG);
        }

        sm_args = static_cast<HandleSendMessageArguments*>(args);

        returned_value = sm_args->msg->EncodedLength();
        if (returned_value < 0)
        {
            Log::Line(Log::EMERG, "UbipalService::HandleSendMessage: EncodedLength had error: %s", GetErrorDescription(returned_value));
            RETURN_STATUS(returned_value);
        }
        bytes_length = returned_value;

        bytes = (char*)malloc(bytes_length);
        if (bytes == nullptr)
        {
            Log::Line(Log::EMERG, "UbipalService::HandleSendMessage: malloc failed");
            RETURN_STATUS(MALLOC_FAILURE);
        }

        status = sm_args->msg->Encode(bytes, bytes_length);
        if (status < 0)
        {
            Log::Line(Log::EMERG, "UbipalService::HandleSendMessage: Encode failed: %s", GetErrorDescription(status));
            RETURN_STATUS(status);
        }
        else
        {
            status = SUCCESS;
        }

        status = sm_args->us->SendData(sm_args->address, sm_args->port, bytes, bytes_length);
        if (status < 0)
        {
            Log::Line(Log::EMERG, "UbipalService::HandleSendMessage: Encode failed: %s", GetErrorDescription(status));
            RETURN_STATUS(status);
        }
        else
        {
            status = SUCCESS;
        }

        exit:
            free(sm_args->msg);
            free(sm_args);
            free(bytes);
            return nullptr;
    }

    int UbipalService::SetDescription(const std::string& desc)
    {
        description = desc;
        return SUCCESS;
    }

    int UbipalService::SendName(const uint32_t flags, const NamespaceCertificate* const send_to)
    {
        FUNCTION_START;
        NamespaceCertificate* msg = nullptr;
        HandleSendMessageArguments* sm_args = nullptr;

        if ((flags & ~(SendMessageFlags::NONBLOCKING)) != 0)
        {
            Log::Line(Log::WARN, "UbipalService::SendMessage: called with invalid flags");
            RETURN_STATUS(INVALID_ARG);
        }

        msg = new NamespaceCertificate();
        msg->to = send_to->id;
        msg->from = id;
        msg->id = id;
        msg->description = description;
        msg->address = address;
        msg->port = port;

        sm_args = new HandleSendMessageArguments(this);
        sm_args->address = send_to->address;
        sm_args->port = send_to->port;
        sm_args->msg = msg;

        if ((flags & SendMessageFlags::NONBLOCKING) != 0)
        {
            // if nonblocking, spin off a thread
            threads_mutex.lock();
            send_threads.emplace(send_threads.end());
            returned_value = pthread_create(&send_threads[send_threads.size() - 1], NULL, HandleSendMessage, sm_args);
            threads_mutex.unlock();
            if (returned_value != 0)
            {
                Log::Line(Log::EMERG, "UbipalService::SendMessage: pthread_create failed: %d", returned_value);
                RETURN_STATUS(THREAD_FAILURE);
            }
        }
        else
        {
            // call from here!
            HandleSendMessage(sm_args);
        }

        exit:
            FUNCTION_END;
    }

    int UbipalService::SendName(const uint32_t flags, const std::string& address, const std::string& port)
    {
        NamespaceCertificate  nc;
        nc.address = address;
        nc.port = port;

        return SendName(flags, &nc);
    }

    int UbipalService::GetNames(const uint32_t flags, std::vector<NamespaceCertificate>& names)
    {
        int status = SUCCESS;

        // check flags
        if ((flags & ~(GetNamesFlags::INCLUDE_UNTRUSTED | GetNamesFlags::INCLUDE_TRUSTED)) != 0)
        {
            Log::Line(Log::WARN, "UbipalService::GetNames: passed invalid flag");
            return INVALID_ARG;
        }

        // empty vector
        names.clear();

        // add untrusted, if flagged
        if ((flags & GetNamesFlags::INCLUDE_UNTRUSTED) != 0)
        {
            std::unordered_map<std::string, NamespaceCertificate>::iterator untrusted_itr;
            for (untrusted_itr = untrusted_services.begin(); untrusted_itr != untrusted_services.end(); ++untrusted_itr)
            {
                names.push_back(untrusted_itr->second);
            }
        }

        // add trusted, if flagged
        if ((flags & GetNamesFlags::INCLUDE_TRUSTED) != 0)
        {
            std::unordered_map<std::string, NamespaceCertificate>::iterator trusted_itr;
            for (trusted_itr = trusted_services.begin(); trusted_itr != trusted_services.end(); ++trusted_itr)
            {
                names.push_back(trusted_itr->second);
            }
        }

        return status;
    }
}