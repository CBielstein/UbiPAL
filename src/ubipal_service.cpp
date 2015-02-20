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
#include <ifaddrs.h>

// OpenSSL
#include <openssl/err.h>

namespace UbiPAL
{
    UbipalService::UbipalService() : UbipalService(NULL, NULL) {}

    UbipalService::UbipalService(const std::string& file_path)
    {
        int status = SUCCESS;
        RSA* _private_key = nullptr;
        FILE* fd = nullptr;
        char buf[1024];
        char* port = nullptr;
        std::string line;

        fd = fopen(file_path.c_str(), "r");
        if (fd == nullptr)
        {
            Log::Line(Log::WARN, "UbipalService::UbipalService(const std::string& file_path): Failed to open file_path: %s", file_path.c_str());
            return;
        }

        if (fgets(buf, 1024, fd) == nullptr)
        {
            Log::Line(Log::WARN, "UbipalService::UbipalService(const std::string& file_path): fgets failed");
            return;
        }
        // remove newline, if applicable
        if (buf[strlen(buf) - 1] == '\n')
        {
            buf[strlen(buf) - 1] = '\0';
        }
        line = buf;
        status = RsaWrappers::StringToPrivateKey(line, _private_key);
        if (status != SUCCESS)
        {
            Log::Line(Log::WARN, "UbipalService::UbipalService(const std::string& file_path): StringToPrivateKey: %s", GetErrorDescription(status));
            return;
        }

        if (fgets(buf, 1024, fd) != nullptr)
        {
            if (buf[strlen(buf) - 1] == '\n')
            {
                buf[strlen(buf) - 1] = '\0';
            }
            port = buf;
        }
        else
        {
            port = NULL;
        }

        UbipalService(_private_key, port);
    }

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
        std::stringstream pub_key_string;
        struct ifaddrs* ifap = nullptr;
        struct ifaddrs* ifap_itr = nullptr;
        struct sockaddr_in* sa = nullptr;
        char* addr = nullptr;

        // Set default thread counts
        num_recv_threads = 5;
        num_send_threads = 5;

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

        returned_value = getifaddrs(&ifap);
        if (returned_value < 0)
        {
            Log::Line(Log::EMERG, "UbipalService::UbipalService: getifaddrs failed %s", strerror(returned_value));
            goto exit;
        }

        for (ifap_itr = ifap; ifap_itr != nullptr; ifap_itr = ifap_itr->ifa_next)
        {
            // register the first address not on the loopback
            if (ifap_itr->ifa_addr->sa_family == AF_INET && strncmp(ifap_itr->ifa_name, "lo", 2) != 0)
            {
                sa = (struct sockaddr_in*) ifap_itr->ifa_addr;
                addr = inet_ntoa(sa->sin_addr);
                address = std::string(addr);
                break;
            }
        }

        exit:
            freeifaddrs(ifap);
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

    int UbipalService::SaveService(const std::string& file_path)
    {
        int status = SUCCESS;
        unsigned int returned_value = 0;
        FILE* fp = nullptr;
        std::string key;

        fp = fopen(file_path.c_str(), "w");
        if (fp == nullptr)
        {
            return OPEN_FILE_FAILED;
        }

        status = RsaWrappers::PrivateKeyToString(private_key, key);
        if (status != SUCCESS)
        {
            return status;
        }

        returned_value = fwrite(key.c_str(), sizeof(char), key.size(), fp);
        if (returned_value != key.size() * sizeof(char))
        {
            return FAILED_FILE_WRITE;
        }

        returned_value = fwrite("\n", sizeof(char), 1, fp);
        if (returned_value != 1 * sizeof(char))
        {
            return FAILED_FILE_WRITE;
        }

        returned_value = fwrite(port.c_str(), sizeof(char), port.size(), fp);
        if (returned_value != port.size())
        {
            return FAILED_FILE_WRITE;
        }

        return status;
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

        // spin up thread for receiving
        us->threads_mutex.lock();
        for (unsigned int i = 0; i < us->num_recv_threads; ++i)
        {
            us->recv_threads.emplace(us->recv_threads.end());
            returned_value = pthread_create(&(us->recv_threads[us->recv_threads.size() - 1]), NULL, ConsumeConnections, us);
            if (returned_value != 0)
            {
                Log::Line(Log::WARN, "UbipalService::Recv: A call to pthread_create failed: %d", returned_value);
            }
        }
        us->threads_mutex.unlock();

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
            us->incoming_conn_mutex.lock();
            hc_args = new HandleConnectionArguments(us, connect_fd);
            us->incoming_connections.push(hc_args);
            hc_args = nullptr;
            us->incoming_conn_mutex.unlock();
            // signal a worker thread
            us->incoming_conn_cv.notify_one();
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

    void* UbipalService::ConsumeConnections(void* arg)
    {
        if (arg == nullptr)
        {
            Log::Line(Log::WARN, "UbipalService::ConsumeConnections: arg was null.");
            return NULL;
        }

        UbipalService* us = (UbipalService*)arg;
        HandleConnectionArguments* hc_args = nullptr;
        std::unique_lock<std::mutex> lock(us->incoming_conn_mutex, std::defer_lock);

        while(us->receiving)
        {
            lock.lock();

            // wait for non-empty queue
            while(us->incoming_connections.size() == 0)
            {
                us->incoming_conn_cv.wait(lock);
            }

            // grab stuff off the queue
            hc_args = us->incoming_connections.front();
            us->incoming_connections.pop();

            // unlock the queue to handle the connection
            lock.unlock();
            HandleConnection(hc_args);
        }

        return NULL;
    }

    void* UbipalService::HandleConnection(void* hc_args)
    {
        FUNCTION_START;

        char* buf = nullptr;
        char* buf_decrypted = nullptr;
        unsigned int buf_decrypted_len = 0;
        int conn_fd = 0;
        uint32_t size = 0;
        uint32_t to_len = 0;

        UbipalService* us = nullptr;
        RSA* from_pub_key = nullptr;

        BaseMessage base_message;
        Message message;
        NamespaceCertificate name_cert;
        AccessControlList acl;

        std::unordered_map<std::string, UbipalCallback>::iterator found;
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
        buf = (char*) malloc(MAX_MESSAGE_SIZE);

        returned_value = recv(conn_fd, buf, MAX_MESSAGE_SIZE, 0);
        if (returned_value < 0)
        {
            Log::Line(Log::INFO, "UbipalService::HandleConnection: receive failed: %s", strerror(errno));
            RETURN_STATUS(NETWORKING_FAILURE);
        }
        size = returned_value;

        // decryption
        // The first byte is the type, the next 4 are the size of the to field
        returned_value = BaseMessage::DecodeUint32_t(buf + 1, size, to_len);
        if (returned_value < 0)
        {
            Log::Line(Log::WARN, "UbipalService::HandleConnection: BaseMessageDecodeUint32_t failed: %s",
                      GetErrorDescription(returned_value));
            RETURN_STATUS(returned_value);
        }

        // if the two field is empty, it's a first handshake, so it's not encrypted
        if (to_len != 0)
        {
            // If the to length is nonzero, compare the next bytes against the service's id.
            // If they are the same, this is not encrypted. If they do not match, try to derypt and try again
            if (to_len != us->id.size() || memcmp(buf + 5, us->id.c_str(), us->id.size()) != 0)
            {
                // decrypt
                status = RsaWrappers::Decrypt(us->private_key, buf, size, buf_decrypted, &buf_decrypted_len);
                if (status != SUCCESS)
                {
                    Log::Line(Log::WARN, "UbipalService::HandleConnection: RsaWrapers::Decrypt failed: %s", GetErrorDescription(status));
                    RETURN_STATUS(status);
                }

                // If they still don't match, toss the message because it isn't to us
                if (memcmp(buf_decrypted + 5, us->id.c_str(), us->id.size()) != 0)
                {
                    Log::Line(Log::WARN, "UbipalService::HandleConnection: Message couldn't be interpreted, so it's tossed.");
                    RETURN_STATUS(INVALID_NETWORK_ENCODING);
                }

                // so we decrypted and it matched, put buf_decrypted in buf
                free(buf);
                buf = buf_decrypted;
                buf_decrypted = nullptr;
                size = buf_decrypted_len;
            }
        }

        // interpret message
        status = base_message.Decode(buf, size);
        if (status < 0)
        {
            Log::Line(Log::WARN, "UbipalService::HandleConnection: BaseMessage::Decode failed: %s", GetErrorDescription(status));
            RETURN_STATUS(status)
        }

        // ensure this isn't directed to somebody else
        // it's to us or it's broadcast (to nobody)
        if (base_message.to != us->id && !base_message.to.empty())
        {
            status = MESSAGE_WRONG_DESTINATION;
            Log::Line(Log::DEBUG, "UbipalService::HandleConnection: Received a message not to this service: %s", GetErrorDescription(status));
            RETURN_STATUS(status);
        }

        // convert from id to public key for validation
        status = RsaWrappers::StringToPublicKey(base_message.from, from_pub_key);
        if (status != SUCCESS)
        {
            Log::Line(Log::INFO, "UbipalService::HandleConnection: RsaWrappers::StringToPublicKey failed: %s", GetErrorDescription(status));
            RETURN_STATUS(status);
        }

        switch(base_message.type)
        {
            case MessageType::MESSAGE:

                // decode as Message
                returned_value = message.Decode(buf, size);
                if (returned_value < 0)
                {
                    Log::Line(Log::WARN, "UbipalService::HandleConnection: Message::Decode failed: %s", GetErrorDescription(returned_value));
                    RETURN_STATUS(returned_value);
                }

                // check signature
                returned_value = RsaWrappers::VerifySignedDigest(from_pub_key, (unsigned char*)buf, returned_value,
                                                                 (unsigned char*)buf + returned_value, size - returned_value);
                if (returned_value < 0)
                {
                    Log::Line(Log::INFO, "UbipalService::HandleConnection: RsaWrappers::VerifySignedDigest error: %s",
                              GetErrorDescription(returned_value));
                    RETURN_STATUS(returned_value);
                }
                else if (returned_value == 0)
                {
                    status = SIGNATURE_INVALID;
                    Log::Line(Log::INFO, "UbipalService::HandleConnection: RsaWrappers::VerifySignedDigest did not verify signature: %s",
                              GetErrorDescription(status));
                    RETURN_STATUS(status);
                }

                // if it's a reply, let's handle it. This avoids the ACLs since we explicitly allowed for the reply
                if (message.message.compare(0, strlen("REPLY_"), "REPLY_") == 0)
                {
                    us->reply_callback_mutex.lock();

                    // if we have a message with the given ID sent to the sender, let's go at it
                    std::string replying_id = message.message.substr(strlen("REPLY_"));
                    if (us->reply_callback_map.count(replying_id) == 1)
                    {
                        UbipalReplyCallback callback_func = us->reply_callback_map[replying_id];
                        if (callback_func == nullptr)
                        {
                            Log::Line(Log::EMERG, "UbipalService::HandleConnection: reply_callback_map.coun() was 1, but fetching element returned null.");
                            us->reply_callback_mutex.unlock();
                            RETURN_STATUS(GENERAL_FAILURE);
                        }

                        returned_value = us->reply_callback_map.erase(replying_id);
                        if (returned_value != 1)
                        {
                            Log::Line(Log::EMERG, "UbipalService::HandleConnection: reply_callback_map.erase() failed to remove the mapping.");
                            us->reply_callback_mutex.unlock();
                            RETURN_STATUS(GENERAL_FAILURE);
                        }

                        Message original_message;
                        bool found_original_message = false;
                        for (unsigned int i = 0; i < us->msgs_awaiting_reply.size(); ++i)
                        {
                            if (us->msgs_awaiting_reply[i]->msg_id == replying_id)
                            {
                                original_message = *(us->msgs_awaiting_reply[i]);
                                free(us->msgs_awaiting_reply[i]);
                                us->msgs_awaiting_reply.erase(us->msgs_awaiting_reply.begin() + i);
                                found_original_message = true;
                                break;
                            }
                        }

                        if (found_original_message == false)
                        {
                            Log::Line(Log::EMERG, "UbipalService::HandleConnection: msgs_awaiting_reply did not have the original message");
                            us->reply_callback_mutex.unlock();
                            RETURN_STATUS(GENERAL_FAILURE);
                        }

                        us->reply_callback_mutex.unlock();
                        status = callback_func(us, original_message, message);
                        RETURN_STATUS(status);
                    }
                    else
                    {
                        // else we toss the message
                        Log::Line(Log::INFO, "UbipalService::HandleConnection: Received a reply to a message we were not expecting or did not send.");
                        us->reply_callback_mutex.unlock();
                        RETURN_STATUS(status);
                    }
                }

                if (message.message == std::string("REVOKE"))
                {
                    us->external_acls_mutex.lock();
                    std::string revoke_id(message.argument, message.arg_len);

                    // if the message is a revocation, take the necessary action then return
                    if (us->trusted_services.count(message.from) == 1)
                    {
                        if (us->trusted_services[message.from].msg_id == revoke_id)
                        {
                            us->trusted_services.erase(message.from);
                            us->external_acls_mutex.unlock();
                            RETURN_STATUS(status);
                        }
                    }

                    if (us->untrusted_services.count(message.from) == 1)
                    {
                        if (us->untrusted_services[message.from].msg_id == revoke_id)
                        {
                            us->untrusted_services.erase(message.from);
                            us->external_acls_mutex.unlock();
                            RETURN_STATUS(status);
                        }
                    }

                    if (us->external_acls.count(message.from) == 1)
                    {
                        for (unsigned int i = 0; i < us->external_acls[message.from].size(); ++i)
                        {
                            if (us->external_acls[message.from][i].msg_id == revoke_id)
                            {
                                us->external_acls[message.from].erase(us->external_acls[message.from].begin() + i);
                                us->external_acls_mutex.unlock();
                                RETURN_STATUS(status);
                            }
                        }
                    }

                    us->external_acls_mutex.unlock();
                    RETURN_STATUS(status);
                }

                // check against ACLs
                status = us->CheckAcls(message.message, message.from, message.to, NULL, NULL);
                if (status != SUCCESS)
                {
                    Log::Line(Log::INFO, "UbipalService::HandleConnection: UbipalService::CheckAcls returned %s", GetErrorDescription(status));
                    RETURN_STATUS(status);
                }

                // find function to call
                found = us->callback_map.find(message.message);
                if (found == us->callback_map.end())
                {
                    Log::Line(Log::WARN, "UbipalService::HandleConnection: Does not have the appropriate callback.");
                    RETURN_STATUS(GENERAL_FAILURE);
                }

                status = found->second(us, message);
                if (status != SUCCESS)
                {
                    Log::Line(Log::WARN, "UbipalService::HandleConnection: Callback returned %d, %s", status, GetErrorDescription(status));
                    RETURN_STATUS(status);
                }

                break;
            case MessageType::NAMESPACE_CERTIFICATE:
                // decode as namespace certificate
                returned_value = name_cert.Decode(buf, size);
                if (returned_value < 0)
                {
                    Log::Line(Log::WARN, "UbipalService::HandleConnection: NamespaceCertificate::Decode failed: %s",
                              GetErrorDescription(returned_value));
                    RETURN_STATUS(returned_value);
                }

                // check signature
                returned_value = RsaWrappers::VerifySignedDigest(from_pub_key, (unsigned char*)buf, returned_value,
                                                                 (unsigned char*)buf + returned_value, size - returned_value);
                if (returned_value < 0)
                {
                    Log::Line(Log::INFO, "UbipalService::HandleConnection: RsaWrappers::VerifySignedDigest error: %s",
                              GetErrorDescription(returned_value));
                    RETURN_STATUS(returned_value);
                }
                else if (returned_value == 0)
                {
                    status = SIGNATURE_INVALID;
                    Log::Line(Log::INFO, "UbipalService::HandleConnection: RsaWrappers::VerifySignedDigest did not verify signature: %s",
                              GetErrorDescription(status));
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
                returned_value = acl.Decode(buf, size);
                if (returned_value < 0)
                {
                    Log::Line(Log::WARN, "UbipalService::HandleConnection: AccessControlList::Decode failed: %s",
                              GetErrorDescription(returned_value));
                    RETURN_STATUS(returned_value);
                }

                // check signature
                returned_value = RsaWrappers::VerifySignedDigest(from_pub_key, (unsigned char*)buf, returned_value,
                                                                 (unsigned char*)buf + returned_value, size - returned_value);
                if (returned_value < 0)
                {
                    Log::Line(Log::INFO, "UbipalService::HandleConnection: RsaWrappers::VerifySignedDigest error: %s",
                              GetErrorDescription(returned_value));
                    RETURN_STATUS(returned_value);
                }
                else if (returned_value == 0)
                {
                    status = SIGNATURE_INVALID;
                    Log::Line(Log::INFO, "UbipalService::HandleConnection: RsaWrappers::VerifySignedDigest did not verify signature: %s",
                              GetErrorDescription(status));
                    RETURN_STATUS(status);
                }

                // find all the acls from this service
                us->external_acls_mutex.lock();
                acl_itr = us->external_acls.find(acl.id);
                if (acl_itr == us->external_acls.end())
                {
                    // wasnt found, so add it
                    acl_vector.push_back(acl);
                    emplace_ret = us->external_acls.emplace(acl.id, acl_vector);
                    if (emplace_ret.second == false)
                    {
                        Log::Line(Log::EMERG, "UbipalService::HandleConnection: external_acls.emplace failed");
                        us->external_acls_mutex.unlock();
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
                            us->external_acls_mutex.unlock();
                            RETURN_STATUS(SUCCESS);
                        }
                    }

                    // if we get here, we haven't heard it, so we're adding it
                    acl_itr->second.push_back(acl);
                }

                us->external_acls_mutex.unlock();
                RETURN_STATUS(status);
            default: RETURN_STATUS(GENERAL_FAILURE);
        }

        exit:
            if (status != SUCCESS)
            {
                Log::Line(Log::DEBUG, "UbipalService::HandleConnection: Exiting failure: %s", GetErrorDescription(status));
            }
            free(buf);
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

    int UbipalService::ReplyToMessage(const uint32_t flags, const Message* const msg, const char* const arg, const uint32_t arg_len)
    {
        int status = SUCCESS;
        NamespaceCertificate reply_to;
        std::string message;

        // Set reply message
        message = "REPLY_" + msg->msg_id;

        // Find NamespaceCertificate
        std::vector<NamespaceCertificate> names;
        bool found_name = false;
        status = GetNames(GetNamesFlags::INCLUDE_TRUSTED | GetNamesFlags::INCLUDE_UNTRUSTED, names);
        if (status != SUCCESS)
        {
            return status;
        }
        for (unsigned int i = 0; i < names.size(); ++i)
        {
            if (names[i].id == msg->from)
            {
                reply_to = names[i];
                found_name = true;
                break;
            }
        }

        if (found_name == false)
        {
            return NAMESPACE_CERTIFICATE_NOT_FOUND;
        }

        return SendMessage(flags, reply_to, message, arg, arg_len);
    }

    int UbipalService::SendMessage(const uint32_t flags, const NamespaceCertificate& to, const std::string& message,
                                   const char* const arg, const uint32_t arg_len)
    {
        return SendMessage(flags, to, message, arg, arg_len, NULL);
    }

    int UbipalService::SendMessage(const uint32_t flags, const NamespaceCertificate& to, const std::string& message,
                                   const char* const arg, const uint32_t arg_len, const UbipalReplyCallback reply_callback)
    {
        FUNCTION_START;
        Message* msg = nullptr;
        HandleSendMessageArguments* sm_args = nullptr;
        std::pair<std::unordered_map<std::string, UbipalReplyCallback>::iterator, bool> returned_pair;

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
        else if ((flags & ~(SendMessageFlags::NONBLOCKING | SendMessageFlags::NO_ENCRYPTION)) != 0)
        {
            Log::Line(Log::WARN, "UbipalService::SendMessage: called with invalid flags");
            RETURN_STATUS(INVALID_ARG);
        }

        msg = new Message(arg, arg_len);
        msg->to = to.id;
        msg->from = id;
        msg->message = message;

        // register callback function for replies and record outgoing message
        if (reply_callback != nullptr)
        {
            reply_callback_mutex.lock();

            returned_pair = reply_callback_map.emplace(msg->msg_id, reply_callback);
            if (returned_pair.second == false)
            {
                returned_pair.first->second = reply_callback;
            }

            msgs_awaiting_reply.push_back(msg);
            reply_callback_mutex.unlock();

        }

        sm_args = new HandleSendMessageArguments(this);
        sm_args->address = to.address;
        sm_args->port = to.port;
        sm_args->msg = msg;
        sm_args->flags = flags;
        if (reply_callback != nullptr)
        {
            sm_args->flags |= SendMessageFlags::MESSAGE_AWAIT_REPLY;
        }

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
        unsigned int sig_len = 0;
        unsigned char* sig = nullptr;
        RSA* dest_pub_key = nullptr;
        char* result = nullptr;
        unsigned int result_len = 0;
        unsigned int total_len = 0;

        if (args == nullptr)
        {
            Log::Line(Log::WARN, "UbipalService::HandleSendMessage: null argument");
            RETURN_STATUS(NULL_ARG);
        }

        sm_args = static_cast<HandleSendMessageArguments*>(args);

        // calculate encoded message length
        returned_value = sm_args->msg->EncodedLength();
        if (returned_value < 0)
        {
            Log::Line(Log::EMERG, "UbipalService::HandleSendMessage: EncodedLength had error: %s", GetErrorDescription(returned_value));
            RETURN_STATUS(returned_value);
        }
        bytes_length = returned_value;

        // calculate signature length
        returned_value = RsaWrappers::SignatureLength(sm_args->us->private_key);
        if (returned_value < 0)
        {
            Log::Line(Log::EMERG, "UbipalService::HandleSendMessage: RsaWrappers::SignatureLength failed: %s", GetErrorDescription(returned_value));
            RETURN_STATUS(status);
        }
        sig_len = returned_value;
        total_len = bytes_length + sig_len;

        // allocate enough space for them both
        bytes = (char*)malloc(total_len);
        if (bytes == nullptr)
        {
            Log::Line(Log::EMERG, "UbipalService::HandleSendMessage: malloc failed");
            RETURN_STATUS(MALLOC_FAILURE);
        }

        // encode the message
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

        // now sign it
        sig = (unsigned char*)(bytes + bytes_length);
        status = RsaWrappers::CreateSignedDigest(sm_args->us->private_key, (unsigned char*)bytes, bytes_length, sig, sig_len);
        if (status != SUCCESS)
        {
            Log::Line(Log::EMERG, "UbipalService::HandleSendMessage: CreateSignedDigest failed: %s", GetErrorDescription(status));
            RETURN_STATUS(status);
        }

        // if we know the public key of the destination (the ID), encrypt it
        // reasons we wouldn't know the ID: first contact, or multicast
        // but don't encrypt if NO_ENCRYPTION
        if (!sm_args->msg->to.empty() && ((sm_args->flags & SendMessageFlags::NO_ENCRYPTION) == 0))
        {
            status = RsaWrappers::StringToPublicKey(sm_args->msg->to, dest_pub_key);
            if (status != SUCCESS)
            {
                Log::Line(Log::EMERG, "UbipalService::HandleSendMessage: RsaWrappers::StringToPublicKey failed: %s", GetErrorDescription(status));
                RETURN_STATUS(status);
            }


            status = RsaWrappers::Encrypt(sm_args->us->private_key, bytes, total_len, result, &result_len);
            if (status != SUCCESS)
            {
                Log::Line(Log::EMERG, "UbipalSerivce::HandleSendMessage: RsaWrappers::Encrypt failed: %s", GetErrorDescription(status));
                RETURN_STATUS(status);
            }

            // make the below code work regardless of encryption or not
            free(bytes);
            bytes = result;
            result = nullptr;
            total_len = result_len;
        }

        // send it!
        status = sm_args->us->SendData(sm_args->address, sm_args->port, bytes, total_len);
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
            if ((sm_args->flags & SendMessageFlags::MESSAGE_AWAIT_REPLY) == 0)
            {
                free(sm_args->msg);
            }
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

        if ((flags & ~(SendMessageFlags::NONBLOCKING | SendMessageFlags::NO_ENCRYPTION)) != 0)
        {
            Log::Line(Log::WARN, "UbipalService::SendName: called with invalid flags");
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
        sm_args->flags = flags;

        if ((flags & SendMessageFlags::NONBLOCKING) != 0)
        {
            // if nonblocking, spin off a thread
            threads_mutex.lock();
            send_threads.emplace(send_threads.end());
            returned_value = pthread_create(&send_threads[send_threads.size() - 1], NULL, HandleSendMessage, sm_args);
            threads_mutex.unlock();
            if (returned_value != 0)
            {
                Log::Line(Log::EMERG, "UbipalService::SendName: pthread_create failed: %d", returned_value);
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

    int UbipalService::SetThreadCounts(const unsigned int& recv_threads, const unsigned int& send_threads)
    {
        num_recv_threads = recv_threads;
        num_send_threads = send_threads;
        return SUCCESS;
    }

    int UbipalService::CheckAcls(const std::string& message, const std::string& sender, const std::string& receiver,
                                 std::vector<std::string>* acl_trail, std::vector<std::string>* conditions)
    {
        local_acls_mutex.lock();
        external_acls_mutex.lock();

        int status = SUCCESS;
        std::vector<std::string> acl_trail_new;
        std::vector<std::string> conditions_new;

        if (acl_trail == nullptr)
        {
            acl_trail = &acl_trail_new;
        }
        if (conditions == nullptr)
        {
            conditions = &conditions_new;
        }

        status = CheckAclsRecurse(message, sender, receiver, receiver, *acl_trail, *conditions);

        external_acls_mutex.unlock();
        local_acls_mutex.unlock();

        return status;
    }

    int UbipalService::CheckAclsRecurse(const std::string& message, const std::string& sender, const std::string& receiver, const std::string& current,
                                        std::vector<std::string>& acl_trail, std::vector<std::string>& conditions)
    {
        int status = SUCCESS;
        size_t first_can = 0;
        size_t first_can_say = 0;
        std::vector<std::string> new_acl_trail;
        std::vector<std::string> new_conditions;
        std::vector<ConsiderService> to_consider;
        ConsiderService temp_consider;
        std::vector<AccessControlList> current_acls;
        std::unordered_map<std::string, std::vector<AccessControlList>>::iterator external_acls_itr;

        if (current == id)
        {
            current_acls = local_acls;
        }
        else
        {
            external_acls_itr = external_acls.find(current);
            if (external_acls_itr == external_acls.end())
            {
                return NOT_IN_ACLS;
            }
            else
            {
                current_acls = external_acls_itr->second;
            }
        }

        // for each of the vectors of ACLs from service
        for (unsigned int i = 0; i < current_acls.size(); ++i)
        {
            // ensure this ACL hasn't been seen before, we don't want loops
            for (unsigned int k = 0; k < acl_trail.size(); ++k)
            {
                if (acl_trail[k] == current_acls[i].msg_id)
                {
                    continue;
                }
            }

            // for each rules in the acl
            for (unsigned int j = 0; j < current_acls[i].rules.size(); ++j)
            {
                // if message is mentioned in rule
                if (current_acls[i].rules[j].find(message) != std::string::npos)
                {
                    // verbs are either can, can say, or is
                    first_can = current_acls[i].rules[j].find("can");
                    first_can_say = current_acls[i].rules[j].find("can say");

                    // if rule first verb is "can say"
                    if (first_can_say <= first_can && first_can_say != std::string::npos)
                    {
                        // push_back on vector to be considered later
                        temp_consider.service_id = current_acls[i].id;
                        temp_consider.referenced_from_acl = current_acls[i].msg_id;
                        // TODO record the conditions needed
                        to_consider.push_back(temp_consider);
                    }
                    // if rules first verb is "can"
                    else if (first_can != std::string::npos && first_can_say == std::string::npos)
                    {
                        // check if this rule is talking about the sender and the receiver, if not continue;
                        if ((current_acls[i].rules[j].compare(0, sender.size(), sender) != 0) ||
                            current_acls[i].rules[j].find(receiver) == std::string::npos)
                        {
                            continue;
                        }
                        else
                        {
                            temp_consider.service_id = current;
                            temp_consider.referenced_from_acl = current_acls[i].msg_id;
                            // TODO record the conditions needed
                            to_consider.insert(to_consider.begin(), temp_consider);
                        }
                    }
                }
            }
        }

        if (to_consider.size() == 0)
        {
            return NOT_IN_ACLS;
        }

        // call this recursively for each in the consideration vector
        for (unsigned int i = 0; i < to_consider.size(); ++i)
        {
            // if to_consider[i].id is current, then just check conditions
            if (to_consider[i].service_id == current)
            {
                // TODO CHECK CONDITIONS
                return SUCCESS;
            }
            // else recurse
            else
            {
                // set up temporary recursion variables
                new_acl_trail = acl_trail;
                new_acl_trail.push_back(to_consider[i].referenced_from_acl);
                new_conditions = conditions;
                for (unsigned int j = 0; j < to_consider[i].conditions.size(); ++j)
                {
                    new_conditions.push_back(to_consider[i].conditions[j]);
                }

                // TODO push on to acl_trail and conditions
                status = CheckAclsRecurse(message, sender, receiver, to_consider[i].service_id, acl_trail, conditions);
                if (status == SUCCESS)
                {
                    acl_trail = new_acl_trail;
                    conditions = new_conditions;
                    return status;
                }
                else if (status != NOT_IN_ACLS || status != FAILED_CONDITIONS)
                {
                    return status;
                }
            }
        }

        return NOT_IN_ACLS;
    }

    int UbipalService::CreateAcl(const std::string& description, const std::vector<std::string>& rules, AccessControlList& result)
    {
        local_acls_mutex.lock();

        int status = SUCCESS;

        AccessControlList temp_acl;

        temp_acl.id = id;
        temp_acl.description = description;
        temp_acl.rules = rules;

        local_acls.push_back(temp_acl);
        result = temp_acl;

        local_acls_mutex.unlock();
        return status;
    }

    int UbipalService::GetAcl(const uint32_t flags, const std::string& search_term, AccessControlList& acl)
    {
        bool search_id = false;
        bool search_desc = false;
        if ((flags & ~(GetAclFlags::SEARCH_BY_ID | GetAclFlags::SEARCH_BY_DESC)) != 0)
        {
            return INVALID_ARG;
        }
        if ((flags & GetAclFlags::SEARCH_BY_ID) != 0)
        {
            search_id = true;
        }
        if ((flags & GetAclFlags::SEARCH_BY_DESC) != 0)
        {
            if (search_id == true)
            {
                return INVALID_ARG;
            }
            search_desc = true;
        }

        local_acls_mutex.lock();

        for (unsigned int i = 0; i < local_acls.size(); ++i)
        {
            if (search_desc && (search_term == local_acls[i].description))
            {
                acl = local_acls[i];
                return SUCCESS;
            }
            if (search_id && (search_term == local_acls[i].msg_id))
            {
                acl = local_acls[i];
                return SUCCESS;
            }
        }

        return NOT_FOUND;
    }

    int UbipalService::RevokeAcl(const uint32_t flags, const std::string& acl, const NamespaceCertificate* const send_to)
    {
        // check flags
        if ((flags & ~(RevokeAclFlags::NO_SENDING | RevokeAclFlags::BROADCAST)) != 0)
        {
            return INVALID_ARG;
        }

        // convert to bool for ease of use later
        bool no_sending = false;
        // bool broadcast = false;
        if ((flags & RevokeAclFlags::NO_SENDING) != 0)
        {
            no_sending = true;
        }
        if ((flags & RevokeAclFlags::BROADCAST) != 0)
        {
            if (no_sending == true)
            {
                return INVALID_ARG;
            }
        //    broadcast = true;
        }

        local_acls_mutex.lock();
        int status = SUCCESS;

        for (unsigned int i = 0; i < local_acls.size(); ++i)
        {
            if (local_acls[i].msg_id == acl)
            {
                local_acls.erase(local_acls.begin() + i);
                break;
            }
        }
        local_acls_mutex.unlock();

        // TODO network notifications

        return status;
    }
}
