// Cameron Bielstein, 1/19/15
// ubipal_service.cpp
// Representation of a service in the UbiPAL namespace

// Header
#include "ubipal_service.h"

// UbiPAL
#include "log.h"
#include "error.h"
#include "rsa_wrappers.h"
#include "aes_wrappers.h"
#include "macros.h"

// Standard
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sstream>
#include <fstream>

// Networking
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/time.h>

// OpenSSL
#include <openssl/err.h>

#define FILE_READ_LENGTH 4096

// variables for evaluation
#ifdef EVALUATE
    uint32_t NUM_MESSAGES_SENT = 0;
    uint32_t NUM_MESSAGES_RECV = 0;
    extern uint32_t NUM_RSA_ENCRYPTS;
    extern double TIME_RSA_ENCRYPTS;
    extern uint32_t NUM_RSA_DECRYPTS;
    extern double TIME_RSA_DECRYPTS;
    extern uint32_t NUM_RSA_SIGNS;
    extern double TIME_RSA_SIGNS;
    extern uint32_t NUM_RSA_VERIFIES;
    extern double TIME_RSA_VERIFIES;
    extern uint32_t NUM_RSA_GENERATES;
    extern double TIME_RSA_GENERATES;
    extern uint32_t NUM_AES_ENCRYPTS;
    extern double TIME_AES_ENCRYPTS;
    extern uint32_t NUM_AES_DECRYPTS;
    extern double TIME_AES_DECRYPTS;
    extern uint32_t NUM_AES_GENERATES;
    extern double TIME_AES_GENERATES;
#endif

namespace UbiPAL
{
    UbipalService::UbipalService()
    {
        init(NULL, NULL);
    }

    UbipalService::UbipalService(const std::string& file_path)
    {
        int status = SUCCESS;
        RSA* _private_key = nullptr;
        FILE* fd = nullptr;
        char buf[FILE_READ_LENGTH];
        char* port = nullptr;
        std::string line;

        fd = fopen(file_path.c_str(), "r");
        if (fd == nullptr)
        {
            Log::Line(Log::WARN, "UbipalService::UbipalService(const std::string& file_path): Failed to open file_path: %s", file_path.c_str());
            return;
        }

        if (fgets(buf, FILE_READ_LENGTH, fd) == nullptr)
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

        if (fgets(buf, FILE_READ_LENGTH, fd) != nullptr)
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

        init(_private_key, port);
        RSA_free(_private_key);
    }

    UbipalService::UbipalService(const RSA* const _private_key, const char* const _port)
    {
        init(_private_key, _port);
    }

    void UbipalService::init(const RSA* const _private_key, const char* const _port)
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
        size_t end_subnet = 0;
        current_cert = nullptr;
        condition_timeout_length = 500;
        broadcast_name_interval = 5000;
        auto_broadcast_name = false;

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

        //// open unicast socket

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
            unicast_fd = socket(itr->ai_family, itr->ai_socktype, itr->ai_protocol);
            if (unicast_fd == -1)
            {
                Log::Line(Log::DEBUG, "UbipalService::UbipalService: Failed to create a socket: %d, %s", errno, strerror(errno));
                continue;
            }

            returned_value = setsockopt(unicast_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
            if (returned_value == -1)
            {
                Log::Line(Log::DEBUG, "UbipalService::UbipalService: Failed to set socket option SOL_SOCKET, SO_REUSEADDR, yes: %d, %s", errno, strerror(errno));
                continue;
            }

            returned_value = bind(unicast_fd, itr->ai_addr, itr->ai_addrlen);
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
            unicast_fd = -2;
            goto exit;
        }

        addr_len = sizeof(struct sockaddr_in);
        returned_value = getsockname(unicast_fd, (struct sockaddr*)&bound_sock, &addr_len);
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

        //// open broadcast socket

        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = AI_PASSIVE;

        // get broadcast address (x.x.x.255)
        // this is preferred over 255.255.255.255 as some routers may not repeat the latter
        end_subnet = address.rfind('.');
        if (end_subnet == std::string::npos)
        {
            // if for some reason we can't find a period in our string, fall back to this
            broadcast_address = "255.255.255.255";
        }
        else
        {
            broadcast_address = address.substr(0, end_subnet + 1);
            broadcast_address += "255";
        }

        returned_value = getaddrinfo(broadcast_address.c_str(), UBIPAL_BROADCAST_PORT, &hints, &broadcast_info);
        if (returned_value != 0)
        {
            Log::Line(Log::EMERG, "UbipalService::UbipalService: Unable to bind to broadcast address and port %s:%s", broadcast_address.c_str(), UBIPAL_BROADCAST_PORT);
            return;
        }

        for (itr = broadcast_info; itr != nullptr; itr = itr->ai_next)
        {
            broadcast_fd = socket(itr->ai_family, itr->ai_socktype, itr->ai_protocol);
            if (broadcast_fd == -1)
            {
                continue;
            }

            returned_value = setsockopt(broadcast_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
            if (returned_value == -1)
            {
                continue;
            }

            returned_value = bind(broadcast_fd, itr->ai_addr, itr->ai_addrlen);
            if (returned_value == -1)
            {
                continue;
            }

            break;
        }
        if (itr == nullptr)
        {
            Log::Line(Log::EMERG, "UbipalService::UbipalService: Unable to bind to any port for broadcast_fd");
            return;
        }
        else
        {
            broadcast_info = itr;
        }

        // enable broadcast
        returned_value = setsockopt(broadcast_fd, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(int));
        if (returned_value == -1)
        {
            Log::Line(Log::EMERG, "UbipalService::UbipalService: Unable to set SO_BROADCAST to true");
            return;
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

        // close unicast socket
        close(unicast_fd);

        // close broadcast socket
        close(broadcast_fd);

        // free broadcast_info
        freeaddrinfo(broadcast_info);

        // delete the current_cert
        delete current_cert;

        #ifdef EVALUATE
            // last thing before quitting, put out our stats
            Log::Line(Log::INFO, "Quitting. Messages sent: %lu, messages received: %lu\nRSA Encrypts: %lu (%f secs), RSA Decrypts: %lu (%f secs), RSA Signs: %lu (%f secs), RSA Verifies: %lu (%f secs), RSA Generate Key: %lu (%f secs)\nAES Encrypts: %lu (%f secs), AES Decrypts: %lu (%f secs), AES Generate Object: %lu (%f secs)\n",
                      NUM_MESSAGES_SENT, NUM_MESSAGES_RECV, NUM_RSA_ENCRYPTS, TIME_RSA_ENCRYPTS, NUM_RSA_DECRYPTS, TIME_RSA_DECRYPTS, NUM_RSA_SIGNS, TIME_RSA_SIGNS, NUM_RSA_VERIFIES, TIME_RSA_VERIFIES, NUM_RSA_GENERATES, TIME_RSA_GENERATES, NUM_AES_ENCRYPTS, TIME_AES_ENCRYPTS, NUM_AES_DECRYPTS, TIME_AES_DECRYPTS, NUM_AES_GENERATES, TIME_AES_GENERATES);
        #endif

        // Ensure everything hits the log before we die.
        Log::FlushLog();
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
        int status = SUCCESS;
        int returned_value = 0;
        pthread_t new_thread = 0;

        if ((flags & ~(BeginRecvFlags::DONT_PUBLISH_NAME | BeginRecvFlags::NON_BLOCKING)) != 0)
        {
            Log::Line(Log::WARN, "UbipalService::BeginRecv: Invalid flags.");
            return INVALID_ARG;
        }

        // use mutual exclusion and state variables to ensure only one thread is receiving at once
        receiving_mutex.lock();
            if (receiving)
            {
                Log::Line(Log::INFO, "UbipalService::BeginRecv: Already receiving. Return!");
                receiving_mutex.unlock();
                return MULTIPLE_RECV;
            }
            else
            {
                receiving = true;
                Log::Line(Log::INFO, "UbipalService::BeginRecv: Beginning receiving on port %s", port.c_str());
            }
        receiving_mutex.unlock();


        // if flag isn't specified, go ahead and broadcast the name
        if ((flags & BeginRecvFlags::DONT_PUBLISH_NAME) == 0)
        {
            status = SendName(0, NULL);
            if (status != SUCCESS)
            {
                Log::Line(Log::EMERG, "UbipalService::BeginRecv: SendName(NULL) failed: %s", GetErrorDescription(status));
            }
        }

        // start threads
        threads_mutex.lock();

        // start broadcast receiver
        returned_value = pthread_create(&new_thread, NULL, RecvBroadcast, this);
        if (returned_value != 0)
        {
            Log::Line(Log::EMERG, "UbipalService::BeginRecv: pthread_create failed: %d", returned_value);
            threads_mutex.unlock();
            return THREAD_FAILURE;
        }

        recv_threads.push_back(new_thread);

        // spin up threads for receiving
        for (unsigned int i = 0; i < num_recv_threads; ++i)
        {
            returned_value = pthread_create(&new_thread, NULL, ConsumeIncoming, this);
            if (returned_value != 0)
            {
                Log::Line(Log::EMERG, "UbipalService::BeginRecv: A call to pthread_create failed: %d", returned_value);
            }

            recv_threads.push_back(new_thread);
        }

        // start condition timeout thread
        returned_value = pthread_create(&conditions_timeout_thread, NULL, ConditionTimeout, this);
        if (returned_value != 0)
        {
            threads_mutex.unlock();
            return THREAD_FAILURE;
        }

        threads_mutex.unlock();

        // begin receiving unicasts. Spin a new thread if we're nonblocking
        if ((flags & BeginRecvFlags::NON_BLOCKING)!= 0)
        {
            threads_mutex.lock();

            returned_value = pthread_create(&new_thread, NULL, RecvUnicast, this);
            if (returned_value != 0)
            {
                Log::Line(Log::EMERG, "UbipalService::BeginRecv: pthread_create failed: %d", returned_value);
                threads_mutex.unlock();
                return THREAD_FAILURE;
            }

            recv_threads.push_back(new_thread);
            threads_mutex.unlock();
        }
        else
        {
            RecvUnicast(this);
        }

        return status;
    }

    int UbipalService::EndRecv()
    {
        receiving_mutex.lock();
            receiving = false;
            recv_threads.clear();
            send_threads.clear();
        receiving_mutex.unlock();

        return SUCCESS;
    }

    void* UbipalService::RecvUnicast(void* arg)
    {
        int returned_value = 0;
        int connect_fd = 0;
        UbipalService* us = nullptr;
        IncomingData* incoming_data = nullptr;

        if (arg == nullptr)
        {
            Log::Line(Log::WARN, "UbipalService::RecvUnicast: null argument.");
            return NULL;
        }

        us = (UbipalService*)arg;

        // listen on unicast_fd for 10 queued connections
        returned_value = listen(us->unicast_fd, 10);
        if (returned_value != 0)
        {
            Log::Line(Log::EMERG, "UbipalService::RecvUnicast: listen failed: %d, %s", errno, strerror(errno));
            return NULL;
        }

        // this is the receiving loop
        while(us->receiving)
        {
            connect_fd = accept(us->unicast_fd, NULL, NULL);
            if (connect_fd == -1)
            {
                // if there was an error, log it and give up on this connection, there are other connections in the sea
                Log::Line(Log::WARN, "UbipalService::RecvUnicast: A call to accept failed: %d, %s", errno, strerror(errno));
                continue;
            }

            // enqueue
            us->incoming_msg_mutex.lock();
            incoming_data = new IncomingData(connect_fd, NULL, 0);
            us->incoming_messages.push(incoming_data);
            incoming_data = nullptr;
            us->incoming_msg_mutex.unlock();
            // signal a worker thread
            us->incoming_msg_cv.notify_one();
        }

        return NULL;
    }

    void* UbipalService::RecvBroadcast(void* arg)
    {
        int returned_value = 0;
        UbipalService* us = nullptr;
        IncomingData* incoming_data = nullptr;
        unsigned char* buf = nullptr;

        if (arg == nullptr)
        {
            Log::Line(Log::WARN, "UbipalService::RecvBroadcast: null argument.");
            return NULL;
        }

        us = (UbipalService*)arg;

        // this is the receiving loop
        while(us->receiving)
        {
            buf = (unsigned char*)malloc(MAX_MESSAGE_SIZE);
            if (buf == nullptr)
            {
                Log::Line(Log::EMERG, "UbipalService::RecvBroadcast: malloc failure.");
                return NULL;
            }

            returned_value = recvfrom(us->broadcast_fd, buf, MAX_MESSAGE_SIZE, 0, NULL, NULL);
            if (returned_value < 0)
            {
                Log::Line(Log::WARN, "UbipalService::RecvBroadcast: recvfrom failed.");
                continue;
            }

            // enqueue
            us->incoming_msg_mutex.lock();
            incoming_data = new IncomingData(0, buf, returned_value);
            us->incoming_messages.push(incoming_data);
            incoming_data = nullptr;
            buf = nullptr;
            us->incoming_msg_mutex.unlock();
            // signal a worker thread
            us->incoming_msg_cv.notify_one();
        }

        return NULL;
    }

    void* UbipalService::ConsumeIncoming(void* arg)
    {
        int status = SUCCESS;

        if (arg == nullptr)
        {
            Log::Line(Log::WARN, "UbipalService::ConsumeIncoming: arg was null.");
            return NULL;
        }

        UbipalService* us = (UbipalService*)arg;
        IncomingData* incoming_data = nullptr;
        std::unique_lock<std::mutex> lock(us->incoming_msg_mutex, std::defer_lock);

        while(us->receiving)
        {
            lock.lock();

            // wait for non-empty queue
            while(us->incoming_messages.size() == 0)
            {
                if (us->receiving == false)
                {
                    lock.unlock();
                    return NULL;
                }
                us->incoming_msg_cv.wait_for(lock, std::chrono::milliseconds(500));
            }

            // grab stuff off the queue
            incoming_data = us->incoming_messages.front();
            us->incoming_messages.pop();

            // unlock the queue to handle the connection
            lock.unlock();

            if (incoming_data->buffer == NULL)
            {
                // this is an incoming connection, get the actual data
                status = us->HandleIncomingConnection(incoming_data);
                if (status != SUCCESS)
                {
                    Log::Line(Log::WARN, "UbipalService::ConsumeIncoming: HandleIncomingConnection failed: %s", GetErrorDescription(status));
                    status = SUCCESS;
                    continue;
                }
            }

            status = us->HandleMessage(incoming_data);
        }

        return NULL;
    }

    int UbipalService::HandleIncomingConnection(IncomingData* const incoming_data) const
    {
        FUNCTION_START;
        unsigned char* buf = nullptr;

        if (incoming_data == nullptr)
        {
            Log::Line(Log::WARN, "UbipalService::HandleIncomingConnection: null arg");
            RETURN_STATUS(NULL_ARG);
        }

        buf = (unsigned char*)malloc(MAX_MESSAGE_SIZE);

        returned_value = recv(incoming_data->conn_fd, buf, MAX_MESSAGE_SIZE, 0);
        if (returned_value < 0)
        {
            Log::Line(Log::INFO, "UbipalService::HandleConnection: receive failed: %s", strerror(errno));
            RETURN_STATUS(NETWORKING_FAILURE);
        }
        else
        {
            incoming_data->buffer = buf;
            incoming_data->buffer_len = returned_value;
        }

        exit:
            if (status != SUCCESS)
            {
                free(buf);
            }
            FUNCTION_END;
    }

    int UbipalService::HandleMessage(IncomingData* const incoming_data)
    {
        FUNCTION_START;
        unsigned char* buf_decrypted = nullptr;
        unsigned int buf_decrypted_len = 0;
        uint32_t to_len = 0;
        uint32_t from_len = 0;
        RSA* from_pub_key = nullptr;
        BaseMessage* msg = nullptr;

        if (incoming_data == nullptr)
        {
            Log::Line(Log::INFO, "UbipalStatus::HandleMessage: Passed null argument");
            RETURN_STATUS(NULL_ARG);
        }
        else if (incoming_data->buffer == nullptr)
        {
            Log::Line(Log::INFO, "UbipalStatus::HandleMessage: Passed incoming_data with null buffer.");
            RETURN_STATUS(INVALID_ARG);
        }

        /// decryption

        // The first byte is the type, the next 4 are the size of the from field, but we want the to field to check for encryption
        returned_value = BaseMessage::DecodeUint32_t(incoming_data->buffer + 1, incoming_data->buffer_len, from_len);
        if (returned_value < 0)
        {
            Log::Line(Log::WARN, "UbipalService::HandleMessage: BaseMessageDecodeUint32_t failed: %s",
                      GetErrorDescription(returned_value));
            RETURN_STATUS(returned_value);
        }

        // ensure we're not going out of bounds
        if (5 + from_len >= incoming_data->buffer_len)
        {
            Log::Line(Log::WARN, "UbipalService::HandleMessage: From field is encrypted or poorly encoded.");
            RETURN_STATUS(GENERAL_FAILURE);
        }

        returned_value = BaseMessage::DecodeUint32_t(incoming_data->buffer + 5 + from_len, incoming_data->buffer_len, to_len);
        if (returned_value < 0)
        {
            Log::Line(Log::WARN, "UbipalService::HandleMessage: BaseMessageDecodeUint32_t failed: %s",
                      GetErrorDescription(returned_value));
            RETURN_STATUS(returned_value);
        }

        // if the two field is empty, it's a first handshake, so it's not encrypted
        if (to_len != 0)
        {
            // If the to length is nonzero, compare the next bytes against the service's id.
            // If they are the same, this is not encrypted. If they do not match, try to derypt and try again
            if (to_len != id.size() || memcmp(incoming_data->buffer + 1 + 4 + from_len + 4, id.c_str(), id.size()) != 0)
            {
                std::string from = std::string((char*)incoming_data->buffer + 1 + 4, from_len);

                aes_keys_mutex.lock();

                // ensure we have the aes key & iv
                if (aes_keys.count(from) == 0)
                {
                    Log::Line(Log::WARN, "UbipalService::HandleMessage: Tried to receive an encrypted message from a service which hasn't sent us an AES key yet.");
                    aes_keys_mutex.unlock();
                    RETURN_STATUS(NOT_FOUND);
                }

                // decrypt
                status = AesWrappers::Decrypt(std::get<0>(aes_keys[from]), std::get<1>(aes_keys[from]), incoming_data->buffer + 5 + from_len,
                                              incoming_data->buffer_len - 5 - from_len, buf_decrypted, &buf_decrypted_len);
                aes_keys_mutex.unlock();
                if (status != SUCCESS)
                {
                    Log::Line(Log::WARN, "UbipalService::HandleMessage: AesWrappers::Decrypt failed: %s", GetErrorDescription(status));
                    RETURN_STATUS(status);
                }

                // If they still don't match, toss the message because it isn't to us
                if (memcmp(buf_decrypted + 4, id.c_str(), id.size()) != 0)
                {
                    Log::Line(Log::WARN, "UbipalService::HandleMessage: Message couldn't be interpreted, so it's tossed.");
                    RETURN_STATUS(INVALID_NETWORK_ENCODING);
                }

                // combine the decrypted and originally unencrypted stuff back together
                unsigned char* final_message = (unsigned char*)malloc(buf_decrypted_len + 5 + from_len);
                if (final_message == nullptr)
                {
                    Log::Line(Log::EMERG, "UbipalService::HandleMessage: malloc failed for final_message");
                    RETURN_STATUS(MALLOC_FAILURE);
                }

                memcpy(final_message, incoming_data->buffer, 5 + from_len);
                memcpy(final_message + 5 + from_len, buf_decrypted, buf_decrypted_len);

                // so we decrypted and it matched, put buf_decrypted in buf
                free(incoming_data->buffer);
                free(buf_decrypted);
                incoming_data->buffer = final_message;
                buf_decrypted = nullptr;
                final_message = nullptr;
                incoming_data->buffer_len = buf_decrypted_len + 5 + from_len;
            }
        }

        // interpret message
        msg = new BaseMessage();
        status = msg->Decode(incoming_data->buffer, incoming_data->buffer_len);
        if (status < 0)
        {
            Log::Line(Log::WARN, "UbipalService::HandleMessage: BaseMessage::Decode failed: %s", GetErrorDescription(status));
            RETURN_STATUS(status)
        }

        if (msg->from == id)
        {
            Log::Line(Log::DEBUG, "UbipalService::HandleMessage: Dropped message from this service.");
            RETURN_STATUS(status);
        }

        // ensure this isn't directed to somebody else
        // it's to us or it's broadcast (to nobody)
        if (msg->to != id && !msg->to.empty())
        {
            status = MESSAGE_WRONG_DESTINATION;
            Log::Line(Log::DEBUG, "UbipalService::HandleMessage: Received a message not to this service: %s", GetErrorDescription(status));
            RETURN_STATUS(status);
        }

        // convert from id to public key for validation
        status = RsaWrappers::StringToPublicKey(msg->from, from_pub_key);
        if (status != SUCCESS)
        {
            Log::Line(Log::INFO, "UbipalService::HandleMessage: RsaWrappers::StringToPublicKey failed: %s", GetErrorDescription(status));
            RETURN_STATUS(status);
        }

        switch(msg->type)
        {
            case MessageType::MESSAGE:
                // reinterpret and authenticate
                delete msg;
                msg = new Message();
                returned_value = msg->Decode(incoming_data->buffer, incoming_data->buffer_len);
                if (status < 0)
                {
                    Log::Line(Log::WARN, "UbipalService::HandleMessage: Message::Decode failed: %s", GetErrorDescription(returned_value));
                    RETURN_STATUS(returned_value);
                }

                // authenticate - check signature
                returned_value = RsaWrappers::VerifySignedDigest(from_pub_key, incoming_data->buffer, returned_value,
                                                                 incoming_data->buffer + returned_value, incoming_data->buffer_len - returned_value);
                if (returned_value < 0)
                {
                    Log::Line(Log::INFO, "UbipalService::HandleMessage: RsaWrappers::VerifySignedDigest error: %s",
                              GetErrorDescription(returned_value));
                    RETURN_STATUS(returned_value);
                }
                else if (returned_value == 0)
                {
                    status = SIGNATURE_INVALID;
                    Log::Line(Log::INFO, "UbipalService::HandleMessage: RsaWrappers::VerifySignedDigest did not verify signature: %s",
                              GetErrorDescription(status));
                    RETURN_STATUS(status);
                }
                status = RecvMessage((Message*)msg);
                if (status != SUCCESS)
                {
                    // this is not an error state, correct the status variable and continue
                    if (status == WAIT_ON_CONDITIONS)
                    {
                        status = SUCCESS;
                    }
                    else
                    {
                        Log::Line(Log::WARN, "UbipalService::HandleMessage: RecvMessage failed: %s", GetErrorDescription(status));
                        RETURN_STATUS(status);
                    }
                }
                break;
            case MessageType::NAMESPACE_CERTIFICATE:
                // reinterpret and authenticate
                delete msg;
                msg = new NamespaceCertificate();
                returned_value = msg->Decode(incoming_data->buffer, incoming_data->buffer_len);
                if (status < 0)
                {
                    Log::Line(Log::WARN, "UbipalService::HandleMessage: Message::Decode failed: %s", GetErrorDescription(returned_value));
                    RETURN_STATUS(returned_value);
                }

                // authenticate - check signature
                returned_value = RsaWrappers::VerifySignedDigest(from_pub_key, incoming_data->buffer, returned_value,
                                                                 incoming_data->buffer + returned_value, incoming_data->buffer_len - returned_value);
                if (returned_value < 0)
                {
                    Log::Line(Log::INFO, "UbipalService::HandleMessage: RsaWrappers::VerifySignedDigest error: %s",
                              GetErrorDescription(returned_value));
                    RETURN_STATUS(returned_value);
                }
                else if (returned_value == 0)
                {
                    status = SIGNATURE_INVALID;
                    Log::Line(Log::INFO, "UbipalService::HandleMessage: RsaWrappers::VerifySignedDigest did not verify signature: %s",
                              GetErrorDescription(status));
                    RETURN_STATUS(status);
                }

                status = RecvNamespaceCertificate((NamespaceCertificate*)msg);
                if (status != SUCCESS)
                {
                    Log::Line(Log::WARN, "UbipalService::HandleMessage: RecvNamespaceCertificate failed: %s", GetErrorDescription(status));
                    RETURN_STATUS(status);
                }
                break;
            case MessageType::ACCESS_CONTROL_LIST:
                // reinterpret and authenticate
                delete msg;
                msg = new AccessControlList();
                returned_value = msg->Decode(incoming_data->buffer, incoming_data->buffer_len);
                if (status < 0)
                {
                    Log::Line(Log::WARN, "UbipalService::HandleMessage: Message::Decode failed: %s", GetErrorDescription(returned_value));
                    RETURN_STATUS(returned_value);
                }

                // authenticate - check signature
                returned_value = RsaWrappers::VerifySignedDigest(from_pub_key, incoming_data->buffer, returned_value,
                                                                 incoming_data->buffer + returned_value, incoming_data->buffer_len - returned_value);
                if (returned_value < 0)
                {
                    Log::Line(Log::INFO, "UbipalService::HandleMessage: RsaWrappers::VerifySignedDigest error: %s",
                              GetErrorDescription(returned_value));
                    RETURN_STATUS(returned_value);
                }
                else if (returned_value == 0)
                {
                    status = SIGNATURE_INVALID;
                    Log::Line(Log::INFO, "UbipalService::HandleMessage: RsaWrappers::VerifySignedDigest did not verify signature: %s",
                              GetErrorDescription(status));
                    RETURN_STATUS(status);
                }

                status = RecvAcl((AccessControlList*)msg);
                if (status != SUCCESS)
                {
                    Log::Line(Log::WARN, "UbipalService::HandleMessage: RecvAcl failed: %s", GetErrorDescription(status));
                    RETURN_STATUS(status);
                }
                break;
            default: RETURN_STATUS(GENERAL_FAILURE);
        }

        exit:
            #ifdef EVALUATE
                // count all messages received, since they were received regardless of any failure afterward
                ++NUM_MESSAGES_RECV;
            #endif
            if (status != SUCCESS)
            {
                Log::Line(Log::DEBUG, "UbipalService::HandleConnection: Exiting failure: %s", GetErrorDescription(status));
            }
            delete msg;
            return status;
    }

    int UbipalService::RecvAcl(const AccessControlList* const acl)
    {
        int status = SUCCESS;
        std::vector<AccessControlList> acl_vector;

        if (acl == nullptr)
        {
            Log::Line(Log::DEBUG, "UbipalService::RecvAcl: Null arg");
            return NULL_ARG;
        }

        // find all the acls from this service
        external_acls_mutex.lock();

        // ensure this acl wasn't previously revoked
        if (revoked_external_acls.count(acl->msg_id) != 0)
        {
            Log::Line(Log::INFO, "UbipalService::RecvAcl: Attempted to add ACL which was previously revoked.");
            external_acls_mutex.unlock();
            return PREVIOUSLY_REVOKED;
        }
        if (external_acls.count(acl->id) == 0)
        {
            // wasnt found, so add it
            acl_vector.push_back(*acl);
            external_acls.emplace(acl->id, acl_vector);
        }
        else
        {
            // was found, so check through the associated vector to see if this is an update (based on ID)
            for (unsigned int i = 0; i < external_acls[acl->id].size(); ++i)
            {
                if (external_acls[acl->id][i].msg_id == acl->msg_id)
                {
                    // we've already heard this one, so we're done.
                    external_acls_mutex.unlock();
                    return SUCCESS;
                }
            }

            // if we get here, we haven't heard it, so we're adding it
            external_acls[acl->id].push_back(*acl);
        }

        external_acls_mutex.unlock();
        return status;
    }

    int UbipalService::RecvNamespaceCertificate(const NamespaceCertificate* const name_cert)
    {
        int status = SUCCESS;
        std::unordered_map<std::string, NamespaceCertificate>::iterator itr;

        if (name_cert == nullptr)
        {
            Log::Line(Log::DEBUG, "UbipalService::RecvNamespaceCertificate: Null arg");
            return NULL_ARG;
        }

        services_mutex.lock();
        // check if it was sent by a trusted source
        itr = trusted_services.find(name_cert->from);
        if (itr != trusted_services.end())
        {
            // we trust the sender, see if the actual name is in our trusted list.
            itr = trusted_services.find(name_cert->id);
            if (itr != trusted_services.end())
            {
                // it is, so update it if it's newer
                if (name_cert->version > itr->second.version)
                {
                    itr->second = *name_cert;
                }
            }
            else
            {
                // it isn't, so add it
                trusted_services.emplace(name_cert->id, *name_cert);
            }
        }
        else
        {
            // check if the actual name is in the untrusted
            itr = untrusted_services.find(name_cert->id);
            if (itr != trusted_services.end())
            {
                // it is, so update it if it's newer
                if (name_cert->version > itr->second.version)
                {
                    itr->second = *name_cert;
                }
            }
            else
            {
                // it isn't, so add it
                untrusted_services.emplace(name_cert->id, *name_cert);
            }
        }

        services_mutex.unlock();
        return status;
    }

    int UbipalService::RecvMessage(const Message* const message)
    {
        FUNCTION_START;
        std::unordered_map<std::string, UbipalCallback>::iterator found;
        std::pair<std::unordered_map<std::string, std::vector<AccessControlList>>::iterator, bool> emplace_ret;

        if (message == nullptr)
        {
            Log::Line(Log::INFO, "UbipalServices::RecvMessage: null argument");
            return NULL_ARG;
        }

        // if it's a reply, let's handle it. This avoids the ACLs since we explicitly allowed for the reply
        if (message->message.compare(0, strlen("REPLY_"), "REPLY_") == 0)
        {
            reply_callback_mutex.lock();

            // if we have a message with the given ID sent to the sender, let's go at it
            std::string replying_id = message->message.substr(strlen("REPLY_"));
            if (reply_callback_map.count(replying_id) == 1)
            {
                UbipalReplyCallback callback_func = reply_callback_map[replying_id];
                if (callback_func == nullptr)
                {
                    Log::Line(Log::EMERG, "UbipalService::RecvMessage: reply_callback_map.coun() was 1, but fetching element returned null.");
                    reply_callback_mutex.unlock();
                    return GENERAL_FAILURE;
                }

                Message* original_message = nullptr;
                bool found_original_message = false;
                for (unsigned int i = 0; i < msgs_awaiting_reply.size(); ++i)
                {
                    if (msgs_awaiting_reply[i]->msg_id == replying_id)
                    {
                        original_message = msgs_awaiting_reply[i];

                        // only erase the mapping if it wasn't a broadcast
                        if (original_message->to.empty() == false)
                        {
                            delete msgs_awaiting_reply[i];
                            msgs_awaiting_reply.erase(msgs_awaiting_reply.begin() + i);
                        }

                        found_original_message = true;
                        break;
                    }
                }

                if (found_original_message == false)
                {
                    Log::Line(Log::EMERG, "UbipalService::RecvMessage: msgs_awaiting_reply did not have the original message");
                    reply_callback_mutex.unlock();
                    return GENERAL_FAILURE;
                }

                // erase the mapping only if it wasn't a broadcast
                if (original_message->to.empty() == false)
                {
                    returned_value = reply_callback_map.erase(replying_id);
                    if (returned_value != 1)
                    {
                        Log::Line(Log::EMERG, "UbipalService::RecvMessage: reply_callback_map.erase() failed to remove the mapping.");
                        reply_callback_mutex.unlock();
                        return GENERAL_FAILURE;
                    }
                }

                reply_callback_mutex.unlock();
                status = callback_func(this, original_message, message);
                return status;
            }
            else
            {
                // else we toss the message
                Log::Line(Log::INFO, "UbipalService::RecvMessage: Received a reply to a message we were not expecting or did not send.");
                reply_callback_mutex.unlock();
                return status;
            }
        }

        // note: currently, each service may only revoke its own ACLs
        if (message->message == std::string("REVOKE"))
        {
            std::string revoke_id((char*)message->argument, message->arg_len);

            // if the message is a revocation, take the necessary action then return
            services_mutex.lock();
            if (trusted_services.count(message->from) == 1)
            {
                if (trusted_services[message->from].msg_id == revoke_id)
                {
                    trusted_services.erase(message->from);
                    services_mutex.unlock();
                    return status;
                }
            }

            if (untrusted_services.count(message->from) == 1)
            {
                if (untrusted_services[message->from].msg_id == revoke_id)
                {
                    untrusted_services.erase(message->from);
                    services_mutex.unlock();
                    return status;
                }
            }

            services_mutex.unlock();

            external_acls_mutex.lock();
            if (external_acls.count(message->from) == 1)
            {
                for (unsigned int i = 0; i < external_acls[message->from].size(); ++i)
                {
                    if (external_acls[message->from][i].msg_id == revoke_id)
                    {
                        revoked_external_acls.insert(revoke_id);
                        external_acls[message->from].erase(external_acls[message->from].begin() + i);
                        if (external_acls[message->from].size() == 0)
                        {
                            external_acls.erase(message->from);
                        }
                        external_acls_mutex.unlock();
                        return status;
                    }
                }
            }

            external_acls_mutex.unlock();

            return status;
        }

        if (message->message == "NEWAESPAIR")
        {
            // use my private key to decrypt the argument (key & iv)
            unsigned char* aes_pair_decrypted = nullptr;
            unsigned int aes_pair_decrypted_len = 0;
            status = RsaWrappers::Decrypt(private_key, message->argument, message->arg_len, aes_pair_decrypted, &aes_pair_decrypted_len);
            if (status != SUCCESS)
            {
                return status;
            }

            // decode key & iv
            uint32_t offset = 0;
            uint32_t length = 0;
            unsigned char* str_bits = nullptr;
            // decode key length
            status = BaseMessage::DecodeUint32_t(aes_pair_decrypted + offset, aes_pair_decrypted_len - offset, length);
            if (status < 0)
            {
                Log::Line(Log::WARN, "UbipalService::HandleMessage: BaseMessage::DecodeUint32_t failed %s", GetErrorDescription(status));
                return status;
            }
            else if (length < 0)
            {
                return INVALID_NETWORK_ENCODING;
            }
            else
            {
                offset += status;
                status = SUCCESS;
            }

            // decode key
            if (aes_pair_decrypted_len < offset + length)
            {
                Log::Line(Log::WARN, "UbipalService::HandleMessage: Given a buf too short: buf_len %u < offset %u + length %u",
                          aes_pair_decrypted_len, offset, length);
                return BUFFER_TOO_SMALL;
            }
            str_bits = aes_pair_decrypted + offset;
            unsigned char* new_key = (unsigned char*)malloc(length);
            memcpy(new_key, str_bits, length);
            offset += length;

            // decode iv length
            status = BaseMessage::DecodeUint32_t(aes_pair_decrypted + offset, aes_pair_decrypted_len - offset, length);
            if (status < 0)
            {
                Log::Line(Log::WARN, "UbipalService::HandleMessage: BaseMessage::DecodeUint32_t failed %s", GetErrorDescription(status));
                return status;
            }
            else if (length < 0)
            {
                return INVALID_NETWORK_ENCODING;
            }
            else
            {
                offset += status;
                status = SUCCESS;
            }

            // decode iv
            if (aes_pair_decrypted_len < offset + length)
            {
                Log::Line(Log::WARN, "UbipalService::HandleMessage: Given a buf too short: buf_len %u < offset %u + length %u",
                          aes_pair_decrypted_len, offset, length);
                return BUFFER_TOO_SMALL;
            }
            str_bits = aes_pair_decrypted + offset;
            unsigned char* new_iv = (unsigned char*)malloc(length);
            memcpy(new_iv, str_bits, length);
            offset += length;

            // update my aes_keys map
            aes_keys_mutex.lock();

            aes_keys[message->from] = std::tuple<unsigned char*, unsigned char*>(new_key, new_iv);

            aes_keys_mutex.unlock();

            return status;
        }

        if (message->message == "REQUESTCERTIFICATE")
        {
            // find if we have the appropriate certificate
            NamespaceCertificate requested_cert;
            std::string requested_service = (message->arg_len == 0) ? GetId() : std::string((char*)message->argument, message->arg_len);
            status = GetCertificateForName(requested_service, requested_cert);

            bool was_local = (requested_service == GetId());

            uint32_t reply_bytes_len = 0;
            unsigned char* reply_bytes = nullptr;
            if (status == SUCCESS)
            {
                uint32_t sig_len = 0;

                // if it was local, we aren't storing the raw signed bytes, so let's sign it now
                if (was_local)
                {
                    sig_len = RsaWrappers::SignatureLength(private_key);
                }

                reply_bytes_len = (uint32_t)requested_cert.EncodedLength() + sig_len;
                reply_bytes = (unsigned char*) malloc(reply_bytes_len);
                if (reply_bytes == nullptr)
                {
                    return MALLOC_FAILURE;
                }

                returned_value = requested_cert.Encode(reply_bytes, requested_cert.EncodedLength());
                if (returned_value < 0)
                {
                    return returned_value;
                }

                if (was_local)
                {
                    unsigned char* sig = reply_bytes + requested_cert.EncodedLength();
                    status = RsaWrappers::CreateSignedDigest(private_key, reply_bytes, requested_cert.EncodedLength(), sig, sig_len);
                    if (status != SUCCESS)
                    {
                        return status;
                    }
                }
            }
            else
            {
                reply_bytes_len = strlen("NOT_FOUND");
                reply_bytes = (unsigned char*) malloc(reply_bytes_len);
                if (reply_bytes == nullptr)
                {
                    return MALLOC_FAILURE;
                }

                memcpy(reply_bytes, "NOT_FOUND", strlen("NOT_FOUND"));
            }

            // send it as a message
            status = ReplyToMessage(0, message, reply_bytes, reply_bytes_len);
            free(reply_bytes);
            return status;
        }

        if (message->message == "REQUESTACL")
        {
            std::string requested_acl((char*)message->argument, message->arg_len);

            // iterate through all acls to see if this service has heard an acl with the appropriate msg_id
            AccessControlList found_acl;
            bool was_found = false;
            bool was_local = false;
            local_acls_mutex.lock();
            for (std::vector<AccessControlList>::iterator itr = local_acls.begin(); itr != local_acls.end(); ++itr)
            {
                if (itr->msg_id == requested_acl)
                {
                    found_acl = *itr;
                    was_found = true;
                    was_local = true;
                    break;
                }
            }
            local_acls_mutex.unlock();

            if (was_found == false)
            {
                external_acls_mutex.lock();
                for (std::unordered_map<std::string, std::vector<AccessControlList>>::iterator map_itr = external_acls.begin(); map_itr != external_acls.end(); ++map_itr)
                {
                    for (std::vector<AccessControlList>::iterator vec_itr = map_itr->second.begin(); vec_itr != map_itr->second.end(); ++vec_itr)
                    {
                        if (vec_itr->msg_id == requested_acl)
                        {
                            found_acl = *vec_itr;
                            was_found = true;
                            break;
                        }
                    }

                    if (was_found == true)
                    {
                        break;
                    }
                }
                external_acls_mutex.unlock();
            }

            uint32_t reply_bytes_len = 0;
            unsigned char* reply_bytes = nullptr;
            if (status == SUCCESS && was_found)
            {
                uint32_t sig_len = 0;

                // if it was local, we aren't storing the raw signed bytes, so let's sign it now
                if (was_local)
                {
                    sig_len = RsaWrappers::SignatureLength(private_key);
                }

                reply_bytes_len = (uint32_t)found_acl.EncodedLength() + sig_len;
                reply_bytes = (unsigned char*) malloc(reply_bytes_len);
                if (reply_bytes == nullptr)
                {
                    return MALLOC_FAILURE;
                }

                returned_value = found_acl.Encode(reply_bytes, found_acl.EncodedLength());
                if (returned_value < 0)
                {
                    return returned_value;
                }

                if (was_local)
                {
                    unsigned char* sig = reply_bytes + found_acl.EncodedLength();
                    status = RsaWrappers::CreateSignedDigest(private_key, reply_bytes, found_acl.EncodedLength(), sig, sig_len);
                    if (status != SUCCESS)
                    {
                        return status;
                    }
                }
            }
            else
            {
                reply_bytes_len = strlen("NOT_FOUND");
                reply_bytes = (unsigned char*) malloc(reply_bytes_len);
                if (reply_bytes == nullptr)
                {
                    return MALLOC_FAILURE;
                }

                memcpy(reply_bytes, "NOT_FOUND", strlen("NOT_FOUND"));
            }

            // send it as a message
            status = ReplyToMessage(0, message, reply_bytes, reply_bytes_len);
            return status;
        }

        if (message->message == "REQUESTLISTACLS")
        {
            std::string requested_service((char*)message->argument, message->arg_len);
            std::vector<AccessControlList> overheard_acls;

            if (requested_service == GetId())
            {
                local_acls_mutex.lock();
                overheard_acls = local_acls;
                local_acls_mutex.unlock();
            }
            else
            {
                external_acls_mutex.lock();
                if (external_acls.count(requested_service) != 0)
                {
                    overheard_acls = external_acls[requested_service];
                }
                external_acls_mutex.unlock();
            }

            std::string reply_ids;
            for (unsigned int i = 0; i < overheard_acls.size(); ++i)
            {
                if (overheard_acls[i].is_private == false)
                {
                    reply_ids += overheard_acls[i].msg_id + ",";
                }
            }

            const unsigned char* reply_bytes = (overheard_acls.size() > 0) ? (const unsigned char*)reply_ids.c_str() : (const unsigned char*)"NOT_FOUND";
            const uint32_t reply_bytes_len = (overheard_acls.size() > 0) ? reply_ids.size() : strlen("NOT_FOUND");
            status = ReplyToMessage(0, message, reply_bytes, reply_bytes_len);
            return status;
        }

        // check against ACLs
        status = EvaluateStatement(message->from + " CAN SEND MESSAGE " + message->message + " TO " + id, message);
        if (status == NOT_IN_ACLS)
        {
            // TODO only encrypt if replying to an encrypted message?
            ReplyToMessage(0, message, (const unsigned char*)"NOT_IN_ACLS", strlen("NOT_IN_ACLS") + 1);
            Log::Line(Log::INFO, "UbipalService::RecvMessage: UbipalService::CheckAcls returned %s for message %s from %s",
                      GetErrorDescription(status), message->message.c_str(), message->from.c_str());
            return status;
        }
        else if (status == FAILED_CONDITIONS)
        {
            // TODO only encrypt if replying to an encrypted message?
            ReplyToMessage(0, message, (const unsigned char*)"FAILED_CONDITIONS", strlen("FAILED_CONDITIONS") + 1);
            Log::Line(Log::INFO, "UbipalService::RecvMessage: UbipalService::CheckAcls returned %s for message %s from %s",
                      GetErrorDescription(status), message->message.c_str(), message->from.c_str());
            return status;
        }
        else if (status == WAIT_ON_CONDITIONS)
        {
            Log::Line(Log::DEBUG, "UbipalService::RecvMessage: Waiting on conditions.");
            return status;
        }
        else if (status != SUCCESS)
        {
            Log::Line(Log::INFO, "UbipalService::RecvMessage: UbipalService::CheckAcls returned %s for message %s from %s",
                      GetErrorDescription(status), message->message.c_str(), message->from.c_str());
            return status;
        }

        status = MessageConditionPassed(*message);
        if (status != SUCCESS)
        {
            Log::Line(Log::WARN, "UbipalService::REcvMessage: MessageConditionPassed failed: %s", GetErrorDescription(status));
            return status;
        }

        return status;
    }

    int UbipalService::BroadcastData(const unsigned char* const data, const uint32_t data_len)
    {
        int status = SUCCESS;
        int returned_value = 0;

        // send to all services we've heard from (handles firewalls and multiple subnets)
        std::vector<NamespaceCertificate> services;
        status = GetNames(GetNamesFlags::INCLUDE_UNTRUSTED | GetNamesFlags::INCLUDE_TRUSTED, services);
        if (status == SUCCESS)
        {
            for (unsigned int i = 0; i < services.size(); ++i)
            {
                status = SendData(services[i].address, services[i].port, data, data_len);
                if (status != SUCCESS)
                {
                    Log::Line(Log::DEBUG, "UbipalService::BroadcastData: Failed to SendData to a known service: %s", GetErrorDescription(status));
                }
            }
        }
        else
        {
            Log::Line(Log::DEBUG, "UbipalService::BroadcastData: GetNames failed: %s", GetErrorDescription(status));
        }

        // broadcast to all services on our subnet
        returned_value = sendto(broadcast_fd, data, data_len, 0, broadcast_info->ai_addr, broadcast_info->ai_addrlen);
        if (returned_value == -1)
        {
            Log::Line(Log::EMERG, "UbipalService::BroadcastData: sendto failed.");
            return NETWORKING_FAILURE;
        }

        return SUCCESS;
    }

    int UbipalService::SendData(const std::string& address, const std::string& port, const unsigned char* const data, const uint32_t data_len) const
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
        current_cert_mutex.lock();
        address = addr;

        // update namespace certificate
        NamespaceCertificate self_nc;
        self_nc.from = id;
        self_nc.id = id;
        self_nc.description = description;
        self_nc.address = address;
        self_nc.port = port;

        if (current_cert != nullptr)
        {
            self_nc.version = current_cert->version + 1;
        }
        else
        {
            self_nc.version = 0;
        }

        current_cert = new NamespaceCertificate();
        *current_cert = self_nc;
        current_cert_mutex.unlock();
        return SUCCESS;
    }

    int UbipalService::SetPort(const std::string& prt)
    {
        current_cert_mutex.lock();
        port = prt;

        // update namespace certificate
        NamespaceCertificate self_nc;
        self_nc.from = id;
        self_nc.id = id;
        self_nc.description = description;
        self_nc.address = address;
        self_nc.port = port;

        if (current_cert != nullptr)
        {
            self_nc.version = current_cert->version + 1;
        }
        else
        {
            self_nc.version = 0;
        }


        current_cert = new NamespaceCertificate();
        *current_cert = self_nc;
        current_cert_mutex.unlock();
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

    int UbipalService::ReplyToMessage(const uint32_t flags, const Message* const msg, const unsigned char* const arg, const uint32_t arg_len)
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

        return SendMessage(flags, &reply_to, message, arg, arg_len);
    }

    int UbipalService::SendMessage(const uint32_t flags, const NamespaceCertificate* to, const std::string& message,
                                   const unsigned char* const arg, const uint32_t arg_len)
    {
        return SendMessage(flags, to, message, arg, arg_len, NULL);
    }

    int UbipalService::SendMessage(const uint32_t flags, const NamespaceCertificate* to, const std::string& message,
                                   const unsigned char* const arg, const uint32_t arg_len, const UbipalReplyCallback reply_callback)
    {
        FUNCTION_START;
        Message* msg = nullptr;
        HandleSendMessageArguments* sm_args = nullptr;
        std::pair<std::unordered_map<std::string, UbipalReplyCallback>::iterator, bool> returned_pair;

        // check args
        if ((to != nullptr) && (to->address.empty() || to->port.empty()))
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
        if (to != nullptr)
        {
            msg->to = to->id;
        }
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

        // if we've cached the response, we just simulate a reply
        // but we can only check this if we're sending to a name
        if ((to != nullptr) && (to->id.empty() == false))
        {
            cached_messages_mutex.lock();
            if (cached_messages.count(to->id) != 0)
            {
                // If we don't have the message (or it's the default place holder, then we can fake it.
                // Else, we'll have to actually send the message
                if (cached_messages[to->id].count(message) != 0 && cached_messages[to->id][message].message.size() != 0)
                {
                    Message sim_reply = cached_messages[to->id][message];
                    sim_reply.message = "REPLY_" + msg->msg_id;

                    cached_messages_mutex.unlock();

                    status = RecvMessage(&sim_reply);
                    return status;
                }
            }
            cached_messages_mutex.unlock();
        }

        sm_args = new HandleSendMessageArguments(this);
        if (to != nullptr)
        {
            sm_args->address = to->address;
            sm_args->port = to->port;
        }
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
    UbipalService::HandleSendMessageArguments::HandleSendMessageArguments(UbipalService* const _us) : us(_us) {}

    void* UbipalService::HandleSendMessage(void* args)
    {
        FUNCTION_START;
        HandleSendMessageArguments* sm_args = nullptr;
        unsigned char* bytes = nullptr;
        int bytes_length = 0;
        unsigned int sig_len = 0;
        unsigned char* sig = nullptr;
        RSA* dest_pub_key = nullptr;
        unsigned char* result = nullptr;
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
        bytes = (unsigned char*)malloc(total_len);
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
            // if we have an AES key, use that, else make one and send it
            sm_args->us->aes_keys_mutex.lock();
            // we have no AES key, so make one and send it
            if (sm_args->us->aes_keys.count(sm_args->msg->to) == 0)
            {
                status = RsaWrappers::StringToPublicKey(sm_args->msg->to, dest_pub_key);
                if (status != SUCCESS)
                {
                    Log::Line(Log::EMERG, "UbipalService::HandleSendMessage: RsaWrappers::StringToPublicKey failed: %s", GetErrorDescription(status));
                    RETURN_STATUS(status);
                }

                // create key & IV
                unsigned char* key = nullptr;
                int key_length = 0;
                unsigned char* iv = nullptr;
                int iv_length = 0;
                status = AesWrappers::GenerateAesObject(key, &key_length);
                if (status != SUCCESS)
                {
                    Log::Line(Log::EMERG, "UbipalServide::HandleSendMessage: AesWrappers::GenerateAesObject failed creating key: %s",
                              GetErrorDescription(status));
                    RETURN_STATUS(status);
                }

                status = AesWrappers::GenerateAesObject(iv, &iv_length);
                if (status != SUCCESS)
                {
                    Log::Line(Log::EMERG, "UbipalServide::HandleSendMessage: AesWrappers::GenerateAesObject failed creating iv: %s",
                              GetErrorDescription(status));
                    RETURN_STATUS(status);
                }

                //  put it in our structure
                sm_args->us->aes_keys[sm_args->msg->to] = std::tuple<unsigned char*, unsigned char*>(key, iv);

                // send it to receiving message
                uint32_t encoded_aes_length = 4 + key_length + 4 + iv_length;
                unsigned char* encoded_aes_pair = (unsigned char*)malloc(encoded_aes_length);
                if (encoded_aes_pair == nullptr)
                {
                    Log::Line(Log::EMERG, "UbipalService::HandleSendMessage: malloc failed on encoded_aes_pair");
                    RETURN_STATUS(MALLOC_FAILURE);
                }

                // place aes key & iv in string
                returned_value = BaseMessage::EncodeBytes(encoded_aes_pair, encoded_aes_length, key, key_length);
                if (returned_value < 0)
                {
                    Log::Line(Log::EMERG, "UbipalService::HandleSendMessage: BaseMessage::EncodeBytes failed: %d", GetErrorDescription(status));
                    RETURN_STATUS(status);
                }
                returned_value = BaseMessage::EncodeBytes(encoded_aes_pair + returned_value, encoded_aes_length - returned_value, iv, iv_length);

                // and encrypt them
                unsigned char* encrypted_aes_pair = nullptr;
                unsigned int encrypted_aes_len = 0;
                status = RsaWrappers::Encrypt(dest_pub_key, encoded_aes_pair, encoded_aes_length, encrypted_aes_pair, &encrypted_aes_len);
                if (status != SUCCESS)
                {
                    Log::Line(Log::EMERG, "UbipalSerivce::HandleSendMessage: RsaWrappers::Encrypt failed on encrypted_ase_pair: %s",
                              GetErrorDescription(status));
                    RETURN_STATUS(status);
                }

                // Send as a message
                Message aes_msg(encrypted_aes_pair, encrypted_aes_len);
                aes_msg.to = sm_args->msg->to;
                aes_msg.from = sm_args->msg->from;
                aes_msg.message = "NEWAESPAIR";

                // encode and sign
                unsigned int signed_msg_len = aes_msg.EncodedLength() + RsaWrappers::SignatureLength(sm_args->us->private_key);
                unsigned char* signed_msg = (unsigned char*)malloc(signed_msg_len);
                if (signed_msg == nullptr)
                {
                    Log::Line(Log::EMERG, "UbipalService::HandleSendMessage malloc failure on signed_msg");
                    RETURN_STATUS(MALLOC_FAILURE);
                }

                status = aes_msg.Encode(signed_msg, aes_msg.EncodedLength());
                if (status < 0)
                {
                    Log::Line(Log::EMERG, "UbipalService::HandleSendMessage aes_msg.Encode: %s", GetErrorDescription(status));
                    RETURN_STATUS(status);
                }

                unsigned int sig_len = RsaWrappers::SignatureLength(sm_args->us->private_key);
                unsigned char* sig = signed_msg + aes_msg.EncodedLength();
                status = RsaWrappers::CreateSignedDigest(sm_args->us->private_key, signed_msg, aes_msg.EncodedLength(),
                                                         sig, sig_len);
                if (status != SUCCESS)
                {
                    Log::Line(Log::EMERG, "UbipalService::HandleSendMessage: CreateSignedDigest failed: %s", GetErrorDescription(status));
                    RETURN_STATUS(status);
                }

                status = sm_args->us->SendData(sm_args->address, sm_args->port, signed_msg, signed_msg_len);
                if (status != SUCCESS)
                {
                    Log::Line(Log::EMERG, "UbipalService::HandleSendMessage: SendData failed for encrypted_aes_msg: %s", GetErrorDescription(status));
                    RETURN_STATUS(status);
                }

                // TODO remove this hack
                sleep(1);
            }

            if (sm_args->us->aes_keys.count(sm_args->msg->to) == 1)
            {
                std::tuple<unsigned char*, unsigned char*> keyIv = sm_args->us->aes_keys[sm_args->msg->to];
                unsigned char* aes_encrypted = nullptr;
                unsigned int aes_encrypted_len = 0;

                // this encrypts everything after the from field, which must be left unencrypted for the sake of the receiving service
                // knowing which aes key/iv to use for decrytion
                status = AesWrappers::Encrypt(std::get<0>(keyIv), std::get<1>(keyIv), bytes + 5 + sm_args->msg->from.size(), total_len - 5 - sm_args->msg->from.size(),
                                              aes_encrypted, &aes_encrypted_len);
                if (status != SUCCESS)
                {
                    Log::Line(Log::EMERG, "UbipalSerivce::HandleSendMessage: AesWrappers::Encrypt failed: %s", GetErrorDescription(status));
                    RETURN_STATUS(status);
                }

                result_len = aes_encrypted_len + 5 + sm_args->msg->from.size();
                result = (unsigned char*)malloc(result_len);
                memcpy(result, bytes, 5 + sm_args->msg->from.size());
                memcpy(result + 5 + sm_args->msg->from.size(), aes_encrypted, aes_encrypted_len);
            }
            else
            {
                Log::Line(Log::EMERG, "UbipalService::HandleSendMessage: Failed to create a new aes key & iv pair and send to dest.");
                RETURN_STATUS(GENERAL_FAILURE);
            }

            sm_args->us->aes_keys_mutex.unlock();

            // make the below code work regardless of encryption or not
            free(bytes);
            bytes = result;
            result = nullptr;
            total_len = result_len;
        }

        // if there's not a single destination, broadcast!
        if (sm_args->msg->to.empty())
        {
            status = sm_args->us->BroadcastData(bytes, total_len);
            if (status < 0)
            {
                Log::Line(Log::EMERG, "UbipalService::HandleSendMessage: SendData failed: %s", GetErrorDescription(status));
                RETURN_STATUS(status);
            }
            else
            {
                status = SUCCESS;
            }
        }
        else
        {
            // else send it!
            status = sm_args->us->SendData(sm_args->address, sm_args->port, bytes, total_len);
            if (status < 0)
            {
                Log::Line(Log::EMERG, "UbipalService::HandleSendMessage: SendData failed: %s", GetErrorDescription(status));
                RETURN_STATUS(status);
            }
            else
            {
                status = SUCCESS;
            }
        }

        exit:
            #ifdef EVALUATE
                // only count successfully sent messages because they only complete sending if successful
                if (status == SUCCESS)
                {
                    ++NUM_MESSAGES_SENT;
                }
            #endif
            if ((sm_args->flags & SendMessageFlags::MESSAGE_AWAIT_REPLY) == 0)
            {
                delete sm_args->msg;
            }
            delete sm_args;
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
        if (send_to != nullptr)
        {
            msg->to = send_to->id;
        }
        msg->from = id;
        msg->id = id;
        msg->description = description;
        msg->address = address;
        msg->port = port;

        current_cert_mutex.lock();
        if (current_cert && *msg == *current_cert)
        {
            *msg = *current_cert;
        }
        else
        {
            if (current_cert == nullptr)
            {
                current_cert = new NamespaceCertificate();
                msg->version = 0;
            }
            else
            {
                msg->version = current_cert->version + 1;
            }
            *current_cert = *msg;
        }
        current_cert_mutex.unlock();

        sm_args = new HandleSendMessageArguments(this);
        if (send_to != nullptr)
        {
            sm_args->address = send_to->address;
            sm_args->port = send_to->port;
        }
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
            if (status != SUCCESS)
            {
                delete msg;
                delete sm_args;
            }
            FUNCTION_END;
    }

    int UbipalService::SendName(const uint32_t flags, const std::string& address, const std::string& port)
    {
        NamespaceCertificate  nc;
        nc.address = address;
        nc.port = port;

        return SendName(flags, &nc);
    }

    int UbipalService::SendAcl(const uint32_t flags, const AccessControlList& acl, const NamespaceCertificate* const send_to)
    {
        FUNCTION_START;
        AccessControlList* msg = nullptr;
        HandleSendMessageArguments* sm_args = nullptr;

        if ((flags & ~(SendMessageFlags::NONBLOCKING | SendMessageFlags::NO_ENCRYPTION)) != 0)
        {
            Log::Line(Log::WARN, "UbipalService::SendName: called with invalid flags");
            RETURN_STATUS(INVALID_ARG);
        }

        msg = new AccessControlList();

        if (send_to != nullptr)
        {
            msg->to = send_to->id;
        }

        msg->msg_id = acl.msg_id;
        msg->from = id;
        msg->rules = acl.rules;
        msg->id = acl.id;

        sm_args = new HandleSendMessageArguments(this);
        if (send_to != nullptr)
        {
            sm_args->address = send_to->address;
            sm_args->port = send_to->port;
        }
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
            if (status != SUCCESS)
            {
                delete msg;
                delete sm_args;
            }
            FUNCTION_END;
    }

    int UbipalService::GetNames(const uint32_t flags, std::vector<NamespaceCertificate>& names)
    {
        int status = SUCCESS;

        // check flags
        if ((flags & ~(GetNamesFlags::INCLUDE_UNTRUSTED | GetNamesFlags::INCLUDE_TRUSTED | GetNamesFlags::INCLUDE_SELF)) != 0)
        {
            Log::Line(Log::WARN, "UbipalService::GetNames: passed invalid flag");
            return INVALID_ARG;
        }

        // empty vector
        names.clear();

        // add me if flaged
        if ((flags & GetNamesFlags::INCLUDE_SELF) != 0)
        {
            current_cert_mutex.lock();
            if (current_cert != nullptr)
            {
                names.push_back(*current_cert);
            }
            else
            {
                NamespaceCertificate self_nc;
                self_nc.from = id;
                self_nc.id = id;
                self_nc.description = description;
                self_nc.address = address;
                self_nc.port = port;
                self_nc.version = 0;
                names.push_back(self_nc);

                current_cert = new NamespaceCertificate();
                *current_cert = self_nc;
            }
            current_cert_mutex.unlock();
        }

        // add untrusted, if flagged
        services_mutex.lock();
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
        services_mutex.unlock();

        return status;
    }

    int UbipalService::SetThreadCounts(const unsigned int& recv_threads, const unsigned int& send_threads)
    {
        num_recv_threads = recv_threads;
        num_send_threads = send_threads;
        return SUCCESS;
    }

    int UbipalService::EvaluateStatement(const std::string& statement)
    {
        return EvaluateStatement(statement, NULL);
    }

    int UbipalService::EvaluateStatement(const std::string& statement, const Message* message)
    {
        local_acls_mutex.lock();
        external_acls_mutex.lock();

        int status = SUCCESS;
        std::vector<std::string> acl_trail;
        std::vector<Statement> conditions;
        Statement statement_struct;

        status = ParseStatement(statement, statement_struct);
        if (status != SUCCESS)
        {
            RETURN_STATUS(status);
        }

        status = EvaluateStatementRecurse(statement_struct, statement_struct.root, acl_trail, conditions, message, std::numeric_limits<uint32_t>::max());
        if (status != SUCCESS)
        {
            RETURN_STATUS(status);
        }

        exit:
            external_acls_mutex.unlock();
            local_acls_mutex.unlock();
            return status;
    }

    int UbipalService::ParseStatement(const std::string& statement, Statement& statement_struct)
    {
        int status = SUCCESS;
        int returned_value = 0;

        // default all fields
        statement_struct.root = std::string();
        statement_struct.type = Statement::Type::INVALID;
        statement_struct.name1 = std::string();
        statement_struct.name2 = std::string();
        statement_struct.name3 = std::string();
        statement_struct.comparison = std::string();
        statement_struct.num1 = 0;
        statement_struct.num2 = 0;
        statement_struct.statement = nullptr;

        // parse type of statement
        if (statement.find(" CAN SAY") != std::string::npos)
        {
            statement_struct.type = Statement::Type::CAN_SAY;
            size_t connective = statement.find(" CAN SAY");
            size_t connective_end = statement.find(" ", connective + strlen(" CAN SAY"));

            // if there is a delegation depth limit, handle it here
            if (statement[connective_end - 1] == ']')
            {
                std::string num_string(statement, connective + strlen(" CAN SAY["), (connective_end - 1) - (connective + strlen(" CAN SAY[")));
                returned_value = std::sscanf(num_string.c_str(), "%u", &statement_struct.num1);
            }
            else
            {
                statement_struct.num1 = std::numeric_limits<uint32_t>::max();
            }

            statement_struct.statement = new Statement;
            if (statement_struct.statement == nullptr)
            {
                RETURN_STATUS(MALLOC_FAILURE);
            }
            size_t start = statement.rfind(" ", connective - 1) + 1;

            if (start != std::string::npos)
            {
                statement_struct.name1 = statement.substr(start, connective - start);
            }
            else
            {
                statement_struct.name1 = statement.substr(0, connective);
            }

            status = ParseStatement(statement.substr(connective_end), *statement_struct.statement);
            if (status != SUCCESS)
            {
                RETURN_STATUS(status)
            }
        }
        else if (statement.find(" CAN SEND MESSAGE ") != std::string::npos)
        {
            statement_struct.type = Statement::Type::CAN_SEND_MESSAGE;

            // find connective
            size_t connective = statement.find(" CAN SEND MESSAGE ");
            size_t connective_end = connective + strlen(" CAN SEND MESSAGE ");

            // find sending service
            size_t start = statement.rfind(" ", connective - 1) + 1;
            if (start != std::string::npos)
            {
                statement_struct.name1 = statement.substr(start, connective - start);
            }
            else
            {
                statement_struct.name1 = statement.substr(0, connective);
            }

            // find message type
            size_t end = statement.find(" ", connective_end);
            statement_struct.name2 = statement.substr(connective_end, end - connective_end);

            // find receiving service
            start = end + strlen(" TO ");
            size_t alt_end = statement.find(",", start);
            end = statement.find(" ", start);

            if (alt_end < end)
            {
                statement_struct.name3 = statement.substr(start, alt_end - start);
            }
            else if (end != std::string::npos)
            {
                statement_struct.name3 = statement.substr(start, end - start);
            }
            else
            {
                statement_struct.name3 = statement.substr(start);
            }
        }
        else if (statement.find(" IS A ") != std::string::npos)
        {
            statement_struct.type = Statement::Type::IS_A;

            size_t connective = statement.find(" IS A ");
            size_t connective_end = connective + strlen(" IS A ");

            // first name
            size_t start = statement.rfind(" ", connective - 1) + 1;
            if (start != std::string::npos)
            {
                statement_struct.name1 = statement.substr(start, connective - start);
            }
            else
            {
                statement_struct.name1 = statement.substr(0, connective);
            }

            // second name
            size_t end = statement.find(" ", connective_end);
            if (end != std::string::npos)
            {
                statement_struct.name2 = statement.substr(connective_end, end - connective_end);
            }
            else
            {
                statement_struct.name2 = statement.substr(connective_end);
            }
        }
        else if (statement.find(" IS ") != std::string::npos)
        {
            statement_struct.type = Statement::Type::IS;

            size_t connective = statement.find(" IS ");
            size_t connective_end = connective + strlen(" IS ");

            // find name
            size_t start = statement.rfind(" ", connective - 1) + 1;
            if (start != std::string::npos)
            {
                statement_struct.name1 = statement.substr(start, connective - start);
            }
            else
            {
                statement_struct.name1 = statement.substr(0, connective);
            }

            // find name2
            size_t end = statement.find(" ", connective_end);
            if (end != std::string::npos)
            {
                statement_struct.name2 = statement.substr(connective_end, end - connective_end);
            }
            else
            {
                statement_struct.name2 = statement.substr(connective_end);
            }

            statement_struct.name3 = std::string();
        }
        else if (statement.find(" CONFIRMS ") != std::string::npos)
        {
            statement_struct.type = Statement::Type::CONFIRMS;

            size_t connective = statement.find(" CONFIRMS ");
            size_t connective_end = connective + strlen(" CONFIRMS ");

            // find name
            size_t start = statement.rfind(" ", connective - 1) + 1;
            if (start != std::string::npos)
            {
                statement_struct.name1 = statement.substr(start, connective - start);
            }
            else
            {
                statement_struct.name1 = statement.substr(0, connective);
            }

            // find name2
            size_t end = statement.find(" ", connective_end);
            if (end != std::string::npos)
            {
                statement_struct.name2 = statement.substr(connective_end, end - connective_end);
            }
            else
            {
                statement_struct.name2 = statement.substr(connective_end);
            }
        }
        else if (statement.find("CurrentTime() ") != std::string::npos)
        {
            statement_struct.type = Statement::Type::CURRENT_TIME;
            if (statement.find(" < ") != std::string::npos)
            {
                statement_struct.comparison = "<";
            }
            else if (statement.find(" > ") != std::string::npos)
            {
                statement_struct.comparison = ">";
            }
            else
            {
                RETURN_STATUS(INVALID_SYNTAX);
            }

            size_t num_start = statement.find(" " + statement_struct.comparison + " ") + strlen(" < ");
            std::string num_string = statement.substr(num_start);
            returned_value = std::sscanf(num_string.c_str(), "%u:%u", &statement_struct.num1, &statement_struct.num2);
            if (returned_value != 2)
            {
                RETURN_STATUS(INVALID_SYNTAX);
            }
        }
        else if (statement.find("CurrentDate() ") != std::string::npos)
        {
            statement_struct.type = Statement::Type::CURRENT_DATE;
            if (statement.find(" < ") != std::string::npos)
            {
                statement_struct.comparison = "<";
            }
            else if (statement.find(" > ") != std::string::npos)
            {
                statement_struct.comparison = ">";
            }
            else
            {
                RETURN_STATUS(INVALID_SYNTAX);
            }


            size_t num_start = statement.find(" " + statement_struct.comparison + " ") + strlen(" < ");
            std::string num_string = statement.substr(num_start);
            returned_value = std::sscanf(num_string.c_str(), "%u", &statement_struct.num1);
            if (returned_value != 1)
            {
                RETURN_STATUS(INVALID_SYNTAX);
            }
        }
        else
        {
            RETURN_STATUS(INVALID_SYNTAX);
        }

        // scope variable end to avoid jump errors when going to exit
        {
            // find the root of the authority for this (if the rule starts with FOO SAYS)
            size_t end = statement.find(" SAYS ");
            if (end != std::string::npos)
            {
                statement_struct.root = statement.substr(0, end);
            }
            else
            {
                // if it doesn't, if we're talking about a CAN_SEND_MESSAGE type, set the base to the receiving service if it isn't a variable
                if (statement_struct.type == Statement::Type::CAN_SEND_MESSAGE && statement_struct.name3.size() != 1)
                {
                    statement_struct.root = statement_struct.name3;
                }
                else
                {
                    statement_struct.root = id;
                }
            }
        }

        exit:
            return status;
    }

    int UbipalService::EvaluateStatementRecurse(const Statement& statement, const std::string& current_service, std::vector<std::string>& acl_trail,
                                                std::vector<Statement>& conditions, const Message* message, const uint32_t delegation_bound)
    {
        int status = SUCCESS;
        int returned_value = 0;

        std::vector<ConsiderService> to_consider;
        ConsiderService temp_consider;
        std::vector<AccessControlList> current_acls;
        std::unordered_map<std::string, std::vector<AccessControlList>>::iterator external_acls_itr;
        std::vector<Statement> rule_conditions;
        std::vector<std::string> new_acl_trail;
        std::vector<Statement> new_conditions;

        // some statement types need not look at the ACLs, handle those immediately
        if (statement.type == Statement::Type::CURRENT_TIME)
        {
            time_t timet = time(NULL);
            struct tm* time_struct = localtime(&timet);
            if (time_struct == nullptr)
            {
                return GENERAL_FAILURE;
            }
            bool passed_eval = false;

            if (statement.comparison == "<")
            {
                passed_eval = (((unsigned int)time_struct->tm_hour) < statement.num1 || (((unsigned int)time_struct->tm_hour) == statement.num1 && ((unsigned int)time_struct->tm_min) < statement.num2));
            }
            else if (statement.comparison == ">")
            {
                passed_eval = (((unsigned int)time_struct->tm_hour) > statement.num1 || (((unsigned int)time_struct->tm_hour) == statement.num1 && ((unsigned int)time_struct->tm_min) > statement.num2));
            }
            else
            {
                return INVALID_SYNTAX;
            }

            return passed_eval ? SUCCESS : FAILED_EVALUATION;
        }
        else if (statement.type == Statement::Type::CURRENT_DATE)
        {
            struct timeval tv;
            returned_value = gettimeofday(&tv, NULL);
            if (returned_value == -1)
            {
                return GENERAL_FAILURE;
            }
            bool passed_eval = false;

            if (statement.comparison == "<")
            {
                passed_eval = (tv.tv_sec < statement.num1);
            }
            else if (statement.comparison == ">")
            {
                passed_eval = (tv.tv_sec > statement.num1);
            }
            else
            {
                return INVALID_SYNTAX;
            }

            return passed_eval ? SUCCESS : FAILED_EVALUATION;
        }
        else if (statement.type == Statement::Type::CONFIRMS)
        {
            return WAIT_ON_CONDITIONS;
        }

        // if we're considering this service, use our local ACLs, else use what we've heard
        if (current_service == id)
        {
            current_acls = local_acls;
        }
        else
        {
            external_acls_itr = external_acls.find(current_service);
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
            bool seen_before = false;
            // ensure this ACL hasn't been seen before, we don't want loops
            for (unsigned int k = 0; k < acl_trail.size(); ++k)
            {
                if (acl_trail[k] == current_acls[i].msg_id)
                {
                    seen_before = true;
                    break;
                }
            }

            if (seen_before)
            {
                continue;
            }

            // for each rules in the acl
            Statement parsed_rule;
            for (unsigned int j = 0; j < current_acls[i].rules.size(); ++j)
            {
                status = ParseStatement(current_acls[i].rules[j], parsed_rule);
                if (status != SUCCESS)
                {
                    continue;
                }
                status = GetConditionsFromRule(current_acls[i].rules[j], rule_conditions);

                // compare rules
                if (statement.type != parsed_rule.type)
                {
                    if (parsed_rule.type != Statement::Type::CAN_SAY
                        || parsed_rule.statement == nullptr
                        || parsed_rule.statement->type != statement.type)
                    {
                        continue;
                    }
                }

                bool skip = false;
                for (Statement* itr = &parsed_rule; itr != nullptr; itr = itr->statement)
                {
                    // check for any mismatches
                    if (statement.name1 != itr->name1)
                    {
                        // all variables are length 1
                        if (itr->name1.size() > 1 && itr->type != Statement::Type::CAN_SAY)
                        {
                            skip = true;
                            break;
                        }

                        // do any necessary replacement in the conditions
                        if (itr->type == statement.type)
                        {
                            for (unsigned int i = 0; i < rule_conditions.size(); ++i)
                            {
                                if (rule_conditions[i].name1 == itr->name1)
                                {
                                    rule_conditions[i].name1 = statement.name1;
                                }
                                if (rule_conditions[i].name2 == itr->name1)
                                {
                                    rule_conditions[i].name2 = statement.name1;
                                }
                                if (rule_conditions[i].name3 == itr->name1)
                                {
                                    rule_conditions[i].name3 = statement.name1;
                                }
                            }
                        }
                    }
                    if (statement.name2 != itr->name2)
                    {
                        // all variables are length 1
                        if (itr->name2.size() > 1 && itr->type != Statement::Type::CAN_SAY)
                        {
                            skip = true;
                            break;
                        }

                        // do any necessary replacement in the conditions
                        if (itr->type == statement.type)
                        {
                            for (unsigned int i = 0; i < rule_conditions.size(); ++i)
                            {
                                if (rule_conditions[i].name1 == itr->name2)
                                {
                                    rule_conditions[i].name1 = statement.name2;
                                }
                                if (rule_conditions[i].name2 == itr->name2)
                                {
                                    rule_conditions[i].name2 = statement.name2;
                                }
                                if (rule_conditions[i].name3 == itr->name2)
                                {
                                    rule_conditions[i].name3 = statement.name2;
                                }
                            }
                        }
                    }
                    if (statement.name3 != itr->name3)
                    {
                        // all variables are length 1
                        if (itr->name3.size() > 1 && itr->type != Statement::Type::CAN_SAY)
                        {
                            skip = true;
                            break;
                        }

                        // do any necessary replacement in the conditions
                        if (itr->type == statement.type)
                        {
                            for (unsigned int i = 0; i < rule_conditions.size(); ++i)
                            {
                                if (rule_conditions[i].name1 == itr->name3)
                                {
                                    rule_conditions[i].name1 = statement.name3;
                                }
                                if (rule_conditions[i].name2 == itr->name3)
                                {
                                    rule_conditions[i].name2 = statement.name3;
                                }
                                if (rule_conditions[i].name3 == itr->name3)
                                {
                                    rule_conditions[i].name3 = statement.name3;
                                }
                            }
                        }
                    }
                }

                if (skip == true)
                {
                    continue;
                }

                if (parsed_rule.type == Statement::Type::CAN_SAY)
                {
                    temp_consider.service_id = parsed_rule.name1;
                    temp_consider.delegation_bound = std::min(delegation_bound, parsed_rule.num1);
                    if (temp_consider.delegation_bound == 0)
                    {
                        continue;
                    }
                }
                else
                {
                    temp_consider.service_id = current_service;
                }
                temp_consider.referenced_from_acl = current_acls[i].msg_id;
                temp_consider.conditions = rule_conditions;

                if (parsed_rule.type == Statement::Type::CAN_SAY)
                {
                    to_consider.push_back(temp_consider);
                }
                else
                {
                    to_consider.insert(to_consider.begin(), temp_consider);
                }
            }
        }

        if (to_consider.size() == 0)
        {
            return NOT_IN_ACLS;
        }

        // call this recursively for each in the consideration vector
        std::vector<Statement> all_conditions;
        for (unsigned int i = 0; i < to_consider.size(); ++i)
        {
            all_conditions.clear();
            // if to_consider[i].id is current, then just check conditions
            if (to_consider[i].service_id == current_service)
            {
                all_conditions.insert(all_conditions.end(), conditions.begin(), conditions.end());
                all_conditions.insert(all_conditions.end(), to_consider[i].conditions.begin(), to_consider[i].conditions.end());

                // Remove any non-confirms conditions
                bool did_fail_conds = false;
                for (unsigned int j = 0; j < all_conditions.size(); ++j)
                {
                    if (all_conditions[j].type != Statement::Type::CONFIRMS)
                    {
                        std::vector<std::string> cond_acl_trail;
                        std::vector<Statement> cond_conds;
                        status = EvaluateStatementRecurse(all_conditions[j], current_service, cond_acl_trail, cond_conds, NULL, std::numeric_limits<uint32_t>::max());
                        if (status == SUCCESS)
                        {
                            all_conditions.erase(all_conditions.begin() + i);
                            --i;
                        }
                        else
                        {
                            did_fail_conds = true;
                            break;
                        }
                    }
                }

                if (did_fail_conds)
                {
                    continue;
                }

                if (all_conditions.size() == 0)
                {
                    return SUCCESS;
                }
                else
                {
                    status = ConfirmChecks(*message, all_conditions);
                    if (status != SUCCESS && status != WAIT_ON_CONDITIONS && status != FAILED_CONDITIONS)
                    {
                        Log::Line(Log::WARN, "UbipalService::CheckAclsRecurse: ConfirmChecks failed: %s", GetErrorDescription(status));
                        return status;
                    }
                    return status;
                }
            }
            // else recurse
            else
            {
                // set up temporary recursion variables
                new_acl_trail = acl_trail;
                new_acl_trail.push_back(to_consider[i].referenced_from_acl);
                all_conditions.clear();
                all_conditions.insert(all_conditions.end(), conditions.begin(), conditions.end());
                all_conditions.insert(all_conditions.end(), to_consider[i].conditions.begin(), to_consider[i].conditions.end());

                // if it's a delegation with a variable service
                std::vector<std::string> delegators;
                std::vector<uint32_t> new_delegation_bounds;
                if (to_consider[i].service_id.size() == 1)
                {
                    // check if a condition applies, if it does, remove that condition and recurse on anything that meets the condition
                    std::vector<std::string> root_conds;
                    for (unsigned int k = 0; k < to_consider[i].conditions.size(); ++k)
                    {
                        if (to_consider[i].conditions[k].name1 == to_consider[i].service_id ||
                            to_consider[i].conditions[k].name2 == to_consider[i].service_id ||
                            to_consider[i].conditions[k].name3 == to_consider[i].service_id)
                        {
                            root_conds.push_back(to_consider[i].conditions[k].ToString());
                            to_consider[i].conditions.erase(to_consider[i].conditions.begin() + k);
                            --k;
                        }
                    }

                    // update all_conditions after removals
                    all_conditions.clear();
                    all_conditions.insert(all_conditions.end(), conditions.begin(), conditions.end());
                    all_conditions.insert(all_conditions.end(), to_consider[i].conditions.begin(), to_consider[i].conditions.end());


                    if (root_conds.size() != 0)
                    {
                        std::map<std::string, std::set<std::string>> potential_roots;
                        status = FindNamesForStatements(root_conds, potential_roots);
                        if ((status == SUCCESS || status == WAIT_ON_CONDITIONS) && potential_roots[to_consider[i].service_id].size() != 0)
                        {
                            for (std::set<std::string>::iterator set_itr = potential_roots[to_consider[i].service_id].begin(); set_itr != potential_roots[to_consider[i].service_id].end(); ++set_itr)
                            {
                                delegators.push_back(*set_itr);
                                new_delegation_bounds.push_back(to_consider[i].delegation_bound);
                            }
                        }
                        else
                        {
                            continue;
                        }

                    }
                    else
                    {
                        // else recurse on ALL possibilities
                        std::unordered_map<std::string, std::vector<AccessControlList>>::iterator acls_itr;
                        delegators.clear();
                        if (GetId() != current_service)
                        {
                            delegators.push_back(GetId());
                            new_delegation_bounds.push_back(to_consider[i].delegation_bound);
                        }
                        for (acls_itr = external_acls.begin(); acls_itr != external_acls.end(); ++acls_itr)
                        {
                            if (acls_itr->first != current_service)
                            {
                                delegators.push_back(acls_itr->first);
                                new_delegation_bounds.push_back(to_consider[i].delegation_bound);
                            }
                        }
                    }
                }
                else
                {
                    delegators.push_back(to_consider[i].service_id);
                    new_delegation_bounds.push_back(to_consider[i].delegation_bound);
                }

                for (unsigned int j = 0; j < delegators.size(); ++j)
                {
                    status = EvaluateStatementRecurse(statement, delegators[j], new_acl_trail, new_conditions, message, new_delegation_bounds[j] - 1);
                    if (status == SUCCESS)
                    {
                        acl_trail = new_acl_trail;
                        conditions = new_conditions;
                        return status;
                    }
                    else if (status != NOT_IN_ACLS && status != FAILED_CONDITIONS)
                    {
                        return status;
                    }
                }
            }
        }
        return NOT_IN_ACLS;
    }

    int UbipalService::ConfirmChecks(const Message& message, const std::vector<Statement>& conditions)
    {
        int status = SUCCESS;

        std::vector<NamespaceCertificate> services;
        status = GetNames(GetNamesFlags::INCLUDE_UNTRUSTED | GetNamesFlags::INCLUDE_TRUSTED, services);
        if (status != SUCCESS)
        {
            return status;
        }

        // create conditions object
        awaiting_conditions_mutex.lock();
        ConditionCheck new_cond_check;
        new_cond_check.message = message;
        new_cond_check.conditions = conditions;
        new_cond_check.time = GetTimeMilliseconds();
        awaiting_conditions.push_back(new_cond_check);
        awaiting_conditions_mutex.unlock();

        // check remote conditions
        bool found_service = false;
        for (unsigned int i = 0; i < conditions.size(); ++i)
        {
            found_service = false;
            for (unsigned int j = 0; j < services.size(); ++j)
            {
                if (services[j].id == conditions[i].name1)
                {
                    found_service = true;
                    status = SendMessage(0, &services[j], conditions[i].name2, NULL, 0, ConditionReplyCallback);
                    if (status != SUCCESS)
                    {
                        Log::Line(Log::WARN, "UbipalService::ConfirmChecks: SendMessage failed: %s", GetErrorDescription(status));
                        return status;
                    }
                    break;
                }
            }

            if (found_service == false)
            {
                Log::Line(Log::DEBUG, "UbipalService::ConfirmChecks: Failed to find a service.");
                return NOT_FOUND;
            }
        }

        return WAIT_ON_CONDITIONS;
    }

    int UbipalService::ConditionReplyCallback(UbipalService* us, const Message* original_message, const Message* reply_message)
    {
        int status = SUCCESS;
        if (us == nullptr || original_message == nullptr || reply_message == nullptr)
        {
            return NULL_ARG;
        }

        us->awaiting_conditions_mutex.lock();

        bool denied = false;
        for (unsigned int i = 0; i < us->awaiting_conditions.size(); ++i)
        {
            for (unsigned int j = 0; j < us->awaiting_conditions[i].conditions.size(); ++j)
            {
                if (reply_message->from == us->awaiting_conditions[i].conditions[j].name1)
                {
                    if (original_message->message == us->awaiting_conditions[i].conditions[j].name2)
                    {
                        if (reply_message->arg_len >= strlen("CONFIRM") && memcmp(reply_message->argument, "CONFIRM", strlen("CONFIRM")) == 0)
                        {
                            us->awaiting_conditions[i].conditions.erase(us->awaiting_conditions[i].conditions.begin() + j);
                            --j;
                            continue;
                        }
                        else
                        {
                            denied = true;
                            break;
                        }
                    }
                }
            }

            if (denied)
            {
                status = us->MessageConditionFailed(us->awaiting_conditions[i].message);
                if (status != SUCCESS)
                {
                    Log::Line(Log::WARN, "UbipalService::CondtionReplyCallback: MessageConditionsFailed failed: %s", GetErrorDescription(status));
                    status = SUCCESS;
                }
                us->awaiting_conditions.erase(us->awaiting_conditions.begin() + i);
                --i;
                denied = false;
                continue;
            }

            if (us->awaiting_conditions[i].conditions.size() == 0)
            {
                status = us->MessageConditionPassed(us->awaiting_conditions[i].message);
                if (status != SUCCESS)
                {
                    Log::Line(Log::WARN, "UbipalService::CondtionReplyCallback: MessageConditionsPassed failed: %s", GetErrorDescription(status));
                    status = SUCCESS;
                }
                us->awaiting_conditions.erase(us->awaiting_conditions.begin() + i);
                --i;
            }
        }

        us->awaiting_conditions_mutex.unlock();
        return status;
    }

    int UbipalService::MessageConditionPassed(const Message& message)
    {
        int status = SUCCESS;
        std::unordered_map<std::string, UbipalCallback>::iterator found;

        // if we've passed ACLs & conditions and we're requesting registration or deregistration, do so here
        if ((message.message.size() >= strlen("REGISTER_") && message.message.compare(0, strlen("REGISTER_"), "REGISTER_") == 0) ||
            (message.message.size() >= strlen("UNREGISTER_") && message.message.compare(0, strlen("UNREGISTER_"), "UNREGISTER_") == 0))
        {
            // register the message here, toss the rest
            registered_services_mutex.lock();

            size_t underscore = message.message.find("_");
            if (underscore == std::string::npos)
            {
                registered_services_mutex.unlock();
                return INVALID_SYNTAX;
            }

            std::string registration_message = message.message.substr(underscore + 1);

            if (message.message.size() >= strlen("REGISTER_") && message.message.compare(0, strlen("REGISTER_"), "REGISTER_") == 0)
            {
                registered_services[registration_message].insert(message.from);
                registered_services_mutex.unlock();

                // send initial update message
                NamespaceCertificate registered_service;
                status = GetCertificateForName(message.from, registered_service);
                if (status != SUCCESS)
                {
                    return status;
                }

                if (automatic_replies.count(message.message) != 0)
                {
                    std::tuple<unsigned char*, uint32_t> reply = automatic_replies[message.message];
                    status = SendMessage(0, &registered_service, "UPDATE_" + registration_message, std::get<0>(reply), std::get<1>(reply));
                }
                return status;
            }
            else // unregister
            {
                registered_services[registration_message].erase(message.from);

                if (registered_services[registration_message].size() == 0)
                {
                    registered_services.erase(registration_message);
                }
            }

            registered_services_mutex.unlock();
            return status;
        }

        // if we're caching this message, update the cache
        if (message.message.size() >= strlen("UPDATE_") && message.message.compare(0, strlen("UPDATE_"), "UPDATE_") == 0)
        {
            size_t underscore = message.message.find("_");
            if (underscore == std::string::npos)
            {
                return INVALID_SYNTAX;
            }
            std::string message_name = message.message.substr(underscore + 1);

            cached_messages_mutex.lock();
            if (cached_messages.count(message.from) != 0)
            {
                if (cached_messages[message.from].count(message_name) != 0)
                {
                    Message cache_message = message;
                    cache_message.message = message_name;
                    cached_messages[message.from][message_name] = cache_message;
                }
            }

            // then call the associated function
            UbipalReplyCallback callback = cached_callbacks[message.from][message_name];
            cached_messages_mutex.unlock();

            return callback(this, NULL, &message);
        }

        // if we have an automatic reply, send that back
        automatic_replies_mutex.lock();
        if (automatic_replies.count(message.message) != 0)
        {
            std::tuple<unsigned char*, uint32_t> reply_args = automatic_replies[message.message];
            status = ReplyToMessage(0, &message, std::get<0>(reply_args), std::get<1>(reply_args));
            if (status != SUCCESS)
            {
                automatic_replies_mutex.unlock();
                return status;
            }
            automatic_replies_mutex.unlock();
            return status;
        }
        automatic_replies_mutex.unlock();

        // find function to call
        found = callback_map.find(message.message);
        if (found == callback_map.end())
        {
            Log::Line(Log::WARN, "UbipalService::MessageConditionPassed: Does not have the appropriate callback.");
            return GENERAL_FAILURE;
        }

        status = found->second(this, message);
        if (status != SUCCESS)
        {
            Log::Line(Log::WARN, "UbipalService::MessageConditionPassed: Callback returned %d, %s", status, GetErrorDescription(status));
            return status;
        }
        return status;
    }

    int UbipalService::MessageConditionFailed(const Message& message)
    {
        int status = SUCCESS;

        // send failure
        // TODO only encrypt if replying to encrypted message?
        status = ReplyToMessage(0, &message, (const unsigned char*)"FAILED_CONDITIONS", strlen("FAILED_CONDITIONS") + 1);
        if (status != SUCCESS)
        {
            Log::Line(Log::WARN, "UbipalService::MessageConditionFailed: ReplyToMessage failed %s", GetErrorDescription(status));
            return status;
        }

        return status;
    }

    int UbipalService::MessageConditionTimeout(const Message& message)
    {
        int status = SUCCESS;

        // send failure
        // TODO only encrypt if replying to encrypted message?
        status = ReplyToMessage(0, &message, (const unsigned char*)"TIMEOUT_CONDITIONS", strlen("TIMEOUT_CONDITIONS") + 1);
        if (status != SUCCESS)
        {
            Log::Line(Log::WARN, "UbipalService::MessageConditionTimeout: ReplyToMessage failed %s", GetErrorDescription(status));
            return status;
        }

        return status;
    }

    int UbipalService::GetConditionsFromRule(const std::string& rule, std::vector<Statement>& conditions)
    {
        int status = SUCCESS;
        size_t begin = 0;
        size_t end = 0;
        Statement temp_statement;
        std::string temp_string;

        conditions.clear();

        begin = rule.find(" if ");
        if (begin == std::string::npos)
        {
            return status;
        }

        begin += strlen(" if ");
        std::string cond_string = rule.substr(begin);
        if (cond_string.size() == 0)
        {
            return status;
        }

        begin = 0;
        while (begin < cond_string.size())
        {
            end = cond_string.find(",", begin);
            temp_string = cond_string.substr(begin, end);
            status = ParseStatement(temp_string, temp_statement);
            if (status == SUCCESS)
            {
                conditions.push_back(temp_statement);
            }
            if (end == std::string::npos)
            {
                break;
            }
            begin = end + strlen(", ");
        }

        return status;
    }

    int UbipalService::CreateAcl(const uint32_t flags, const std::string& description, const std::vector<std::string>& rules, AccessControlList& result)
    {
        int status = SUCCESS;

        if ((flags & ~(CreateAclFlags::PRIVATE)) != 0)
        {
            return INVALID_ARG;
        }

        local_acls_mutex.lock();

        AccessControlList temp_acl;

        if ((flags & CreateAclFlags::PRIVATE) != 0)
        {
            temp_acl.is_private = true;
        }

        temp_acl.id = id;
        temp_acl.description = description;
        temp_acl.rules = rules;

        local_acls.push_back(temp_acl);
        result = temp_acl;

        local_acls_mutex.unlock();
        return status;
    }

    int UbipalService::CreateAcl(const uint32_t flags, const std::string& description, const std::string file, AccessControlList result)
    {
        int status = SUCCESS;

        if ((flags & ~(CreateAclFlags::PRIVATE)) != 0)
        {
            return INVALID_ARG;
        }

        // open file
        std::vector<std::string> rules;
        std::fstream rules_file;
        rules_file.open(file);
        if (rules_file.is_open() == false)
        {
            return OPEN_FILE_FAILED;
        }

        // read rules
        std::string one_rule;
        while (std::getline(rules_file, one_rule))
        {
            rules.push_back(one_rule);
        }

        // create file
        status = CreateAcl(flags, description, rules, result);

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
                local_acls_mutex.unlock();
                return SUCCESS;
            }
            if (search_id && (search_term == local_acls[i].msg_id))
            {
                acl = local_acls[i];
                local_acls_mutex.unlock();
                return SUCCESS;
            }
        }

        local_acls_mutex.unlock();
        return NOT_FOUND;
    }

    int UbipalService::RevokeAcl(const uint32_t flags, const AccessControlList& acl, const NamespaceCertificate* const send_to)
    {
        // check flags
        if ((flags & ~(RevokeAclFlags::NO_SENDING | RevokeAclFlags::NO_ENCRYPT)) != 0)
        {
            return INVALID_ARG;
        }

        // convert to bool for ease of use later
        bool no_sending = false;
        if ((flags & RevokeAclFlags::NO_SENDING) != 0)
        {
            no_sending = true;
        }

        local_acls_mutex.lock();
        int status = SUCCESS;

        for (unsigned int i = 0; i < local_acls.size(); ++i)
        {
            if (local_acls[i].msg_id == acl.msg_id)
            {
                local_acls.erase(local_acls.begin() + i);
                break;
            }
        }
        local_acls_mutex.unlock();

        if (no_sending == false)
        {
            uint32_t send_message_flags = 0;
            if ((flags & RevokeAclFlags::NO_ENCRYPT) != 0)
            {
                send_message_flags |= SendMessageFlags::NO_ENCRYPTION;
            }
            status = SendMessage(send_message_flags, send_to, std::string("REVOKE"), (unsigned char*)acl.msg_id.c_str(), acl.msg_id.size());
            if (status != SUCCESS)
            {
                Log::Line(Log::WARN, "UbipalService::RevokeAcl: Failed to SendMessage: %s", GetErrorDescription(status));
                return status;
            }
        }

        return status;
    }

    void* UbipalService::ConditionTimeout(void* arg)
    {
        if (arg == nullptr)
        {
            return NULL;
        }

        int status = SUCCESS;
        UbipalService* us = (UbipalService*)arg;
        uint32_t time = 0;
        uint32_t last_sent_name = 0;

        while(us->receiving)
        {
            sched_yield();
            usleep(us->condition_timeout_length * 1000);
            time = GetTimeMilliseconds();

            us->broadcast_name_mutex.lock();
            if (us->auto_broadcast_name == true && time - last_sent_name > us->broadcast_name_interval)
            {
                status = us->SendName(SendMessageFlags::NONBLOCKING | SendMessageFlags::NO_ENCRYPTION, NULL);
                if (status != SUCCESS)
                {
                    Log::Line(Log::INFO, "UbipalService::ConditionTimeout: UbipalService::SendName failed on interval: %s", GetErrorDescription(status));
                }

                last_sent_name = GetTimeMilliseconds();
            }
            us->broadcast_name_mutex.unlock();

            us->awaiting_conditions_mutex.lock();
            for (unsigned int i = 0; i < us->awaiting_conditions.size(); ++i)
            {
                if (us->awaiting_conditions[i].time + us->condition_timeout_length < time)
                {
                    // this message timed out
                    status = us->MessageConditionTimeout(us->awaiting_conditions[i].message);
                    if (status != SUCCESS)
                    {
                        Log::Line(Log::WARN, "UbipalService::ConditionTimeout: MessageConditionTimeout failed. %s", GetErrorDescription(status));
                        continue;
                    }

                    us->awaiting_conditions.erase(us->awaiting_conditions.begin() + i);
                    --i;
                }
            }
            us->awaiting_conditions_mutex.unlock();
        }

        return NULL;
    }

    uint32_t UbipalService::GetTimeMilliseconds()
    {
        struct timeval time;
        int returned_value = gettimeofday(&time, NULL);
        if (returned_value == -1)
        {
            return 0;
        }

        return (time.tv_sec * 1000) + (time.tv_usec / 1000);
    }

    int UbipalService::RequestCertificate(const uint32_t flags, const std::string& service_id, const NamespaceCertificate* to)
    {
        return SendMessage(flags, to, "REQUESTCERTIFICATE", (unsigned char*)service_id.c_str(), service_id.size(), HandleRequestCertificateReply);
    }

    int UbipalService::RequestAcl(const uint32_t flags, const std::string& acl_id, const NamespaceCertificate* to)
    {
        return SendMessage(flags, to, "REQUESTACL", (unsigned char*)acl_id.c_str(), acl_id.size(), HandleRequestAclReply);
    }

    int UbipalService::RequestAclsFromName(const uint32_t flags, const std::string& service_id, const NamespaceCertificate* to, const UbipalReplyCallback callback)
    {
        return SendMessage(flags, to, "REQUESTLISTACLS", (unsigned char*)service_id.c_str(), service_id.size(), callback);
    }

    int UbipalService::GetCertificateForName(const std::string& name, NamespaceCertificate& certificate)
    {
        int status = SUCCESS;

        std::vector<NamespaceCertificate> all_certificates;
        status = GetNames(GetNamesFlags::INCLUDE_TRUSTED | GetNamesFlags::INCLUDE_UNTRUSTED | GetNamesFlags::INCLUDE_SELF, all_certificates);
        if (status != SUCCESS)
        {
            return status;
        }

        for (unsigned int i = 0; i < all_certificates.size(); ++i)
        {
            if (all_certificates[i].id == name)
            {
                certificate = all_certificates[i];
                return SUCCESS;
            }
        }

        return NOT_FOUND;
    }

    int UbipalService::FindNamesForStatements(const std::string& statement, std::map<std::string, std::set<std::string>>& names)
    {
        std::vector<std::string> statements_vector;
        statements_vector.push_back(statement);
        return FindNamesForStatements(statements_vector, names);
    }

    int UbipalService::FindNamesForStatements(const std::vector<std::string>& statements, std::map<std::string, std::set<std::string>>& names)
    {
        int status = SUCCESS;
        std::vector<Statement> parsed_statements;
        Statement parsed;
        for (unsigned int i = 0; i < statements.size(); ++i)
        {
            status = ParseStatement(statements[i], parsed);
            if (status != SUCCESS)
            {
                continue;
            }
            parsed_statements.push_back(parsed);
        }

        status = FindNamesForStatements(parsed_statements, names);
        return status;
    }

    int UbipalService::FindNamesForStatements(const std::vector<Statement>& statements, std::map<std::string, std::set<std::string>>& names)
    {
        int status = SUCCESS;

        // create a set for each variable name
        std::map<std::string, std::set<std::string>> possible_answers;

        // organize each
        std::map<std::string, std::set<Statement>> grouped_statements;

        // group statements by which variables they reference
        for (unsigned int i = 0; i < statements.size(); ++i)
        {
            if (statements[i].type == Statement::Type::CURRENT_TIME || statements[i].type == Statement::Type::CURRENT_DATE ||
                statements[i].type == Statement::Type::CONFIRMS || statements[i].type == Statement::Type::INVALID)
            {
                continue;
            }

            // for each variable, add it to the appropriate
            for (const Statement* itr = &statements[i]; itr != nullptr; itr = itr->statement)
            {
                if (itr->root.size() == 1)
                {
                    grouped_statements[itr->root].insert(statements[i]);
                }
                if (itr->name1.size() == 1)
                {
                    grouped_statements[itr->name1].insert(statements[i]);
                }
                if (itr->name2.size() == 1)
                {
                    grouped_statements[itr->name2].insert(statements[i]);
                }
                if (itr->name3.size() == 1)
                {
                    grouped_statements[itr->name3].insert(statements[i]);
                }
            }
        }

        // get all names we've heard of
        std::vector<NamespaceCertificate> all_certificates;
        status = GetNames(GetNamesFlags::INCLUDE_TRUSTED | GetNamesFlags::INCLUDE_UNTRUSTED | GetNamesFlags::INCLUDE_SELF, all_certificates);
        if (status != SUCCESS)
        {
            Log::Line(Log::WARN, "UbipalService::FindNamesForStatements: GetNames failed: %d", GetErrorDescription(status));
            return status;
        }

        // add all names from certificates
        std::set<std::string> all_names;
        for (unsigned int i = 0; i < all_certificates.size(); ++i)
        {
            all_names.insert(all_certificates[i].id);
        }

        // add all names from rules
        std::unordered_map<std::string, std::vector<AccessControlList>>::iterator acls_itr;
        for (acls_itr = external_acls.begin(); acls_itr != external_acls.end(); ++acls_itr)
        {
            all_names.insert(acls_itr->first);
        }

        std::set<std::string> successful_names;
        for (std::map<std::string, std::set<Statement>>::iterator itr = grouped_statements.begin(); itr != grouped_statements.end(); ++itr)
        {
            for (std::set<Statement>::iterator stmnts = itr->second.begin(); stmnts != itr->second.end(); ++stmnts)
            {
                successful_names.clear();
                for (std::set<std::string>::iterator names_itr = all_names.begin(); names_itr != all_names.end(); ++names_itr)
                {
                    Statement temp_statement = *stmnts;
                    for (Statement* statement_itr = &temp_statement; statement_itr != nullptr; statement_itr = statement_itr->statement)
                    {
                        // for each field, if it equals the variable in this set, replace it with the certificate id, else leave it
                        // if we're sending to a variable, we care about the permissions at the receiver, so fix the root
                        if (statement_itr->root == itr->first ||
                            (statement_itr->type == Statement::Type::CAN_SEND_MESSAGE && statement_itr->name3 == itr->first))
                        {
                            statement_itr->root = *names_itr;
                        }
                        statement_itr->name1 = (statement_itr->name1 == itr->first) ? *names_itr : statement_itr->name1;
                        statement_itr->name2 = (statement_itr->name2 == itr->first) ? *names_itr : statement_itr->name2;
                        statement_itr->name3 = (statement_itr->name3 == itr->first) ? *names_itr : statement_itr->name3;

                    }

                    // replacements are done, try to evaluate
                    std::vector<std::string> acl_trail;
                    std::vector<Statement> conditions;
                    status = EvaluateStatementRecurse(temp_statement, temp_statement.root, acl_trail, conditions, NULL, std::numeric_limits<uint32_t>::max());
                    if (status == SUCCESS)
                    {
                        successful_names.insert(*names_itr);
                    }
                }

                // if it's the first round, copy the set
                if (stmnts == itr->second.begin())
                {
                    possible_answers[itr->first] = successful_names;
                }
                else
                {
                    // else, remove any name not in succesful_names
                    std::set<std::string> new_possible_answers;
                    for (std::set<std::string>::iterator add_itr = possible_answers[itr->first].begin(); add_itr != possible_answers[itr->first].end(); ++add_itr)
                    {
                        if (successful_names.count(*add_itr) == 1)
                        {
                            new_possible_answers.insert(*add_itr);
                        }
                    }

                    possible_answers[itr->first] = new_possible_answers;
                }
                if (possible_answers[itr->first].size() == 0)
                {
                    return NOT_IN_ACLS;
                }
            }
        }

        names = possible_answers;
        return SUCCESS;
    }

    std::string UbipalService::UpperCase(const std::string& str)
    {
        std::locale loc;
        std::string upper;
        for (unsigned int i = 0; i < str.size(); ++i)
        {
            upper += std::toupper(str[i], loc);
        }

        return upper;
    }

    int UbipalService::RegisterForUpdates(const uint32_t flags, const NamespaceCertificate& service, const std::string& message, const UbipalReplyCallback callback)
    {
        int status = SUCCESS;

        // Add ACL rules that allow this message through
        // find the old ACL
        // (failure doesn't matter here, since they might not exist to begin with)
        AccessControlList old_acl;
        status = GetAcl(GetAclFlags::SEARCH_BY_DESC, REGISTRATION_ACL, old_acl);

        // revoke the old ACL
        status = RevokeAcl(RevokeAclFlags::NO_SENDING, old_acl, NULL);

        // add the appropriate rule
        std::vector<std::string> new_rules = old_acl.rules;
        new_rules.push_back(service.id + " CAN SEND MESSAGE UPDATE_" + message + " TO " + GetId());

        // create ACL based on new rules
        AccessControlList new_acl;
        status = CreateAcl(CreateAclFlags::PRIVATE, REGISTRATION_ACL, new_rules, new_acl);
        if (status != SUCCESS)
        {
            return status;
        }

        // register cache & callback
        cached_messages_mutex.lock();
        Message blank;
        cached_messages[service.id][message] = blank;
        cached_callbacks[service.id][message] = callback;
        cached_messages_mutex.unlock();

        // send registration message
        status = SendMessage(flags, &service, "REGISTER_" + message, NULL, 0);

        return status;
    }

    int UbipalService::UnregisterForUpdates(const uint32_t flags, const NamespaceCertificate& service, const std::string& message)
    {
        int status = SUCCESS;

        // First, let's remove the old ACL rules that allow this message through
        // find the old ACL
        AccessControlList old_acl;
        status = GetAcl(GetAclFlags::SEARCH_BY_DESC, REGISTRATION_ACL, old_acl);
        if (status != SUCCESS)
        {
            return status;
        }

        // revoke the old ACL
        status = RevokeAcl(RevokeAclFlags::NO_SENDING, old_acl, NULL);
        if (status != SUCCESS)
        {
            return status;
        }

        // copy any rules that were not associated with the unregistered message
        std::vector<std::string> new_rules;
        for (unsigned int i = 0; i < old_acl.rules.size(); ++i)
        {
            if (old_acl.rules[i].find(service.id) == std::string::npos || old_acl.rules[i].find(message) == std::string::npos)
            {
                new_rules.push_back(old_acl.rules[i]);
            }
        }

        // create new ACL on those other rules
        if (new_rules.size() != 0)
        {
            AccessControlList new_acl;
            status = CreateAcl(CreateAclFlags::PRIVATE, REGISTRATION_ACL, new_rules, new_acl);
            if (status != SUCCESS)
            {
                return status;
            }
        }

        // remove our cache and send unregister to service
        cached_messages_mutex.lock();

        cached_messages[service.id].erase(message);

        if (cached_messages.count(service.id) == 0)
        {
            cached_messages.erase(service.id);
        }

        cached_callbacks[service.id].erase(message);
        if (cached_callbacks.count(service.id) == 0)
        {
            cached_callbacks.erase(service.id);
        }

        cached_messages_mutex.unlock();

        status = SendMessage(flags, &service, "UNREGISTER_" + message, NULL, 0);

        return status;
    }

    int UbipalService::SetMessageReply(const uint32_t flags, const std::string& message, const unsigned char* const arg, const uint32_t arg_len)
    {
        int status = SUCCESS;
        automatic_replies_mutex.lock();

        // check old message
        if (automatic_replies.count(message) != 0)
        {
            if (std::get<1>(automatic_replies[message]) == arg_len && memcmp(std::get<0>(automatic_replies[message]), arg, arg_len) == 0)
            {
                // message is the same, no need to do anything further
                automatic_replies_mutex.unlock();
                return status;
            }
        }

        // if we get here, the message is either new or has a new argument value
        unsigned char* copy_pointer = nullptr;
        copy_pointer = (unsigned char*)malloc(arg_len);
        if (copy_pointer == nullptr)
        {
            automatic_replies_mutex.unlock();
            return MALLOC_FAILURE;
        }

        memcpy(copy_pointer, arg, arg_len);
        std::tuple<unsigned char*, uint32_t> tup(copy_pointer, arg_len);
        automatic_replies[message] = tup;

        // send updates
        registered_services_mutex.lock();
        if (registered_services.count(message) != 0)
        {
            for (std::set<std::string>::iterator itr = registered_services[message].begin(); itr != registered_services[message].end(); ++itr)
            {
                status = EvaluateStatement(*itr + " CAN SEND MESSAGE REGISTER_" + message + " TO " + GetId());
                if (status != SUCCESS)
                {
                    continue;
                }

                NamespaceCertificate cert;
                status = GetCertificateForName(*itr, cert);
                if (status != SUCCESS)
                {
                    Log::Line(Log::INFO, "UbipalService::SetMessageReply: UbipalService::GetCertificateForName failed to find a certificate for %s with error %s",
                              itr->c_str(), GetErrorDescription(status));
                    continue;
                }

                status = SendMessage(flags, &cert, "UPDATE_" + message, arg, arg_len);
                if (status != SUCCESS)
                {
                    Log::Line(Log::INFO, "UbipalService::SetMessageReply: UbipalService::SendMessage failed for %s: %s",
                              itr->c_str(), GetErrorDescription(status));
                }
            }
        }
        registered_services_mutex.unlock();

        automatic_replies_mutex.unlock();
        return status;
    }

    int UbipalService::RemoveMessageReply(const std::string& message)
    {
        int status = SUCCESS;

        automatic_replies_mutex.lock();

        automatic_replies.erase(message);

        automatic_replies_mutex.unlock();

        return status;
    }

    int UbipalService::SetNameBroadcast(const bool on, const uint32_t ms)
    {
        int status = SUCCESS;
        broadcast_name_mutex.lock();

        auto_broadcast_name = on;
        broadcast_name_interval = ms;

        broadcast_name_mutex.unlock();
        return status;
    }

    int UbipalService::HandleRequestCertificateReply(UbipalService* us, const Message* original_message, const Message* reply_message)
    {
        int status = SUCCESS;
        int returned_value = 0;

        // check arguments
        if (us == nullptr || reply_message == nullptr)
        {
            return NULL_ARG;
        }
        else if (reply_message->argument == nullptr || reply_message->arg_len == 0)
        {
            return NOT_FOUND;
        }
        else if (reply_message->arg_len == strlen("NOT_FOUND") && memcmp(reply_message->argument, "NOT_FOUND", strlen("NOT_FOUND")) == 0)
        {
            return NOT_FOUND;
        }

        // decode NamespaceCertificate
        NamespaceCertificate received_cert;
        returned_value = received_cert.Decode(reply_message->argument, reply_message->arg_len);
        if (returned_value < SUCCESS)
        {
            return returned_value;
        }

        RSA* pkey = nullptr;
        status = RsaWrappers::StringToPublicKey(received_cert.id, pkey);
        if (status != SUCCESS)
        {
            return status;
        }

        returned_value = RsaWrappers::VerifySignedDigest(pkey, reply_message->argument, returned_value, reply_message->argument + returned_value, reply_message->arg_len - returned_value);
        if (returned_value != 1)
        {
            return (returned_value == SUCCESS) ? GENERAL_FAILURE : returned_value;
        }

        // call RecvNamespaceCertificate to handle the rest
        status = us->RecvNamespaceCertificate(&received_cert);
        return status;
    }

    int UbipalService::HandleRequestAclReply(UbipalService* us, const Message* original_message, const Message* reply_message)
    {
        int status = SUCCESS;
        int returned_value = 0;

        // check arguments
        if (us == nullptr || reply_message == nullptr)
        {
            return NULL_ARG;
        }
        else if (reply_message->argument == nullptr || reply_message->arg_len == 0)
        {
            return NOT_FOUND;
        }
        else if (reply_message->arg_len == strlen("NOT_FOUND") && memcmp(reply_message->argument, "NOT_FOUND", strlen("NOT_FOUND")) == 0)
        {
            return NOT_FOUND;
        }

        // decode ACL
        AccessControlList received_acl;
        returned_value = received_acl.Decode(reply_message->argument, reply_message->arg_len);
        if (returned_value < SUCCESS)
        {
            return returned_value;
        }

        RSA* pkey = nullptr;
        status = RsaWrappers::StringToPublicKey(received_acl.id, pkey);
        if (status != SUCCESS)
        {
            return status;
        }

        returned_value = RsaWrappers::VerifySignedDigest(pkey, reply_message->argument, returned_value, reply_message->argument + returned_value, reply_message->arg_len - returned_value);
        if (returned_value != 1)
        {
            return (returned_value == SUCCESS) ? GENERAL_FAILURE : returned_value;
        }

        // call RecvNamespaceCertificate to handle the rest
        status = us->RecvAcl(&received_acl);
        return status;
    }

    int UbipalService::GetAclsForName(const std::string& name, std::vector<AccessControlList>& acls)
    {
        int status = SUCCESS;

        // if asking for our own acls, simply return local_acls
        if (name == GetId())
        {
            local_acls_mutex.lock();
            acls = local_acls;
            local_acls_mutex.unlock();
            return status;
        }

        // else search external_acls
        external_acls_mutex.lock();
        if (external_acls.count(name) == 1)
        {
            acls = external_acls[name];
        }
        else
        {
            status = NOT_FOUND;
        }
        external_acls_mutex.unlock();

        return status;
    }
}
