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

        condition_timeout_length = 500;

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

        #ifdef EVALUATE
            // last thing before quitting, put out our stats
            Log::Line(Log::INFO, "Quitting. Messages sent: %lu, messages received: %lu\nRSA Encrypts: %lu (%f secs), RSA Decrypts: %lu (%f secs), RSA Signs: %lu (%f secs), RSA Verifies: %lu (%f secs)",
                      NUM_MESSAGES_SENT, NUM_MESSAGES_RECV, NUM_RSA_ENCRYPTS, TIME_RSA_ENCRYPTS, NUM_RSA_DECRYPTS, TIME_RSA_DECRYPTS, NUM_RSA_SIGNS, TIME_RSA_SIGNS, NUM_RSA_VERIFIES, TIME_RSA_VERIFIES);
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
        int returned_value = 0;
        receiving_mutex.lock();
            receiving = false;
        receiving_mutex.unlock();

        for (unsigned int i = 0; i < recv_threads.size(); ++i)
        {
            returned_value = pthread_join(recv_threads[i], NULL);
            if (returned_value != 0)
            {
                Log::Line(Log::WARN, "UbipalService::EndRecv(): pthread_join returned %d for recv_threads[%d]", returned_value, i);
            }
        }

        for (unsigned int i = 0; i < send_threads.size(); ++i)
        {
            returned_value = pthread_join(send_threads[i], NULL);
            if (returned_value != 0)
            {
                Log::Line(Log::WARN, "UbipalService::EndRecv(): pthread_join returned %d for send_threads[%d]", returned_value, i);
            }
        }

        returned_value = pthread_join(conditions_timeout_thread, NULL);
        if (returned_value != 0)
        {
            Log::Line(Log::WARN, "UbipalService::EndRecv(): pthread_join returned %d for conditions_timeout_thread", returned_value);
        }

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
                us->incoming_msg_cv.wait(lock);
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

        // The first byte is the type, the next 4 are the size of the to field
        returned_value = BaseMessage::DecodeUint32_t(incoming_data->buffer + 1, incoming_data->buffer_len, to_len);
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
            if (to_len != id.size() || memcmp(incoming_data->buffer + 5, id.c_str(), id.size()) != 0)
            {
                // decrypt
                status = RsaWrappers::Decrypt(private_key, incoming_data->buffer, incoming_data->buffer_len, buf_decrypted, &buf_decrypted_len);
                if (status != SUCCESS)
                {
                    Log::Line(Log::WARN, "UbipalService::HandleMessage: RsaWrapers::Decrypt failed: %s", GetErrorDescription(status));
                    RETURN_STATUS(status);
                }

                // If they still don't match, toss the message because it isn't to us
                if (memcmp(buf_decrypted + 5, id.c_str(), id.size()) != 0)
                {
                    Log::Line(Log::WARN, "UbipalService::HandleMessage: Message couldn't be interpreted, so it's tossed.");
                    RETURN_STATUS(INVALID_NETWORK_ENCODING);
                }

                // so we decrypted and it matched, put buf_decrypted in buf
                free(incoming_data->buffer);
                incoming_data->buffer = buf_decrypted;
                buf_decrypted = nullptr;
                incoming_data->buffer_len = buf_decrypted_len;
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
                    Log::Line(Log::WARN, "UbipalService::HandleMessage: RecvNamespaceCertificate failed: %s", GetErrorDescription(status));
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
        std::unordered_map<std::string, std::vector<AccessControlList>>::iterator acl_itr;
        std::vector<AccessControlList> acl_vector;

        if (acl == nullptr)
        {
            Log::Line(Log::DEBUG, "UbipalService::RecvAcl: Null arg");
            return NULL_ARG;
        }

        // find all the acls from this service
        external_acls_mutex.lock();
        acl_itr = external_acls.find(acl->id);
        if (acl_itr == external_acls.end())
        {
            // wasnt found, so add it
            acl_vector.push_back(*acl);
            external_acls.emplace(acl->id, acl_vector);
        }
        else
        {
            // was found, so check through the associated vector to see if this is an update (based on ID)
            for (unsigned int i = 0; i < acl_itr->second.size(); ++i)
            {
                if (acl_itr->second[i].msg_id.compare(acl->msg_id))
                {
                    // we've already heard this one, so we're done.
                    external_acls_mutex.unlock();
                    return SUCCESS;
                }
            }

            // if we get here, we haven't heard it, so we're adding it
            acl_itr->second.push_back(*acl);
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
                // it is, so update it
                itr->second = *name_cert;
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
                // it is, so update it
                itr->second = *name_cert;
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

                returned_value = reply_callback_map.erase(replying_id);
                if (returned_value != 1)
                {
                    Log::Line(Log::EMERG, "UbipalService::RecvMessage: reply_callback_map.erase() failed to remove the mapping.");
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
                        delete msgs_awaiting_reply[i];
                        msgs_awaiting_reply.erase(msgs_awaiting_reply.begin() + i);
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

        if (message->message.compare(0, strlen("CACHECONDITION_"), "CACHECONDITION_") == 0)
        {
            cached_conditions_mutex.lock();

            // get condition
            size_t underscore = message->message.find("_");
            std::string condition = message->message.substr(underscore + 1);

            // copy the reply
            unsigned char* reply = (unsigned char*)malloc(message->arg_len);
            if (reply == nullptr)
            {
                cached_conditions_mutex.unlock();
                return MALLOC_FAILURE;
            }
            memcpy(reply, message->argument, message->arg_len);

            // add to cache
            cached_conditions[message->from][condition] = std::tuple<unsigned char*, uint32_t>(reply, message->arg_len);

            cached_conditions_mutex.unlock();
            return status;
        }

        if (message->message.compare(0, strlen("REMOVECACHECONDITION_"), "REMOVECACHECONDITION_") == 0)
        {
            cached_conditions_mutex.lock();

            // get condition
            size_t underscore = message->message.find("_");
            std::string condition = message->message.substr(underscore + 1);

            // remove from the mapped map
            cached_conditions[message->from].erase(condition);

            // remove the entry for that service, if there are no more conditions
            if (cached_conditions[message->from].size() == 0)
            {
                cached_conditions.erase(message->from);
            }

            cached_conditions_mutex.unlock();
            return status;
        }

        if (message->message.compare(0, strlen("REQUESTCERTIFICATE"), "REQUESTCERTIFICATE") == 0)
        {
            // TODO fill this in
        }

        if (message->message.compare(0, strlen("REQUESTACL"), "REQUESTACL") == 0)
        {
            // TODO fill this in
            // think about privacy infringement if this is always replied to
            return NOT_IMPLEMENTED;
        }

        // check against ACLs
        status = EvaluateStatement(message->from + " CAN SEND MESSAGE " + message->message + " TO " + id, message);
        if (status == NOT_IN_ACLS)
        {
            ReplyToMessage(SendMessageFlags::NO_ENCRYPTION, message, (const unsigned char*)"NOT_IN_ACLS", strlen("NOT_IN_ACLS") + 1);
            Log::Line(Log::INFO, "UbipalService::RecvMessage: UbipalService::CheckAcls returned %s for message %s from %s",
                      GetErrorDescription(status), message->message.c_str(), message->from.c_str());
            return status;
        }
        else if (status == FAILED_CONDITIONS)
        {
            ReplyToMessage(SendMessageFlags::NO_ENCRYPTION, message, (const unsigned char*)"FAILED_CONDITIONS", strlen("FAILED_CONDITIONS") + 1);
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
        if ((flags & ~(GetNamesFlags::INCLUDE_UNTRUSTED | GetNamesFlags::INCLUDE_TRUSTED)) != 0)
        {
            Log::Line(Log::WARN, "UbipalService::GetNames: passed invalid flag");
            return INVALID_ARG;
        }

        // empty vector
        names.clear();

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

        status = EvaluateStatementRecurse(statement_struct, statement_struct.root, acl_trail, conditions, message);
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
        statement_struct.type = INVALID;
        statement_struct.name1 = std::string();
        statement_struct.name2 = std::string();
        statement_struct.name3 = std::string();
        statement_struct.comparison = std::string();
        statement_struct.num1 = 0;
        statement_struct.num2 = 0;
        statement_struct.statement = nullptr;

        // parse type of statement
        if (statement.find(" CAN SAY ") != std::string::npos)
        {
            statement_struct.type = CAN_SAY;
            size_t connective = statement.find(" CAN SAY ");
            size_t connective_end = connective + strlen(" CAN SAY ");
            statement_struct.statement = new Statement; // TODO this is a memory leak
            if (statement_struct.statement == nullptr)
            {
                RETURN_STATUS(MALLOC_FAILURE);
            }
            size_t start = statement.rfind(" ", connective - 1);

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
            statement_struct.type = CAN_SEND_MESSAGE;

            // find connective
            size_t connective = statement.find(" CAN SEND MESSAGE ");
            size_t connective_end = connective + strlen(" CAN SEND MESSAGE ");

            // find sending service
            size_t start = statement.rfind(" ", connective - 1);
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
            statement_struct.type = IS_A;

            size_t connective = statement.find(" IS A ");
            size_t connective_end = connective + strlen(" IS A ");

            // first name
            size_t start = statement.rfind(" ", connective - 1);
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
            statement_struct.type = IS;

            size_t connective = statement.find(" IS ");
            size_t connective_end = connective + strlen(" IS ");

            // find name
            size_t start = statement.rfind(" ", connective - 1);
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
            statement_struct.type = CONFIRMS;

            size_t connective = statement.find(" CONFIRMS ");
            size_t connective_end = connective + strlen(" CONFIRMS ");

            // find name
            size_t start = statement.rfind(" ", connective - 1);
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
            statement_struct.type = CURRENT_TIME;
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
            statement_struct.type = CURRENT_DATE;
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
            size_t end = statement.find(" SAYS ");
            if (end != std::string::npos)
            {
                statement_struct.root = statement.substr(0, end);
            }
            else
            {
                statement_struct.root = id;
            }
        }

        exit:
            return status;
    }

    int UbipalService::EvaluateStatementRecurse(const Statement& statement, const std::string& current_service, std::vector<std::string>& acl_trail, std::vector<Statement>& conditions, const Message* message)
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
        if (statement.type == CURRENT_TIME)
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
        else if (statement.type == CURRENT_DATE)
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
        else if (statement.type == CONFIRMS)
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
                    if (parsed_rule.type != CAN_SAY || parsed_rule.statement == nullptr || parsed_rule.statement->type != statement.type)
                    {
                        continue;
                    }
                }

                // check for any mismathes
                if ((statement.name1 != parsed_rule.name1) && (parsed_rule.statement == nullptr || parsed_rule.statement->name1 != statement.name1))
                {
                    // all variables are length 1
                    if ((parsed_rule.name1.size() != 1 && parsed_rule.type != CAN_SAY)
                         || (parsed_rule.type == CAN_SAY && parsed_rule.statement != nullptr && parsed_rule.statement->name1.size() != 1))
                    {
                        continue;
                    }

                    // do any necessary replacement in the conditions
                    for (unsigned int i = 0; i < rule_conditions.size(); ++i)
                    {
                        if (rule_conditions[i].name1 == parsed_rule.name1
                            || (parsed_rule.statement != nullptr && parsed_rule.statement->name1 == rule_conditions[i].name1))
                        {
                            rule_conditions[i].name1 = statement.name1;
                        }
                        if (rule_conditions[i].name2 == parsed_rule.name1
                            || (parsed_rule.statement != nullptr && parsed_rule.statement->name1 == rule_conditions[i].name2))
                        {
                            rule_conditions[i].name2 = statement.name1;
                        }
                        if (rule_conditions[i].name3 == parsed_rule.name1
                            || (parsed_rule.statement != nullptr && parsed_rule.statement->name1 == rule_conditions[i].name3))
                        {
                            rule_conditions[i].name3 = statement.name1;
                        }
                    }
                }
                if ((statement.name2 != parsed_rule.name2) && (parsed_rule.statement == nullptr || parsed_rule.statement->name2 != statement.name2))
                {
                    // all variables are length 1
                    if ((parsed_rule.name2.size() != 1 && parsed_rule.type != CAN_SAY)
                         || (parsed_rule.type == CAN_SAY && parsed_rule.statement != nullptr && parsed_rule.statement->name2.size() != 1))
                    {
                        continue;
                    }

                    // do any necessary replacement in the conditions
                    for (unsigned int i = 0; i < rule_conditions.size(); ++i)
                    {
                        if (rule_conditions[i].name1 == parsed_rule.name2
                            || (parsed_rule.statement != nullptr && parsed_rule.statement->name2 == rule_conditions[i].name1))
                        {
                            rule_conditions[i].name1 = statement.name2;
                        }
                        if (rule_conditions[i].name2 == parsed_rule.name2
                            || (parsed_rule.statement != nullptr && parsed_rule.statement->name2 == rule_conditions[i].name2))
                        {
                            rule_conditions[i].name2 = statement.name2;
                        }
                        if (rule_conditions[i].name3 == parsed_rule.name2
                            || (parsed_rule.statement != nullptr && parsed_rule.statement->name2 == rule_conditions[i].name3))
                        {
                            rule_conditions[i].name3 = statement.name2;
                        }
                    }
                }
                if ((statement.name3 != parsed_rule.name3) && (parsed_rule.statement == nullptr || parsed_rule.statement->name3 != statement.name3))
                {
                    // all variables are length 1
                    if ((parsed_rule.name3.size() != 1 && parsed_rule.type != CAN_SAY)
                         || (parsed_rule.type == CAN_SAY && parsed_rule.statement != nullptr && parsed_rule.statement->name3.size() != 1))
                    {
                        continue;
                    }

                    // do any necessary replacement in the conditions
                    for (unsigned int i = 0; i < rule_conditions.size(); ++i)
                    {
                        if (rule_conditions[i].name1 == parsed_rule.name3
                            || (parsed_rule.statement != nullptr && parsed_rule.statement->name3 == rule_conditions[i].name1))
                        {
                            rule_conditions[i].name1 = statement.name3;
                        }
                        if (rule_conditions[i].name2 == parsed_rule.name3
                            || (parsed_rule.statement != nullptr && parsed_rule.statement->name3 == rule_conditions[i].name2))
                        {
                            rule_conditions[i].name2 = statement.name3;
                        }
                        if (rule_conditions[i].name3 == parsed_rule.name3
                            || (parsed_rule.statement != nullptr && parsed_rule.statement->name3 == rule_conditions[i].name3))
                        {
                            rule_conditions[i].name3 = statement.name3;
                        }
                    }
                }

                if (parsed_rule.type == CAN_SAY)
                {
                    temp_consider.service_id = parsed_rule.name1;
                }
                else
                {
                    temp_consider.service_id = current_service;
                }
                temp_consider.referenced_from_acl = current_acls[i].msg_id;
                temp_consider.conditions = rule_conditions;

                if (parsed_rule.type == CAN_SAY)
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
            // if to_consider[i].id is current, then just check conditions
            if (to_consider[i].service_id == current_service)
            {
                all_conditions.insert(all_conditions.end(), conditions.begin(), conditions.end());
                all_conditions.insert(all_conditions.end(), to_consider[i].conditions.begin(), to_consider[i].conditions.end());

                // Remove any non-confirms conditions
                bool did_fail_conds = false;
                for (unsigned int j = 0; j < all_conditions.size(); ++j)
                {
                    if (all_conditions[j].type != CONFIRMS)
                    {
                        std::vector<std::string> cond_acl_trail;
                        std::vector<Statement> cond_conds;
                        status = EvaluateStatementRecurse(all_conditions[j], current_service, cond_acl_trail, cond_conds, NULL);
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
                new_conditions = conditions;
                for (unsigned int j = 0; j < to_consider[i].conditions.size(); ++j)
                {
                    new_conditions.push_back(to_consider[i].conditions[j]);
                }

                status = EvaluateStatementRecurse(statement, to_consider[i].service_id, new_acl_trail, new_conditions, message);
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
        return status;
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

        std::vector<Statement> remote_conditions;

        // Handle any local conditions first
        cached_conditions_mutex.lock();
        for (unsigned int i = 0; i < conditions.size(); ++i)
        {
            // if we have an entry for the confirming service AND we have an entry for the condition
            if (cached_conditions.count(conditions[i].name1) == 1 && cached_conditions[conditions[i].name1].count(conditions[i].name2) == 1)
            {
                // get the answer
                std::tuple<unsigned char*, uint32_t> cond_reply = cached_conditions[conditions[i].name1][conditions[i].name2];
                if (std::get<0>(cond_reply) != nullptr)
                {
                    if (std::get<1>(cond_reply) >= strlen("CONFIRM") && memcmp(std::get<0>(cond_reply), "CONFIRM", strlen("CONFIRM")) == 0)
                    {
                        // confirmed, we don't need to send a message about it
                        cached_conditions_mutex.unlock();
                        continue;
                    }
                    else
                    {
                        // something other than confirmed, conditions failed!
                        cached_conditions_mutex.unlock();
                        return FAILED_CONDITIONS;
                    }
                }
            }
            else
            {
                // if we haven't cached it, we'll have to check it with the source
                remote_conditions.push_back(conditions[i]);
            }
        }
        cached_conditions_mutex.unlock();

        // if there are no more conditions, we're done!
        if (remote_conditions.size() == 0)
        {
            return SUCCESS;
        }

        // create conditions object
        awaiting_conditions_mutex.lock();
        ConditionCheck new_cond_check;
        new_cond_check.message = message;
        new_cond_check.conditions = remote_conditions;
        new_cond_check.time = GetTimeMilliseconds();
        awaiting_conditions.push_back(new_cond_check);
        awaiting_conditions_mutex.unlock();

        // check remote conditions
        bool found_service = false;
        for (unsigned int i = 0; i < remote_conditions.size(); ++i)
        {
            found_service = false;
            for (unsigned int j = 0; j < services.size(); ++j)
            {
                if (services[j].id == remote_conditions[i].name1)
                {
                    found_service = true;
                    status = SendMessage(SendMessageFlags::NO_ENCRYPTION, &services[j], remote_conditions[i].name2, NULL, 0, ConditionReplyCallback);
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
        status = ReplyToMessage(SendMessageFlags::NO_ENCRYPTION, &message, (const unsigned char*)"FAILED_CONDITIONS", strlen("FAILED_CONDITIONS") + 1);
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
        status = ReplyToMessage(SendMessageFlags::NO_ENCRYPTION, &message, (const unsigned char*)"TIMEOUT_CONDITIONS", strlen("TIMEOUT_CONDITIONS") + 1);
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

        while(us->receiving)
        {
            sched_yield();
            usleep(us->condition_timeout_length * 1000);
            time = GetTimeMilliseconds();

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


    int UbipalService::CacheCondition(const uint32_t flags, const NamespaceCertificate* to, const std::string condition,
                                      const unsigned char* const reply, const uint32_t reply_len)
    {
        return SendMessage(flags, to, "CACHECONDITION_" + condition, reply, reply_len);
    }

    int UbipalService::InvalidateCachedCondition(const uint32_t flags, const NamespaceCertificate* to, const std::string condition)
    {
        return SendMessage(flags, to, "REMOVECACHECONDITION_" + condition, NULL, 0);
    }

    int UbipalService::RequestCertificate(const uint32_t flags, const std::string service_id, const NamespaceCertificate* to)
    {
        // TODO add a callback to handle adding the returned certificate
        return SendMessage(flags, to, "REQUESTCERTIFICATE", (unsigned char*)service_id.c_str(), service_id.size());
    }

    int UbipalService::RequestAcl(const uint32_t flags, const std::string service_id, const NamespaceCertificate* to)
    {
        // TODO add a callback to handle adding the returned ACL
        return SendMessage(flags, to, "REQUESTACL", (unsigned char*)service_id.c_str(), service_id.size());
    }

    int UbipalService::GetCertificateForName(const std::string& name, NamespaceCertificate& certificate)
    {
        int status = SUCCESS;

        std::vector<NamespaceCertificate> all_certificates;
        status = GetNames(GetNamesFlags::INCLUDE_TRUSTED | GetNamesFlags::INCLUDE_UNTRUSTED, all_certificates);
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
}
