// Cameron Bielstein, 1/14/15
// ubipal_service.h
// Representation of a service in the UbiPAL namespace

#ifndef UBIPAL_SRC_UBIPAL_SERVICE_H
#define UBIPAL_SRC_UBIPAL_SERVICE_H

// Ubipal
#include "ubipal_name.h"
#include "ubipal_acl.h"
#include "messages.h"

// Standard
#include <vector>
#include <map>
#include <unordered_map>
#include <string>
#include <mutex>
#include <pthread.h>

// OpenSSL
#include <openssl/rsa.h>

// Note: Any function marked XXX is yet to be implemented

namespace UbiPAL
{
    // A callback type for received messages
    typedef int(*UbipalCallback)(std::string message, char* arg, uint32_t arg_len);

    // UbipalService
    // Representation of a service in the UbiPAL namespace
    // Similar to UbipalName, but capable of sending and receiving messages
    class UbipalService
    {
        public:
            // UbipalService
            // Default constructor: generates a new private key and opens on a random port
            UbipalService();

            // UbipalService
            // Constructor: Uses whichever argument is not null and generates/picks whichever is null
            // args
            //          [IN] _private_key: Uses the private key for this service. If NULL, generates a new key
            //          [IN] port: Binds to this port. If NULL, picks a random port
            UbipalService(const RSA* const _private_key, const char* const _port);

            // TODO XXX ???
            // UbipalService
            // Constructor: pointed to a file, recovers the settings in the file
            // args
            //          [IN] file_path: The path to the file which holds the settings for this server
            // UbipalService(const std::string& file_path);

            // ~UbipalService
            // Destructor
            ~UbipalService();

            // No copy constructor
            // Only one of each service should exist to avoid double receiving
            UbipalService(const UbipalService& other) = delete;

            // TODO XXX ???
            // SaveService
            // Given a file pointer, saves the relevant information to a file for restarting the service later
            // args
            //          [IN] file_path: a path at which to save the file, overwrites the file at that destination
            // return
            //          int: status. SUCCESS on successful write, failure otherwise
            // int SaveService(const std::string& file_path);

            // Flags for BeginRecv
            enum BeginRecvFlags
            {
                // prevents BeginRecv from publishing the namespace certificate
                DONT_PUBLISH_NAME = 1 << 0,
                NON_BLOCKING = 1 << 1,
            };

            // BeginRecv
            // Begins accepting messages from the network. Nonblocking and spins up threads in the background for IO
            // args
            //          [IN] flags: options including:
            //                            DONT_PUBLISH_NAME: stops the default namespace cetificate publication
            //                            NON_BLOCKING: does not block to do receiving
            // return
            //          int: SUCCESS on success
            int BeginRecv(const uint32_t flags);

            // RegisterCallback
            // Adds a function to be called upon receiving a given message
            // If the message has previously registered a callback, it is replaced with the new callback
            // args
            //          [IN] message: The message type to pass to the callback
            //          [IN] callback: Function pointer to the function to use
            // return
            //          int: SUCCESS on success
            int RegisterCallback(const std::string& message, const UbipalCallback callback);

            // EndRecv
            // Stops accepting messages from the network
            // Does not wait for all threads to stop, sets a state variable and returns.
            // Receiving threads will spin down on next message recev
            // return
            //          int: SUCCESS
            int EndRecv();

            // SetAddress
            // Sets the advertised address. This is necessary to allow for DNS and internal/external IPs
            // args
            //          [IN] addr: The new address to advertise
            // return
            //          int: SUCCESS on success
            int SetAddress(const std::string& addr);

            // SetPort
            // Sets the advertised port. This is necessary to allow for firewall rules and NAT
            // args
            //          [IN] prt: The new port to advertise
            // return
            //          int: SUCCESS on success
            int SetPort(const std::string& prt);

            // SendData
            // Actually does the act of sending data to an address. No formatting or anything is done.
            // args
            //          [IN] address: the address to which to send
            //          [IN] port: the port to send to
            //          [IN] data: the bytes to send
            //          [IN] data_len: The number of bytes to send
            int SendData(const std::string& address, const std::string& port, const char* const data, const uint32_t data_len) const;

            enum SendMessageFlags
            {
                NONBLOCKING = 1 << 0,
            };

            // XXX
            // sends message with args to to
            // flags:
            //          NONBLOCKING
            int SendMessage(const uint32_t flags, const UbipalName& to, const std::string& message, const char* const arg, const uint32_t arg_len);

            // TODO XXX ???
            // int SendMessage(const uint32_t flags, const UbipalName& to, const std::string& message,
                            // const std::string& args, const UbipalCallback& reply_callback);


            // XXX
            // Sends an updated namespace certificate to the given name, or broadcasts it if null
            int SendName(const UbipalName* const send_to) const;
            int SendName(const std::string& address, const std::string& port) const;

            // XXX
            // adds a new Acl to the list of local acls
            int CreateAcl(const std::string& name, const std::vector<std::string>& rules);

            // XXX
            // Returns a mutable pointer to the acl for modification (rule addition or removal)
            int GetAcl(const std::string& name, UbipalAcl*& acl);

            // XXX
            // if send_to is null, broadcast, if it's non-null, send it to a specific location
            int SendAcl(const UbipalAcl* const acl, const UbipalName* const send_to) const;
            int SendAcl(const UbipalAcl* const acl, const std::vector<UbipalName*>& send_to) const;

            // XXX
            // deletes Acl and sends revokation certificate to the given names
            int RevokeAcl(const UbipalAcl* const acl, const UbipalName* const send_to);
            int RevokeAcl(const UbipalAcl* const acl, const std::vector<UbipalName*>& send_to);

            // XXX
            // looks up a name advertising the desired message
            int FindNameForMessage(const std::string& message, UbipalName*& name);

        private:
            // Recv
            // Does all the actual work of receiving and filtering messages to their appropriate functions
            // args
            //          [IN] arg: The UbipalService* on which to receive
            // return
            //          int: SUCCESS on successful stop, negative error code otherwise. Does not return until EndRecv is called
            static void* Recv(void* arg);

            // allows passing two arguments to HandleConnection
            struct HandleConnectionArguments
            {
                UbipalService* us;
                int conn_fd;
                HandleConnectionArguments(UbipalService* _us, int _conn_fd) : us(_us), conn_fd(_conn_fd) {}
            };

            // HandleConnection
            // Handle an incoming connection
            static void* HandleConnection(void* hc_args);

            struct HandleSendMessageArguments
            {
                const UbipalService* us;
                std::string address;
                std::string port;
                BaseMessage* msg;

                HandleSendMessageArguments();
                HandleSendMessageArguments(const UbipalService* const _us);
            };

            // HandleSendMessage
            // Handles an outgoing message to allow threaded execution
            static void* HandleSendMessage(void* args);

            // the key for this service, public version also works as a unique identifier
            RSA* private_key;

            // A string representation of the public key for ID use
            std::string id;

            // stores information parsed from received certificates
            std::vector<UbipalName> neighbors;

            // some data structure to hold ACLs
            // maps the public key string representation to any acls it has sent
            std::map<std::string, std::vector<UbipalAcl>> other_acls;

            // some data structure to hold our rules array of strings or something
            std::vector<UbipalAcl> local_acls;

            // the port on which we operate. String held in case we save to a file later
            std::string port;

            // the address on which we advertise our namespace
            std::string address;

            // socket descriptor used to send and receive
            int sockfd;

            // ensure only one thread is receiving at a time
            bool receiving;

            // mutual exclusion for the above variable
            std::mutex receiving_mutex;

            // threads for replying to messages
            // The 0th thread is used for Recv
            std::vector<pthread_t> recv_threads;

            // threads for async sends
            std::vector<pthread_t> send_threads;

            // mutex for thread creation and message passing
            std::mutex threads_mutex;

            // status for recv
            // this allows a returned value without pointer exceptions
            int recv_status;

            // maps message types to callbacks
            std::unordered_map<std::string, UbipalCallback> callback_map;

            // mutex to avoid time-of-check-to-time-of-use race conditions in RegisterCallback
            std::mutex callbacks_mutex;

            // Enable tests
            friend class UbipalServiceTests;
    };
}

#endif
