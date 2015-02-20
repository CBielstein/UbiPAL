// Cameron Bielstein, 1/14/15
// ubipal_service.h
// Representation of a service in the UbiPAL namespace

#ifndef UBIPAL_SRC_UBIPAL_SERVICE_H
#define UBIPAL_SRC_UBIPAL_SERVICE_H

// Ubipal
#include "messages.h"

// Standard
#include <vector>
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
                DONT_PUBLISH_NAME = 2 << 0,
                NON_BLOCKING = 2 << 1,
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

            // SetDescription
            // Sets the advertised service description. This allows simple discovery of the service.
            // args
            //          [IN] desc: The new description to advertise
            // return
            //          int:: SUCCESS on success
            int SetDescription(const std::string& desc);

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
                NONBLOCKING = 2 << 0,
                NO_ENCRYPTION = 2 << 1,
            };

            // SendMessage
            // sends message with args to to
            // args
            //          [IN] flags: flags, including:
            //                  NONBLOCKING: returns immediately, uses a different thread to send
            //                  NO_ENCRYPTION: does not encrypt communication.
            //          [IN] to: The name to which to send
            //          [IN] message: the message to send
            //          [IN] arg: Any arguments to the message
            //          [IN] arg_len: The length of arg
            // return
            //          int: SUCCESS on success
            int SendMessage(const uint32_t flags, const NamespaceCertificate& to, const std::string& message, const char* const arg, const uint32_t arg_len);

            // TODO XXX ???
            // int SendMessage(const uint32_t flags, const NamespaceCertificate& to, const std::string& message,
                            // const std::string& args, const UbipalCallback& reply_callback);

            // SendName
            // Sends an updated namespace certificate to the given name, or broadcasts it if null
            // args
            //          [IN] flags: Flags, including:
            //                  NONBLOCKING: returns immediately, uses a different thread to send
            //                  NO_ENCRYPTION: does not encrypt communication.
            //          [IN] send_to: The address to which to send, if null, this broadcasts the name
            // return
            //          int: SUCCESS on success
            int SendName(const uint32_t flags, const NamespaceCertificate* const send_to);

            // SendName
            // Sends an updated namespace certificate to the given address and port. This is unencrypted.
            // args
            //          [IN] flags: Flags, including:
            //                  NONBLOCKING: returns immediately, uses a different thread to send
            //                  NO_ENCRYPTION: does not encrypt communication.
            //          [IN] address: The address to which to send
            //          [IN] port: The port to which to send
            // return
            //          int: SUCCESS on success
            int SendName(const uint32_t flags, const std::string& address, const std::string& port);

            // CreateAcl
            // adds a new Acl to the list of local acls with the given rule-s
            // args
            //          [IN] description: a description to put on the ACL, local only does not get published
            //          [IN] rules: a vector of rules to place in the new ACL
            //          [OUT] result: the resultant ACL
            // return
            //          int: SUCCESS on success, else negative error code
            int CreateAcl(const std::string& description, const std::vector<std::string>& rules, AccessControlList& result);

            // GetAclFlags
            // Flags for GetAcl, descriptions in comments on that function
            enum GetAclFlags
            {
                SEARCH_BY_ID = 2 << 0,
                SEARCH_BY_DESC = 2 << 1,
            };

            // GetAcl
            // Returns a reference to the first control list matching the search term
            // args
            //          [IN] flags: Flags, as follows:
            //                  SEARCH_BY_ID: searches by id
            //                  SEARCH_BY_DESC: searches by description
            //          [IN] search_term: the description we want to find
            //          [OUT] acl: The access control list that was found
            // return
            //          int: SUCCESS on success, NOT_FOUND if not found, other negative error code on error
            int GetAcl(const uint32_t flags, const std::string& search_term, AccessControlList& acl);

            // XXX
            // if send_to is null, broadcast, if it's non-null, send it to a specific location
            int SendAcl(const AccessControlList* const acl, const NamespaceCertificate* const send_to) const;

            // RevokeAclFlags
            // Flags for the RevokeAcl function, descriptions in the comments for that function
            enum RevokeAclFlags
            {
                NO_SENDING = 2 << 0,
                BROADCAST = 2 << 1,
            };

            // RevokeAcl
            // deletes Acl and sends revokation certificate to the given names
            // args
            //          [IN] flags:
            //                  NO_SENDING: Does not send notifications
            //                  BROADCAST: Sends to many parties
            //          [IN] acl: the id of the ACL to revoke
            //          [IN] send_to: a service a revoke message
            // returns
            //          int: SUCCESS on success, negative error code if not
            int RevokeAcl(const uint32_t flags, const std::string& acl, const NamespaceCertificate* const send_to);

            // XXX
            // looks up a name advertising the desired message
            int FindNameForMessage(const std::string& message, NamespaceCertificate*& name);

            enum GetNamesFlags
            {
                INCLUDE_UNTRUSTED = 2 << 0,
                INCLUDE_TRUSTED = 2 << 1
            };

            // GetNames
            // Constructs a vector of NamespaceCertificates (either trusted, untrusted, or both) to iterate through
            // This vector is not by reference, so changes here will not be reflected in the private data structures below
            // args
            //          [IN] flags: flags, including
            //                  INCLUDE_UNTRUSTED: includes untrusted names
            //                  INCLUDE_TRUSTED: includes trusted names
            //          [IN/OUT] names: A vector of resultant names
            // return
            //          int: SUCCESS on success, negative error otherwise
            int GetNames(const uint32_t flags, std::vector<NamespaceCertificate>& names);

            // CheckAcls
            // Verifies that the sender can send message based on receiver's ACLs
            // args
            //          [IN] message: message in question
            //          [IN] sender: the service that sent/will send the message
            //          [IN] receiver: the destination of the message
            //          [OUT] acl_trail: if not null, the set of ACLs used to validate this message
            //          [OUT] conditions: if not null, a set of conditions which must hold
            // returns
            //          int: SUCCESS if authorized, NOT_IN_ACLS if the current ACLs don't allow it, FAILED_CONDITIONS if conditions didn't hold
            //               else an error code
            int CheckAcls(const std::string& message, const std::string& sender, const std::string& receiver,
                          std::vector<std::string>* acl_trail, std::vector<std::string>* conditions);

            // GetId
            // Returns the id of this service
            // returns
            //          std::string the ID of this service
            std::string GetId();

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
            // args
            //          [IN] hc_args: a pointer to a HancleConnectionArguments struct which includes
            //                  us: A pointer to this UbipalService
            //                  conn_fd: the file descriptor of the connection to use
            // return
            //          void*: NULL
            static void* HandleConnection(void* hc_args);

            struct HandleSendMessageArguments
            {
                const UbipalService* us;
                std::string address;
                std::string port;
                BaseMessage* msg;
                uint32_t flags;

                HandleSendMessageArguments();
                HandleSendMessageArguments(const UbipalService* const _us);
            };

            // HandleSendMessage
            // Handles an outgoing message to allow threaded execution
            // args
            //          [IN] args: A pointer to a HandleSendMessageArguments struct which includes
            //                  us: A pointero to this UbipalService
            //                  address: The address to send to
            //                  port: The port to receive from
            //                  msg: The message to send
            // returns
            //          void*: NULL
            static void* HandleSendMessage(void* args);

            // the key for this service, public version also works as a unique identifier
            RSA* private_key;

            // A string representation of the public key for ID use
            std::string id;

            // A string description useful for finding a specific service
            std::string description;

            // stores information parsed from received certificates from services we trust
            std::unordered_map<std::string, NamespaceCertificate> trusted_services;

            // stores information parsed from received certificates from other services
            std::unordered_map<std::string, NamespaceCertificate> untrusted_services;

            // some data structure to hold ACLs
            // maps the public key string representation to any acls it has sent
            std::unordered_map<std::string, std::vector<AccessControlList>> external_acls;

            // prevents toc-tou race in external_acls
            std::mutex external_acls_mutex;

            // some data structure to hold our rules array of strings or something
            std::vector<AccessControlList> local_acls;

            // prevents time-of-check to time-of-use race in local_acls
            std::mutex local_acls_mutex;

            // the port on which we operate
            std::string port;

            // the address on which we advertise our service
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

            // ConsiderService
            // A structure used internally in CheckAclsRecurse
            struct ConsiderService
            {
                std::string service_id;
                std::vector<std::string> conditions;
                std::string referenced_from_acl;
            };

            // CheckAclsRecurse
            // Recurseive call to verify that the sender can send message based on receiver's ACLs
            // args
            //          [IN] message: message in question
            //          [IN] sender: the service that sent/will send the message
            //          [IN] receiver: the destination of the message
            //          [IN] current: the current service being evaluated
            //          [IN/OUT] acl_trail: the set of ACLs used to validate this message
            //          [IN/OUT] conditions: a set of conditions which must hold
            // returns
            //          int: SUCCESS if authorized, NOT_IN_ACLS if the current ACLs don't allow it, FAILED_CONDITIONS if conditions didn't hold
            //               else an error code
            int CheckAclsRecurse(const std::string& message, const std::string& sender, const std::string& receiver, const std::string& current,
                                 std::vector<std::string>& acl_trail, std::vector<std::string>& conditions);
    };
}

#endif
