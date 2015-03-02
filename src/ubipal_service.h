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
#include <queue>
#include <condition_variable>

// OpenSSL
#include <openssl/rsa.h>

// Networking
#include <netdb.h>

// chosen to be outside of the range of assigned ports
#define UBIPAL_BROADCAST_PORT "50015"

// Note: Any function marked XXX is yet to be implemented

namespace UbiPAL
{
    // forward declaration for the callbacks
    class UbipalService;

    // A callback type for received messages
    typedef int(*UbipalCallback)(UbipalService* us, Message message);

    // A callback for received replies.
    typedef int(*UbipalReplyCallback)(UbipalService* us, const Message* original_message, const Message* reply_message);

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

            // UbipalService
            // Constructor: pointed to a file, recovers the settings in the file
            // File format is private key\nport
            // port is optional
            // args
            //          [IN] file_path: The path to the file which holds the settings for this server
            UbipalService(const std::string& file_path);

            // ~UbipalService
            // Destructor
            ~UbipalService();

            // No copy constructor
            // Only one of each service should exist to avoid double receiving
            UbipalService(const UbipalService& other) = delete;

            // SaveService
            // Given a file path, saves the relevant information to a file for restarting the service later
            // File format is private key\nport
            // args
            //          [IN] file_path: a path at which to save the file, overwrites the file at that destination
            // return
            //          int: status. SUCCESS on successful write, failure otherwise
            int SaveService(const std::string& file_path);

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

            enum SendMessageFlags
            {
                NONBLOCKING = 2 << 0,
                NO_ENCRYPTION = 2 << 1,
                MESSAGE_AWAIT_REPLY = 2 << 2,
            };

            // SendMessage
            // sends message with args to to
            // args
            //          [IN] flags: flags, including:
            //                  NONBLOCKING: returns immediately, uses a different thread to send
            //                  NO_ENCRYPTION: does not encrypt communication.
            //          [IN] to: The name to which to send, broadcast if null
            //          [IN] message: the message to send
            //          [IN] arg: Any arguments to the message
            //          [IN] arg_len: The length of arg
            // return
            //          int: SUCCESS on success
            int SendMessage(const uint32_t flags, const NamespaceCertificate* to, const std::string& message,
                            const unsigned char* const arg, const uint32_t arg_len);

            // SendMessage
            // sends message with args to to, registers a callback function to allow replies
            // args
            //          [IN] flags: flags, including:
            //                  NONBLOCKING: returns immediately, uses a different thread to send
            //                  NO_ENCRYPTION: does not encrypt communication.
            //          [IN] to: The name to which to send, broadcast if null
            //          [IN] message: the message to send
            //          [IN] arg: Any arguments to the message
            //          [IN] arg_len: The length of arg
            //          [IN] reply_callback: Function to call upon reply to this message
            // return
            //          int: SUCCESS on success
            int SendMessage(const uint32_t flags, const NamespaceCertificate* to, const std::string& message,
                            const unsigned char* const arg, const uint32_t arg_len, const UbipalReplyCallback reply_callback);

            // ReplyToMessage
            // Sends a message reply back for msg
            // args
            //          [IN] flags: Flags, same as for SendMessage
            //          [IN] msg: The message to which to reply
            //          [IN] arg: The arguments of the reply
            //          [IN} arg_len: The length of the arguments
            // return
            //          int: SUCCESSS on success
            int ReplyToMessage(const uint32_t flags, const Message* const msg, const unsigned char* const arg, const uint32_t arg_len);

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

            // SendAcl
            // Sends an AccessControlList to send_to. If sent_to is null, then broadcast it
            // args
            //          [IN] flags: Flags, including:
            //                  NONBLOCKING: returns immediately, uses a different thread to send
            //                  NO_ENCRYPTION: does not encrypt communication.
            //          [IN] acl: The access control list to send
            //          [IN] send_to: the NamespaceCertificate of the service to which to send. If send_to is null, broadcast
            //  return
            //          int: SUCCESS on success, negative error on failure
            int SendAcl(const uint32_t flags, const AccessControlList& acl, const NamespaceCertificate* const send_to);

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

            // RevokeAclFlags
            // Flags for the RevokeAcl function, descriptions in the comments for that function
            enum RevokeAclFlags
            {
                NO_SENDING = 2 << 0,
                NO_ENCRYPT = 2 << 1,
            };

            // RevokeAcl
            // deletes Acl and sends revokation certificate to the given names
            // args
            //          [IN] flags:
            //                  NO_SENDING: Does not send notifications
            //                  BROADCAST: Sends to many parties
            //                  NO_ENCRYPT: Revoke messages are not encrypted
            //          [IN] acl: the id of the ACL to revoke
            //          [IN] send_to: a service a revoke message
            // returns
            //          int: SUCCESS on success, negative error code if not
            int RevokeAcl(const uint32_t flags, const AccessControlList& acl, const NamespaceCertificate* const send_to);

            // The types of UbiPAL statements which are exist.
            enum StatementType
            {
                IS_A,
                IS,
                CAN_SEND_MESSAGE,
                CAN_SAY,
                CURRENT_TIME,
                CURRENT_DATE,
            };

            // STATEMENT
            //          - NAME says NAME CONNECTIVE NAME
            //          - NAME says NAME CONNECTIVE NAME CONNECTIVE NAME
            //          - NAME says CurrentTime() COMPARISON INTEGER
            //          - NAME says NAME CONNECTIVE STATEMENT
            //
            // CONNECTIVE
            //          - {is a, is, can send message, to}
            //
            // COMPARISON
            //          - { <, > }
            //
            // Examples: (a, b, c for variables)
            // a says b is a c
            // a says b is c
            // a says b can send message c to d
            // CurrentTime() a b // CurrentTime() > 9:00, CurrentTime() < 17:00
            // CurrentDate() a b // CurrentDate() < UNIX_TIME (seconds since epoch)
            // a says b can say STATEMENT
            struct Statement
            {
                std::string root;
                StatementType type;
                std::string name1;
                std::string connective;
                std::string name2;
                std::string connective2;
                std::string name3;
                std::string statement;
                std::string comparison;
                std::string integer;
            };

            // XXX
            // EvaluateStatement
            // Checks to see if the given rule holds based on ACLs we've heard. Will evaluate conditions as necessary.
            // example:
            //          FOO can send message BAR to BAZ
            // args
            //          [IN] the statement to evaluate
            // return
            //          int: SUCCESS implies it holds, else will receive NOT_IN_ACLS, FAILED_CONDITIONS, TIMEOUT_CONDITIONS, FAILED_EVALUATION, or INVALID_SYNTAX, else a negative error code
            int EvaluateStatement(const std::string& statement);

            // XXX
            // EvaluateStatementRecurse
            // Recursive call for EvaluateStatement.
            // args
            //          [IN] statement: The parsed statement in a struct form. Parsed by EvaluateStatement
            //          [IN] current_service: The current service ID for evaluation
            //          [IN/OUT] acl_trail: The trail of acls we've gone through to this point to avoid loops
            //          [IN/OUT] conditions: The collections of conditions to this point
            // return
            //          int: SUCCESS means the rule holds, else reutnrs NOT_IN_ACLS, FAILED_CONDITIONS, TIMEOUT_CONDITIONS, FAILED_EVALUATION, or INVALID_SYNTAX, else a negative error code
            int EvaluateStatementRecurse(const Statement& statement, const std::string& current_service, std::vector<std::string>& acl_trail, std::vector<std::string>& conditions);

            // XXX
            // FindNameForStatements
            // Checks to see if there is a name that matches the given statements
            // args
            //          [IN] statements: The statements to evaluate. "NAME" is used as the wildcard in these rules.
            //                  Examples: "NAME can send message OPEN to FOO", "FOO say NAME is a BAR", "NAME can say FOO can send message BAR to BAZ"
            //                  This would find a service which can send OPEN to FOO, FOO says is a BAR, and can delegate sending BAR to BAZ.
            //          [OUT] result_name: The resulting name. For now, this selects the first name which matches the criteria.
            // return
            //          int: 0 imples SUCCESS, NOT_IN_ACLS, FAILED_CONDITIONS_or TIMEOUT_CONDITIONS if it fails, else negative error code
            int FindNameForStatements(const std::vector<std::string>& statements, NamespaceCertificate& result_name);

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

            // SetThreadCounts
            // Sets the thread limits
            // args
            //          [IN] recv_threads: Number of threads for receiving
            //          [IN] send_threads: Number of threads for sending
            // return
            //          int: SUCCESS on success
            int SetThreadCounts(const unsigned int& recv_threads, const unsigned int& send_threads);

            // GetId
            // Returns the string ID of this service
            // return
            //          string: ID of this service
            inline std::string GetId() { return id; }

        private:

            // MessageConditionPassed
            // Called when all message conditions have been met and message is ready to be delivered.
            // args
            //          [IN] message: The message to deliver.
            // return
            //          int: SUCCESS on success
            int MessageConditionPassed(const Message& message);

            // MessageConditionFailed
            // Called when a message conditition failed. Informs the requesting service.
            // args
            //          [IN] message: The message which failed conditions.
            // return
            //          int: SUCCESS on success
            int MessageConditionFailed(const Message& message);

            // MessageConditionTimeout
            // Called when a message conditition failed. Informs the requesting service.
            // args
            //          [IN] message: The message which timeout conditions.
            // return
            //          int: SUCCESS on success
            int MessageConditionTimeout(const Message& message);

            // init
            // Runs common parts of the constructors
            // args
            //          [IN] _private_key: The private key to use. If null, a new one is generated
            //          [IN] _port: The port to use. If Null, the OS assigns a port
            // return
            //          void
            void init(const RSA* const _private_key, const char* const _port);

            // SendData
            // Actually does the act of sending data to an address. No formatting or anything is done.
            // args
            //          [IN] address: the address to which to send
            //          [IN] port: the port to send to
            //          [IN] data: the bytes to send
            //          [IN] data_len: The number of bytes to send
            // return
            //          int: SUCCESS on success, negative error else
            int SendData(const std::string& address, const std::string& port, const unsigned char* const data, const uint32_t data_len) const;

            // BroadcastData
            // Broadcasts data to any listening parties
            // args
            //          [IN] data: the bytes to send
            //          [IN] data_len: The number of bytes to send
            // return
            //          int: SUCCESS on success, negative error else
            int BroadcastData(const unsigned char* const data, const uint32_t data_len);

            // RecvUnicast
            // Receives messages bound only for this service and enqueues them to be hanleded by a separate thread
            // args
            //          [IN] arg: The UbipalService* on which to receive
            // return
            //          int: SUCCESS on successful stop, negative error code otherwise. Does not return until EndRecv is called
            static void* RecvUnicast(void* arg);

            // RecvBroadcast
            // Receives messages received as a broadcast and enqueues them to be handled by a separate thread
            // args
            //          [IN] arg: The UbipalService* on which to receive
            // return
            //          int: SUCCESS on successful stop, negative error code otherwise. Does not return until EndRecv is called
            static void* RecvBroadcast(void* arg);

            // RecvMessage
            // Handles receiving for a message which has already be decrypted, decoded, and authenticated.
            // This function handles ACLs and callbacks.
            // args
            //          [IN] message: A message pointer
            // return
            //          int: SUCCESS on success, else a negative error, does not return if callback for message does not return
            int RecvMessage(const Message* const message);

            // RecvNamespaceCertificate
            // Handles receiving for a NamespaceCertificate which has already be decrypted, decoded, and authenticated.
            // args
            //          [IN] name_cert: A namespace certificate pointer
            // return
            //          int: SUCCESS on success, else a negative error
            int RecvNamespaceCertificate(const NamespaceCertificate* const name_cert);

            // RecvAcl
            // Handles receiving for an acl which has already be decrypted, decoded, and authenticated.
            // args
            //          [IN] acl: An acl certificate pointer
            // return
            //          int: SUCCESS on success, else a negative error
            int RecvAcl(const AccessControlList* const acl);

            // IncomingData
            // Allows either an incoming connection or buffer of data to be enqueued for handling later
            struct IncomingData
            {
                // If the data is coming TCP, this is a file desriptor for the socket on which the connection is coming
                int conn_fd;

                // If the data is UDP, we've already received it an placed it in this buffer. If it's TCP, this must be null
                unsigned char* buffer;

                // The length of the above buffer. If it's unused, this must be zero
                unsigned int buffer_len;

                // IncomingData
                // Constructs an IncomingData struct
                // args
                //      [IN] _conn_fd: The connection file descriptor for incoming connections
                //      [IN] _buffer: A buffer pointing to received data for incoming data.
                //                      Must be null to treat this as an incoming connection and use conn_fd
                //      [IN] _buffer_len: The length of the above buffer, if the buffer is non-null
                IncomingData(int _conn_fd, unsigned char* _buffer, unsigned int _buffer_len)
                    : conn_fd(_conn_fd), buffer(_buffer), buffer_len(_buffer_len) {}
            };

            // HandleIncomingConnection
            // Handle an incoming connection and stores its data in the incoming_data struct
            // args
            //          [IN/OUT] incoming_data: A struct to read the data from the connection file descriptor and
            //                                  store data in the buffer and buffer length fields
            // return
            //          SUCCESS on success, negative error otherwise
            int HandleIncomingConnection(IncomingData* const incoming_data) const;

            // HandleMessage
            // Handles the decryption and authentication of incoming message data and passes to the appropriate recv function
            // args
            //          [IN/OUT] incoming_data: Data going in (must be stored in incoming_data->buffer by now). If encrypted, it is decrypted
            //                                  with the result placed back in incoming_data->buffer.
            int HandleMessage(IncomingData* const incoming_data);

            // ConsumeIncoming
            // Consumes incoming data from incoming_messages queue with authentication and decryption
            // args
            //          [IN] arg: UbipalService* pointer to this
            // return
            //          void*: NULL
            static void* ConsumeIncoming(void* arg);

            struct HandleSendMessageArguments
            {
                UbipalService* us;
                std::string address;
                std::string port;
                BaseMessage* msg;
                uint32_t flags;

                HandleSendMessageArguments();
                HandleSendMessageArguments(UbipalService* const _us);
            };

            // HandleSendMessage
            // Handles an outgoing message to allow threaded execution
            // args
            //          [IN] args: A pointer to a HandleSendMessageArguments struct which includes
            //                  us: A pointero to this UbipalService
            //                  address: The address to send to
            //                  port: The port to receive from
            //                  msg: The message to send
            //                  flags: Flags for the function, including MESSAGE_AWAITING_REPLY which avoids freeing the message
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

            // avoids race conditions on the above data structures
            std::mutex services_mutex;

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

            // the address to which we broadcast
            std::string broadcast_address;

            // holds address structure for broadcasting
            struct addrinfo* broadcast_info;

            // socket descriptor used to send and receive directly to and from other services
            int unicast_fd;

            // socket descriptor used to send and receive broadcast messages
            int broadcast_fd;

            // ensure only one thread is receiving at a time
            bool receiving;

            // mutual exclusion for the above variable
            std::mutex receiving_mutex;

            // threads for receiving messages
            std::vector<pthread_t> recv_threads;

            // Incomming connections to be handled
            std::queue<IncomingData*> incoming_messages;

            // Mutex for incoming connections
            std::mutex incoming_msg_mutex;

            // Condition variable for incoming connections
            std::condition_variable incoming_msg_cv;

            // The number of threads to use for receiving
            unsigned int num_recv_threads;

            // threads for async sends
            std::vector<pthread_t> send_threads;

            // The number of threads to use for sending
            unsigned int num_send_threads;

            // mutex for thread creation and message passing
            std::mutex threads_mutex;

            // maps message types to callbacks
            std::unordered_map<std::string, UbipalCallback> callback_map;

            // mutex to avoid time-of-check-to-time-of-use race conditions in RegisterCallback
            std::mutex callbacks_mutex;

            // maps message ID to reply callback
            std::unordered_map<std::string, UbipalReplyCallback> reply_callback_map;

            // mutex to avoid toc-tou race conditions
            std::mutex reply_callback_mutex;

            // holds messages for which we are awaiting replies
            std::vector<Message*> msgs_awaiting_reply;

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

            // GetConditionsFromRule
            // Takes a string rule and parses it to find the conditions in string form
            // args
            //          [IN] rule: The string of the entire rule
            //          [OUT] conditions: The vector of conditions
            // returns
            //          int: SUCCESS on success
            int GetConditionsFromRule(const std::string& rule, std::vector<std::string>& conditions);

            // ConditionsCheck
            // A structure used to track condition confirmations
            struct ConditionCheck
            {
                Message message;
                std::vector<std::string> conditions;
                uint32_t time;
            };

            // Holds messages awaiting condition checks
            std::vector<ConditionCheck> awaiting_conditions;

            // avoids race conditionson the above data structure
            std::mutex awaiting_conditions_mutex;

            // holds the thread for checking condition timeouts
            pthread_t conditions_timeout_thread;

            // The length of condition check timeout in milliseconds
            uint32_t condition_timeout_length;

            // GetTimeMilliseconds
            // Returns the current service (systeM) time in milliseconds since the epoch
            // returns
            //          int: The current time in milliseconds
            static uint32_t GetTimeMilliseconds();

            // ConditionTimeout
            // Checks condition timeout with timeout of condition_timeout_length. Any conditions which time out are removed from the list
            // and their requesting services are notified.
            // args
            //          [IN] arg: UbipaService* this
            // return
            //          NULL
            static void* ConditionTimeout(void* arg);

            // ConditionReplyCallback
            // Walks through the awaiting_conditions structure and removes any dependencies on the confirmed message
            // For ANY message with a matching condition
            // args
            //          [IN] us: This service
            //          [IN] original_message: Message sent to service for confirmation
            //          [IN] reply_message: The message with either a confirmation or denies
            // returns
            //          int: SUCCESS on success, negative error code on error
            static int ConditionReplyCallback(UbipalService* us, const Message* original_message, const Message* reply_message);

            // StartConditionChecks
            // Begins the process of checking for conditions by saving the message and conditions
            // as well as sending the confirmation messages
            // args
            //          [IN] message: The message in question
            //          [IN] conditions: conditions which must be met
            // returns
            //          int: SUCCESS on success, negative error code on error
            int StartConditionChecks(const Message& message, const std::vector<std::string>& conditions);
    };
}

#endif
