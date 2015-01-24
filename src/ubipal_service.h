// Cameron Bielstein, 1/14/15
// ubipal_service.h
// Representation of a service in the UbiPAL namespace

#ifndef UBIPAL_SRC_UBIPAL_SERVICE_H
#define UBIPAL_SRC_UBIPAL_SERVICE_H

// Ubipal
#include "ubipal_name.h"
#include "ubipal_acl.h"

// Standard
#include <vector>
#include <map>
#include <string>

// OpenSSL
#include <openssl/rsa.h>

namespace UbiPAL
{
    // A callback type for received messages
    typedef void(*UbipalCallback)(const std::string&, const std::string&);

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

            // TODO ???
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

            // TODO ???
            // SaveService
            // Given a file pointer, saves the relevant information to a file for restarting the service later
            // args
            //          [IN] file_path: a path at which to save the file, overwrites the file at that destination
            // return
            //          int: status. SUCCESS on successful write, failure otherwise
            // int SaveService(const std::string& file_path);

            // sends message with args to to
            // flags:
            //          NONBLOCKING
            int SendMessage(const uint32_t flags, const UbipalName& to, const std::string& message, const std::string& args) const;

            // BeginRecv
            // Binds to a port and begins receiving
            // flags:
            //          DONT_PUBLISH_NAME
            int BeginRecv(const uint32_t flags, const UbipalCallback& received_callback);

            // Sends an updated namespace certificate to the given name, or broadcasts it if null
            int SendName(const UbipalName* const send_to) const;

            // adds a new Acl to the list of local acls
            int CreateAcl(const std::string& name, const std::vector<std::string>& rules);

            // Returns a mutable pointer to the acl for modification (rule addition or removal)
            int GetAcl(const std::string& name, UbipalAcl*& acl);

            // if send_to is null, broadcast, if it's non-null, send it to a specific location
            int SendAcl(const UbipalAcl* const acl, const UbipalName* const send_to) const;
            int SendAcl(const UbipalAcl* const acl, const std::vector<UbipalName*>& send_to) const;

            // deletes Acl and sends revokation certificate to the given names
            int RevokeAcl(const UbipalAcl* const acl, const UbipalName* const send_to);
            int RevokeAcl(const UbipalAcl* const acl, const std::vector<UbipalName*>& send_to);

            // looks up a name advertising the desired message
            int FindNameForMessage(const std::string& message, UbipalName*& name);

        private:
            // the key for this service, also works as a unique identifier
            RSA* private_key;

            // stores information parsed from received certificates
            std::vector<UbipalName> neighbors;

            // some data structure to hold ACLs
            // maps the public key string representation to any acls it has sent
            std::map<std::string, std::vector<UbipalAcl>> other_acls;

            // some data structure to hold our rules array of strings or something
            std::vector<UbipalAcl> local_acls;

            // the port on which we operate. String held in case we save to a file later
            std::string port;

            // socket descriptor used to send and receive
            int sockfd;

            // Enable tests
            friend class UbipalServiceTests;
    };
}

#endif
