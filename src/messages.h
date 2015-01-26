// Cameron Bielstein, 1/14/15
// messages.h
// Message types and certificates for UbiPAL

#ifndef UBIPAL_SRC_MESSAGES_H
#define UBIPAL_SRC_MESSAGES_H

#define MAX_MESSAGE_SIZE 1024

namespace UbiPAL
{
/*    enum MessageType
    {
        MESSAGE = 1,
        NAMESPACE_CERTIFICATE = 2,
        ACCESS_CONTROL_LIST = 3,
    };

    struct BaseMessage {};

    // Message
    // A message sent from one UbipalName to another requesting action or information
    struct Message : BaseMessage
    {
        const uint32_t type = MessageType::MESSAGE;
        char[NAME_LENGTH+1] to;
        char[NAME_LENGTH+1] from;
        uint32_t message_length;
        char* message;
        uint32_t arguments_length;
        char* arguments;
        char* signature;
    };

    struct NamespaceCertificate : BaseMessage
    {
        const uint32_t type = MessageType::NAMESPACE_CERTIFICATE;
        char[NAME_LENGTH+1] name;
        uint32_t address_length;
        char* address;
        uint32_t port_length;
        char* port;
        RSA* public_key;
        char[NAME_LENGTH+1] signer;
        char* signature;

    };

    struct AccessControlList : BaseMessage
    {
        const uint32_t type = MessageType::ACCESS_CONTROL_LIST;
        char[NAME_LENGTH+1] from;
        uint32_t rules_length;
        char* rules;
        char* signature;
    }

*/
}

#endif
