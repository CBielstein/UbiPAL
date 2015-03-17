// Cameron Bielstein, 1/14/15
// messages.h
// Message types and certificates for UbiPAL

#ifndef UBIPAL_SRC_MESSAGES_H
#define UBIPAL_SRC_MESSAGES_H

#define MAX_MESSAGE_SIZE 4096

// ubipal
#include "rsa_wrappers.h"

// standard
#include <stdint.h>
#include <string>
#include <vector>
#include <string.h>

/** Network encoding takes the following formats. This is to be used as a reference for encode and decode functions. They should do the rest.
All types should use the appropriate translations to and from network types for endian correctness

BaseMessage:
    1 byte: type
    4 bytes: length_to, length of name dest address in bytes
    length_to bytes: name of dest
    4 bytes: length_from, length of name of sender address in bytes
    length_from bytes: name of source

Message: BaseMessage, plus the following
    4 bytes: msg_len uint32_t
    msg_len bytes: message char*
    4 bytes: arg_len uint32_t
    arg_len bytes: arg char*
    4 bytes: msg_id_len uint32_t
    msg_id_len bytes: msg_id uuid as char*

NamespaceCerfiticate: BaseMessage, plus the following
    4 bytes: id_len uint32_t
    id_len bytes: id char*
    4 bytes: desc_len uint32_t
    desc_len bytes: description char*
    4 bytes: addr_len uint32_t
    addr_len bytes: address char*
    4 bytes: port_len uint32_t
    port_len bytes: port char*

Note: ACLs will store rule without leading "<name> says" as it is implied by the signer of the ACL
AccessControlList: BaseMessage, plus the following
    4 bytes: num_rules
    num_rules times the following
        4 bytes: rule_len
        rule_len bytes: rule char*

AesKeysMessage: BaseMessage plus the following
    4 bytes: key_len
    key_len bytes: key
    4 bytes: iv_len
    iv_len bytes: iv
**/


namespace UbiPAL
{

    enum MessageType
    {
        MESSAGE = 1,
        NAMESPACE_CERTIFICATE = 2,
        ACCESS_CONTROL_LIST = 3,
        AES_KEY_MESSAGE = 4,
    };

    struct BaseMessage
    {
        uint8_t type;
        std::string to;
        std::string from;

        // used to identify ACLs and namespace certificates for revocation
        std::string msg_id;

        // default constructor generates uuid
        BaseMessage();
        virtual ~BaseMessage();

        // Encode
        // Takes a buffer buf of length buf_len and outputs an array of bytes representing this message type.
        // If the buffer is too short, additional data is truncated
        // args
        //      [IN/OUT] buf: the buffer in which to place the resulting bytes
        //      [IN] buf_len: The length of the buffer. This ensures it's of appropriate length
        // return
        //      int: the length of the resulting bytes, or a negative error code
        virtual int Encode(unsigned char* const buf, const uint32_t buf_len) const;

        // Decode
        // Takes a buffer buf of length buf_len and decodes the data to the fields in this message type.
        // args
        //      [IN] buf: the buffer of bytes to decode
        //      [IN] buf_len: The length of the bytes to decode
        // return
        //      int: The number of bytes used, negative error code otherwise
        virtual int Decode(const unsigned char* const buf, const uint32_t buf_len);

        // EncodedLength
        // Returns the number of bytes required to encode this message
        // return
        //      int: the number of bytes required to encode this message, or a negative error code
        virtual int EncodedLength() const;

        // EncodeString
        // Given a string, encodes and saves it in to buf (of length buf_len) as 4 bytes length then the string itself
        // args
        //      [IN/OUT] buf: The buffer to which to save
        //      [IN] buf_len: the length of the buffer (to avoid overflow)
        //      [IN] str: The string we want to encode
        // return
        //      int: the number of bytes encoded and saved to buf, else a negative error code
        static int EncodeString(unsigned char* const buf, const uint32_t buf_len, const std::string& str);

        // EncodeBytes
        // Give a buffer, raw bytes, and a length for both, this encodes as 4 bytes unsigned length then the bytes themselves
        // args
        //      [IN/OUT] buf: The buffer to which to save
        //      [IN] buf_len: The length of the buffer
        //      [IN] bytes: The bytes to encode
        //      [IN] bytes_len: The number of bytes to encode
        // return
        //      int: the number of bytes encoded and saved to buf, else a negative error code
        static int EncodeBytes(unsigned char* const buf, const uint32_t buf_len, const unsigned char* const bytes, const uint32_t bytes_len);

        // EncodeUint32_t
        // Encodes a uint32_t number to the buffer
        // args
        //      [IN/OUT] buf: The buffer into which to encode
        //      [IN] buf_len: The length of the buffer in buf
        //      [IN] number: The number to encode in buf
        // return
        //      int: the number of bytes encoded and saved to buf, else a negative error code
        static int EncodeUint32_t(unsigned char* const buf, const uint32_t buf_len, const uint32_t number);

        // DecodeString
        // Given a buffer of raw bytes, a length for that buffer, and a string object, decodes from the above functions
        // args
        //      [IN] buf: The raw bytes
        //      [IN] buf_len: The number of raw bytes
        //      [OUT] str: The string object to which to save
        // return
        //      int: the number of bytes decoded, else a negative error code
        static int DecodeString(const unsigned char* const buf, const uint32_t buf_len, std::string& str);

        // DecodeUint32_t
        // Give a buffer of raw bytes, a length for that buffer, and a uint32_t, decodes from the above functions
        // args
        //      [IN] buf: The raw bytes
        //      [IN] buf_len: THe number of raw bytes
        //      [OUT] number: The number to which to save
        // return
        //      int: The number of bytes decoded, else a negative error code
        static int DecodeUint32_t(const unsigned char* const buf, const uint32_t buf_len, uint32_t& number);
    };

    // Message
    // A message sent from one UbipalName to another requesting action or information
    struct Message : BaseMessage
    {
        std::string message;
        uint32_t arg_len;
        unsigned char* argument;

        Message();
        Message(const unsigned char* const arg, const uint32_t arg_size);
        Message(const Message& other);
        ~Message() override;
        Message& operator=(const Message& rhs);

        virtual int Encode(unsigned char* const buf, const uint32_t buf_len) const override;
        virtual int Decode(const unsigned char* const buf, const uint32_t buf_len) override;
        virtual int EncodedLength() const override;
    };

    struct NamespaceCertificate : BaseMessage
    {
        std::string id;
        std::string description;
        std::string address;
        std::string port;

        NamespaceCertificate();

        virtual int Encode(unsigned char* const buf, const uint32_t buf_len) const override;
        virtual int Decode(const unsigned char* const buf, const uint32_t buf_len) override;
        virtual int EncodedLength() const override;
    };

    struct AccessControlList : BaseMessage
    {
        std::string id;

        // a local description, not published
        std::string description;

        std::vector<std::string> rules;

        AccessControlList();

        virtual int Encode(unsigned char* const buf, const uint32_t buf_len) const override;
        virtual int Decode(const unsigned char* const buf, const uint32_t buf_len) override;
        virtual int EncodedLength() const override;
    };

    struct AesKeyMessage : BaseMessage
    {
        uint32_t key_len;
        unsigned char* key;
        uint32_t iv_len;
        unsigned char* iv;

        virtual int Encode(unsigned char* const buf, const uint32_t buf_len) const override;
        virtual int Decode(const unsigned char* const buf, const uint32_t buf_len) override;
        virtual int EncodedLength() const override;
        AesKeyMessage();
        AesKeyMessage(const unsigned char* const _key, const uint32_t _key_len, const unsigned char* const _iv, const uint32_t _iv_len);
        ~AesKeyMessage() override;
        AesKeyMessage& operator=(const AesKeyMessage& rhs);
    };

    // Define comparison operators
    inline bool operator==(const BaseMessage& lhs, const BaseMessage& rhs)
    {
        return ((lhs.type == rhs.type) && (lhs.to.compare(rhs.to) == 0) && (lhs.from.compare(rhs.from) == 0) &&
                (lhs.msg_id.compare(rhs.msg_id) == 0));
    }
    inline bool operator!=(const BaseMessage& lhs, const BaseMessage& rhs) { return !operator==(lhs, rhs); }

    inline bool operator==(const NamespaceCertificate& lhs, const NamespaceCertificate& rhs)
    {
        return ((lhs.type == rhs.type) && (lhs.to.compare(rhs.to) == 0) && (lhs.from.compare(rhs.from) == 0) &&
                (lhs.msg_id.compare(rhs.msg_id) == 0) && (lhs.id.compare(rhs.id) == 0) && (lhs.description.compare(rhs.description) == 0)&&
                (lhs.address.compare(rhs.address) == 0) && (lhs.port.compare(rhs.port) == 0));
    }
    inline bool operator!=(const NamespaceCertificate& lhs, const NamespaceCertificate& rhs) { return !operator==(lhs, rhs); }

    inline bool operator==(const Message& lhs, const Message& rhs)
    {
        return ((lhs.type == rhs.type) && (lhs.to.compare(rhs.to) == 0) && (lhs.from.compare(rhs.from) == 0) &&
                (lhs.msg_id.compare(rhs.msg_id) == 0) && (lhs.message.compare(rhs.message) == 0) && (lhs.arg_len == rhs.arg_len) &&
                (memcmp(lhs.argument, rhs.argument, lhs.arg_len) == 0));
    }
    inline bool operator!=(const Message& lhs, const Message& rhs) { return !operator==(lhs, rhs); }

    inline bool operator==(const AccessControlList& lhs, const AccessControlList& rhs)
    {
        if (!((lhs.type == rhs.type) && (lhs.to.compare(rhs.to) == 0) && (lhs.from.compare(rhs.from) == 0) &&
                (lhs.msg_id.compare(rhs.msg_id) == 0) && (lhs.id.compare(rhs.id) == 0) && (lhs.rules.size() == rhs.rules.size())))
        {
            return false;
        }

        for (unsigned int i = 0; i < lhs.rules.size(); ++i)
        {
            if (lhs.rules[i].compare(rhs.rules[i]) != 0)
            {
                return false;
            }
        }

        return true;
    }
    inline bool operator!=(const AccessControlList& lhs, const AccessControlList& rhs) { return !operator==(lhs, rhs); }

}

#endif
