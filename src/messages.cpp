// Cameron Bielstein, 1/27/15
// messages.cpp
// Message types and certificates for UbiPAL

// header
#include "messages.h"

// ubipal
#include "log.h"
#include "error.h"
#include "macros.h"

// standard
#include <arpa/inet.h>
#include <string.h>
#include <uuid/uuid.h>

namespace UbiPAL
{
    BaseMessage::BaseMessage()
    {
        // create uuid
        uuid_t uuid_uu;
        uuid_generate(uuid_uu);

        // translate to char*
        // as per the man page, UUID in string form takes 36 bytes + null
        char* uuid_char = (char*) malloc(37);
        if (uuid_char == nullptr)
        {
            Log::Line(Log::EMERG, "AccessControlList::AccessControlList: malloc failed");
            return;
        }
        uuid_unparse_lower(uuid_uu, uuid_char);

        // translate to string
        msg_id = std::string(uuid_char);

        // clean up
        free(uuid_char);
    }

    BaseMessage::~BaseMessage() {}

    int BaseMessage::EncodeString(unsigned char* const buf, const uint32_t buf_len, const std::string& str)
    {
        return BaseMessage::EncodeBytes(buf, buf_len, (unsigned char*)str.c_str(), str.size());
    }

    int BaseMessage::EncodeBytes(unsigned char* const buf, const uint32_t buf_len, const unsigned char* const bytes, const uint32_t bytes_len)
    {
        int status = SUCCESS;
        uint32_t offset = 0;
        unsigned char* str_bits = nullptr;

        // check args
        if (buf == nullptr)
        {
            Log::Line(Log::WARN, "BaseMessage::EncodeBytes: null args EncodeBytes(%p, %u, %p, %u)", buf, buf_len, bytes, bytes_len);
            return NULL_ARG;
        }
        if (bytes == nullptr && bytes_len != 0)
        {
            Log::Line(Log::WARN, "BaseMessage::EncodeBytes: Invalid argument. bytes is null, but bytes_len = %lu", bytes_len);
            return INVALID_ARG;
        }

        // encode length
        status = EncodeUint32_t(buf + offset, buf_len - offset, bytes_len);
        if (status < 0)
        {
            Log::Line(Log::WARN, "BaseMessage::EncodeBytes: BaseMessage::EncodeUint32_t failed %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
            status = SUCCESS;
        }

        // encode bytes
        if (buf_len < offset + bytes_len)
        {
            Log::Line(Log::WARN, "BaseMessage::Encode: Given a buf too short: buf_len %u < offset %u + bytes_len %u", buf_len, offset, bytes_len);
            return BUFFER_TOO_SMALL;
        }
        str_bits = buf + offset;
        memcpy(str_bits, bytes, bytes_len);
        offset += bytes_len;

        return offset;
    }

    int BaseMessage::EncodeUint32_t(unsigned char* const buf, const uint32_t buf_len, const uint32_t number)
    {
        uint32_t offset = 0;
        uint32_t length = 4;
        uint32_t* num_ptr = nullptr;

        if (buf == nullptr)
        {
            Log::Line(Log::WARN, "BaseMessage::EncodeUint32_t: EncodeUint32_t(%p, %u)", buf, buf_len);
            return INVALID_ARG;
        }

        length = 4;
        if (buf_len < offset + length)
        {
            Log::Line(Log::WARN, "BaseMessage::EncodeUint32_t: Given a buf too short: buf_len %u < offset %u + length %u", buf_len, offset, length);
            return BUFFER_TOO_SMALL;
        }

        num_ptr = reinterpret_cast<uint32_t*>(buf + offset);
        if (num_ptr == nullptr)
        {
            Log::Line(Log::EMERG, "BaseMessage::EncodeUint32_t: reinterpet_cast failed.");
            return GENERAL_FAILURE;
        }
        *num_ptr = htonl(number);
        offset += length;

        return length;
    }

    int BaseMessage::DecodeString(const unsigned char* const buf, const uint32_t buf_len, std::string& str)
    {
        int status = SUCCESS;
        uint32_t length = 0;
        uint32_t offset = 0;
        unsigned char* str_bits = nullptr;
        unsigned char* buff = nullptr;

        // check args
        if (buf == nullptr)
        {
            Log::Line(Log::WARN, "BaseMessage::DecodeString: null args DecodeString(%p, %u, str)", buf, buf_len);
            return NULL_ARG;
        }

        // cast of the constness of buff. It's const in the header to show it won't be changed,
        // but it needs to be non-const for later casts
        buff = const_cast<unsigned char*>(buf);
        if (buff == nullptr)
        {
            Log::Line(Log::EMERG, "BaseMessage::DecodeString: const_cast failed.");
            return GENERAL_FAILURE;
        }

        // decode length
        status = DecodeUint32_t(buf + offset, buf_len - offset, length);
        if (status < 0)
        {
            Log::Line(Log::WARN, "BaseMessage::DecodeString: BaseMessage::DecodeUint32_t failed %s", GetErrorDescription(status));
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

        // decode string
        if (buf_len < offset + length)
        {
            Log::Line(Log::WARN, "BaseMessage::DecodeString: Given a buf too short: buf_len %u < offset %u + length %u", buf_len, offset, length);
            return BUFFER_TOO_SMALL;
        }
        str_bits = buff + offset;
        str = std::string((char*)str_bits, length);
        offset += length;

        return offset;
    }

    int BaseMessage::DecodeUint32_t(const unsigned char* const buf, const uint32_t buf_len, uint32_t& number)
    {
        uint32_t length = 0;
        uint32_t offset = 0;
        unsigned char* buff = nullptr;
        uint32_t* num_ptr = nullptr;

        // check args
        if (buf == nullptr)
        {
            Log::Line(Log::WARN, "BaseMessage::DecodeUint32_t: null args DecodeUint32_t(%p, %u, %u)", buf, buf_len, number);
            return NULL_ARG;
        }

        // cast of the constness of buff. It's const in the header to show it won't be changed,
        // but it needs to be non-const for later casts
        buff = const_cast<unsigned char*>(buf);
        if (buff == nullptr)
        {
            Log::Line(Log::EMERG, "BaseMessage::DecodeUint32_t: const_cast failed.");
            return GENERAL_FAILURE;
        }

        length = 4;
        if (buf_len < offset + length)
        {
            Log::Line(Log::WARN, "BaseMessage::DecodeUint32_t: Given a buf too short: buf_len %u < offset %u + length %u", buf_len, offset, length);
            return BUFFER_TOO_SMALL;
        }

        num_ptr = reinterpret_cast<uint32_t*>(buff + offset);
        if (num_ptr == nullptr)
        {
            Log::Line(Log::EMERG, "BaseMessage::DecodeUint32_t: reinterpet_cast failed.");
            return GENERAL_FAILURE;
        }
        number = ntohl(*num_ptr);
        offset += length;

        return offset;
    }

    int BaseMessage::Decode(const unsigned char* const buf, const uint32_t buf_len)
    {
        int status = SUCCESS;
        uint8_t* type_ptr = nullptr;
        uint32_t length = 0;
        unsigned char* buff = nullptr;
        uint32_t offset = 0;

        if (buf == nullptr || buf_len == 0)
        {
            Log::Line(Log::WARN, "BaseMessage::Decode: Decode(%p, %u)", buf, buf_len);
            return INVALID_ARG;
        }

        // cast of the constness of buff. It's const in the header to show it won't be changed,
        // but it needs to be non-const for later casts
        buff = const_cast<unsigned char*>(buf);
        if (buff == nullptr)
        {
            Log::Line(Log::EMERG, "BaseMessage::Decode: const_cast failed.");
            return GENERAL_FAILURE;
        }

        // decode message type
        length = 1;
        if (buf_len < offset + length)
        {
            Log::Line(Log::WARN, "BaseMessage::Decode: Given a buf too short: buf_len %u < offset %u + length %u", buf_len, offset, length);
            return BUFFER_TOO_SMALL;
        }
        type_ptr = reinterpret_cast<uint8_t*>(buff);
        if (type_ptr == nullptr)
        {
            Log::Line(Log::EMERG, "BaseMessage::Decode: reinterpet_cast failed.");
            return GENERAL_FAILURE;
        }
        type = *type_ptr;
        offset += length;

        // decode from
        status = DecodeString(buf + offset, buf_len - offset, from);
        if (status < 0)
        {
            Log::Line(Log::WARN, "NamespaceCertificate::Decode: BaseMessage::DecodeString failed %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
        }

        // decode to
        status = DecodeString(buf + offset, buf_len - offset, to);
        if (status < 0)
        {
            Log::Line(Log::WARN, "NamespaceCertificate::Decode: BaseMessage::DecodeString failed %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
        }

        // decode msg_id
        status = DecodeString(buf + offset, buf_len - offset, msg_id);
        if (status < 0)
        {
            Log::Line(Log::WARN, "NamespaceCertificate::Decode: BaseMessage::DecodeString failed %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
        }

        return offset;
    }

    int BaseMessage::Encode(unsigned char* const buf, const uint32_t buf_len) const
    {
        int status = SUCCESS;
        uint8_t* type_ptr = nullptr;
        uint32_t length = 0;
        uint32_t offset = 0;

        if (buf == nullptr || buf_len == 0)
        {
            Log::Line(Log::WARN, "BaseMessage::Encode: Encode(%p, %u)", buf, buf_len);
            return INVALID_ARG;
        }

        // encode message type
        length = 1;
        if (buf_len < offset + length)
        {
            Log::Line(Log::WARN, "BaseMessage::Encode: Given a buf too short: buf_len %u < offset %u + length %u", buf_len, offset, length);
            return INVALID_ARG;
        }
        type_ptr = reinterpret_cast<uint8_t*>(buf);
        if (type_ptr == nullptr)
        {
            Log::Line(Log::EMERG, "BaseMessage::Encode: reinterpet_cast failed.");
            return GENERAL_FAILURE;
        }
        *type_ptr = type;
        offset += length;

        // encode from
        status = EncodeString(buf + offset, buf_len - offset, from);
        if (status < 0)
        {
            Log::Line(Log::WARN, "BaseMessage::Encode: BaseMessage::EncodeString failed %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
        }

        // encode to
        status = EncodeString(buf + offset, buf_len - offset, to);
        if (status < 0)
        {
            Log::Line(Log::WARN, "BaseMessage::Encode: BaseMessage::EncodeString failed %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
        }

        // encode msg_id
        status = EncodeString(buf + offset, buf_len - offset, msg_id);
        if (status < 0)
        {
            Log::Line(Log::WARN, "BaseMessage::Encode: BaseMessage::EncodeString failed %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
        }

        return offset;
    }

    int BaseMessage::EncodedLength() const
    {
        return 1 + 4 + to.size() + 4 + from.size() + 4 + msg_id.size();
    }

    int Message::Encode(unsigned char* const buf, const uint32_t buf_len) const
    {
        int status = SUCCESS;
        uint32_t offset = 0;

        if (buf == nullptr || buf_len == 0)
        {
            Log::Line(Log::WARN, "Message::Encode: Encode(%p, %u)", buf, buf_len);
            return INVALID_ARG;
        }

        // encode basemessage part of the struct
        status = BaseMessage::Encode(buf, buf_len);
        if (status < 0)
        {
            Log::Line(Log::WARN, "Message::Encode: BaseMessage::Encode failed: %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
        }

        // encode message
        status = EncodeString(buf + offset, buf_len - offset, message);
        if (status < 0)
        {
            Log::Line(Log::WARN, "Message::Encode: BaseMessage::EncodeString failed %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
        }

        // encode args
        status = EncodeBytes(buf + offset, buf_len - offset, argument, arg_len);
        if (status < 0)
        {
            Log::Line(Log::WARN, "Message::Encode: BaseMessage::EncodeString failed %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
        }

        return offset;
    }

    int Message::Decode(const unsigned char* const buf, const uint32_t buf_len)
    {
        int status = SUCCESS;
        unsigned char* str_bits = nullptr;
        unsigned char* buff = nullptr;
        uint32_t offset = 0;

        if (buf == nullptr || buf_len == 0)
        {
            Log::Line(Log::WARN, "BaseMessage::Decode: Decode(%p, %u)", buf, buf_len);
            return INVALID_ARG;
        }

        // decode the basemessage part of the struct
        status = BaseMessage::Decode(buf, buf_len);
        if (status < 0)
        {
            Log::Line(Log::WARN, "Message::Decode: BaseMessage::Decode failed: %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
        }

        // cast of the constness of buff. It's const in the header to show it won't be changed,
        // but it needs to be non-const for later casts
        buff = const_cast<unsigned char*>(buf);
        if (buff == nullptr)
        {
            Log::Line(Log::EMERG, "Message::Decode: reinterpet_cast failed.");
            return GENERAL_FAILURE;
        }

        // decode message
        status = DecodeString(buf + offset, buf_len - offset, message);
        if (status < 0)
        {
            Log::Line(Log::WARN, "Message::Decode: BaseMessage::DecodeString failed %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
        }

        // decode args length
        status = DecodeUint32_t(buf + offset, buf_len - offset, arg_len);
        if (status < 0)
        {
            Log::Line(Log::WARN, "Message:::Decode: BaseMessage::DecodeUint32_t failed %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
            status = SUCCESS;
        }

        // decode args
        if (buf_len < offset + arg_len)
        {
            Log::Line(Log::WARN, "Message::Decode: Given a buf too short: buf_len %u < offset %u + arg_len %u", buf_len, offset, arg_len);
            return BUFFER_TOO_SMALL;
        }
        str_bits = buff + offset;
        argument = (unsigned char*)malloc(arg_len);
        if (argument == nullptr)
        {
            Log::Line(Log::EMERG, "Message::Decode: malloc failed");
            return MALLOC_FAILURE;
        }
        memcpy(argument, str_bits, arg_len);
        offset += arg_len;

        return offset;
    }

    int Message::EncodedLength() const
    {
        return BaseMessage::EncodedLength() + 4 + message.size() + 4 + arg_len;
    }

    Message::Message()
        : BaseMessage()
    {
        type = MESSAGE;
        argument = nullptr;
    }

    Message::Message(const unsigned char* const arg, const uint32_t arg_size)
        : Message()
    {
        if (arg == nullptr || arg_size == 0)
        {
            argument = nullptr;
            arg_len = 0;
            return;
        }

        argument = (unsigned char*)malloc(arg_size);
        if (argument == nullptr)
        {
            Log::Line(Log::EMERG, "Message::Message: malloc failed.");
            arg_len = 0;
        }
        else
        {
            memcpy(argument, arg, arg_size);
            arg_len = arg_size;
        }
    }

    Message::Message(const Message& other)
    {
        type = other.type;
        to = other.to;
        from = other.from;
        msg_id = other.msg_id;
        message = other.message;
        arg_len = other.arg_len;

        argument = (unsigned char*) malloc(arg_len);
        if (argument == nullptr)
        {
            Log::Line(Log::EMERG, "Message::Message(const Message&): malloc failed!");
            return;
        }

        memcpy(argument, other.argument, arg_len);
    }

    Message::~Message()
    {
        free(argument);
    }

    Message& Message::operator=(const Message& rhs)
    {
        type = rhs.type;
        to = rhs.to;
        from = rhs.from;
        msg_id = rhs.msg_id;
        message = rhs.message;
        arg_len = rhs.arg_len;

        argument = (unsigned char*) malloc(arg_len);
        if (argument == nullptr)
        {
            Log::Line(Log::EMERG, "Message::operator=(const Message&): malloc failed!");
            return *this;;
        }

        memcpy(argument, rhs.argument, arg_len);
        return *this;
    }

    NamespaceCertificate::NamespaceCertificate()
        : BaseMessage()
    {
       type = NAMESPACE_CERTIFICATE;
    }

    AccessControlList::AccessControlList()
        : BaseMessage()
    {
        type = ACCESS_CONTROL_LIST;
    }

    int NamespaceCertificate::Encode(unsigned char* const buf, const uint32_t buf_len) const
    {
        int status = SUCCESS;
        uint32_t offset = 0;

        if (buf == nullptr || buf_len == 0)
        {
            Log::Line(Log::WARN, "NamespaceCertificate::Encode: Encode(%p, %u)", buf, buf_len);
            return INVALID_ARG;
        }

        // encode basemessage part of the struct
        status = BaseMessage::Encode(buf, buf_len);
        if (status < 0)
        {
            Log::Line(Log::WARN, "NamespaceCertificate::Encode: BaseMessage::Encode failed: %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
        }

        // encode id
        status = EncodeString(buf + offset, buf_len - offset, id);
        if (status < 0)
        {
            Log::Line(Log::WARN, "NamespaceCertificate::Encode: BaseMessage::EncodeString failed %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
        }

        // encode description
        status = EncodeString(buf + offset, buf_len - offset, description);
        if (status < 0)
        {
            Log::Line(Log::WARN, "NamespaceCertificate::Encode: BaseMessage::EncodeString failed %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
        }

        // encode address
        status = EncodeString(buf + offset, buf_len - offset, address);
        if (status < 0)
        {
            Log::Line(Log::WARN, "NamespaceCertificate::Encode: BaseMessage::EncodeString failed %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
        }

        // encode port
        status = EncodeString(buf + offset, buf_len - offset, port);
        if (status < 0)
        {
            Log::Line(Log::WARN, "NamespaceCertificate::Encode: BaseMessage::EncodeString failed %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
        }

        return offset;
    }

    int NamespaceCertificate::Decode(const unsigned char* const buf, const uint32_t buf_len)
    {
        int status = SUCCESS;
        uint32_t offset = 0;

        if (buf == nullptr || buf_len == 0)
        {
            Log::Line(Log::WARN, "NamespaceCertificate::Decode: Decode(%p, %u)", buf, buf_len);
            return INVALID_ARG;
        }

        // decode basemessage part of the struct
        status = BaseMessage::Decode(buf, buf_len);
        if (status < 0)
        {
            Log::Line(Log::WARN, "NamespaceCertificate::Decode: BaseMessage::Decode failed: %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
        }

        // decode id
        status = DecodeString(buf + offset, buf_len - offset, id);
        if (status < 0)
        {
            Log::Line(Log::WARN, "NamespaceCertificate::Decode: BaseMessage::DecodeString failed %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
        }

        // decode description
        status = DecodeString(buf + offset, buf_len - offset, description);
        if (status < 0)
        {
            Log::Line(Log::WARN, "NamespaceCertificate::Decode: BaseMessage::DecodeString failed %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
        }

        // decode address
        status = DecodeString(buf + offset, buf_len - offset, address);
        if (status < 0)
        {
            Log::Line(Log::WARN, "NamespaceCertificate::Decode: BaseMessage::DecodeString failed %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
        }

        // decode port
        status = DecodeString(buf + offset, buf_len - offset, port);
        if (status < 0)
        {
            Log::Line(Log::WARN, "NamespaceCertificate::Decode: BaseMessage::DecodeString failed %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
        }

        return offset;
    }

    int NamespaceCertificate::EncodedLength() const
    {
        return BaseMessage::EncodedLength() + 4 + id.size() + 4 + description.size() + 4 + address.size() + 4 + port.size();
    }

    int AccessControlList::Encode(unsigned char* const buf, const uint32_t buf_len) const
    {
        int status = SUCCESS;
        uint32_t offset = 0;

        if (buf == nullptr || buf_len == 0)
        {
            Log::Line(Log::WARN, "AccessControlList::Encode: Encode(%p, %u)", buf, buf_len);
            return INVALID_ARG;
        }

        // encode basemessage part of the struct
        status = BaseMessage::Encode(buf, buf_len);
        if (status < 0)
        {
            Log::Line(Log::WARN, "AccessControlList::Encode: BaseMessage::Encode failed: %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
            status = SUCCESS;
        }

        // encode id
        status = EncodeString(buf + offset, buf_len - offset, id);
        if (status < 0)
        {
            Log::Line(Log::WARN, "AccessControlList::Encode: BaseMessage::EncodeString failed: %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
            status = SUCCESS;
        }

        // encode number of strings
        status = EncodeUint32_t(buf + offset, buf_len - offset, rules.size());
        if (status < 0)
        {
            Log::Line(Log::WARN, "AccessControlList::Encode: BaseMessage::EncodeUint32_t failed: %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
            status = SUCCESS;
        }

        // encode each string in the rules
        for (unsigned int i = 0; i < rules.size(); ++i)
        {
            status = EncodeString(buf + offset, buf_len - offset, rules[i]);
            if (status < 0)
            {
                Log::Line(Log::WARN, "AccessControlList::Encode: BaseMessage::EncodeString failed: %s", GetErrorDescription(status));
                return status;
            }
            else
            {
                offset += status;
                status = SUCCESS;
            }
        }

        return offset;
    }

    int AccessControlList::Decode(const unsigned char* const buf, const uint32_t buf_len)
    {
        int status = SUCCESS;
        uint32_t offset = 0;
        std::string single_rule;
        uint32_t num_rules = 0;

        if (buf == nullptr || buf_len == 0)
        {
            Log::Line(Log::WARN, "AccessControlList::Decode: Decode(%p, %u)", buf, buf_len);
            return INVALID_ARG;
        }

        // decode basemessage part of the struct
        status = BaseMessage::Decode(buf, buf_len);
        if (status < 0)
        {
            Log::Line(Log::WARN, "AccessControlList::Decode: BaseMessage::Decode failed: %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
            status = SUCCESS;
        }

        // decode the id
        status = DecodeString(buf + offset, buf_len - offset, id);
        if (status < 0)
        {
            Log::Line(Log::WARN, "AccessControlList::Decode: BaseMessage::DecodeString failed: %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
            status = SUCCESS;
        }

        // decode number of strings
        status = DecodeUint32_t(buf + offset, buf_len - offset, num_rules);
        if (status < 0)
        {
            Log::Line(Log::WARN, "AccessControlList::Decode: BaseMessage::DecodeUint32_t failed: %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
            status = SUCCESS;
        }

        // decode each string in the rules
        for (unsigned int i = 0; i < num_rules; ++i)
        {
            status = DecodeString(buf + offset, buf_len - offset, single_rule);
            if (status < 0)
            {
                Log::Line(Log::WARN, "AccessControlList::Decode: BaseMessage::DecodeString failed: %s", GetErrorDescription(status));
                return status;
            }
            else
            {
                offset += status;
                status = SUCCESS;
                rules.push_back(single_rule);
            }
        }

        return offset;
    }

    int AccessControlList::EncodedLength() const
    {
        int length = 0;

        length = BaseMessage::EncodedLength();

        // id
        length += 4 + id.size();

        // rules
        length += 4;
        for (unsigned int i = 0; i < rules.size(); ++i)
        {
            length += 4 + rules[i].size();
        }

        return length;
    }

    AesKeyMessage::AesKeyMessage() : BaseMessage()
    {
        type = AES_KEY_MESSAGE;
        key = nullptr;
        key_len = 0;
        iv = nullptr;
        iv_len = 0;
    }

    AesKeyMessage::AesKeyMessage(const unsigned char* const _key, const uint32_t _key_len, const unsigned char* const _iv, const uint32_t _iv_len)
        : BaseMessage()
    {
        key = (unsigned char*)malloc(_key_len);
        if (key == nullptr)
        {
            Log::Line(Log::EMERG, "AesKeyMessage::AesKeyMessage: malloc failed on key");
            return;
        }
        key_len = _key_len;
        memcpy(key, _key, _key_len);

        iv = (unsigned char*)malloc(_iv_len);
        if (iv == nullptr)
        {
            Log::Line(Log::EMERG, "AesKeyMessage::AesKeyMessage: malloc failed on iv");
            return;
        }
        iv_len = _iv_len;
        memcpy(iv, _iv, _iv_len);
    }

    AesKeyMessage::~AesKeyMessage()
    {
        free(key);
        free(iv);
    }

    AesKeyMessage& AesKeyMessage::operator=(const AesKeyMessage& rhs)
    {
        type = rhs.type;
        to = rhs.to;
        from = rhs.from;
        msg_id = rhs.msg_id;
        key_len = rhs.key_len;
        iv_len = rhs.iv_len;

        key = (unsigned char*) malloc(key_len);
        if (key == nullptr)
        {
            Log::Line(Log::EMERG, "Message::operator=(const Message&): malloc failed!");
            return *this;
        }
        memcpy(key, rhs.key, key_len);

        iv = (unsigned char*) malloc(iv_len);
        if (iv == nullptr)
        {
            Log::Line(Log::EMERG, "Message::operator=(const Message&): malloc failed!");
            return *this;
        }
        memcpy(iv, rhs.iv, iv_len);

        return *this;
    }

    int AesKeyMessage::Encode(unsigned char* const buf, const uint32_t buf_len) const
    {
        int status = SUCCESS;
        uint32_t offset = 0;

        if (buf == nullptr || buf_len == 0)
        {
            Log::Line(Log::WARN, "AesKeyMessage::Encode: Encode(%p, %u)", buf, buf_len);
            return INVALID_ARG;
        }

        // encode basemessage part of the struct
        status = BaseMessage::Encode(buf, buf_len);
        if (status < 0)
        {
            Log::Line(Log::WARN, "AesKeyMessage::Encode: BaseMessage::Encode failed: %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
        }

        // encode key
        status = EncodeBytes(buf + offset, buf_len - offset, key, key_len);
        if (status < 0)
        {
            Log::Line(Log::WARN, "AesKeyMessage::Encode: BaseMessage::EncodeString failed %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
        }

        // encode iv
        status = EncodeBytes(buf + offset, buf_len - offset, iv, iv_len);
        if (status < 0)
        {
            Log::Line(Log::WARN, "AesKeyMessage::Encode: BaseMessage::EncodeString failed %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
        }

        return offset;
    }

    int AesKeyMessage::Decode(const unsigned char* const buf, const uint32_t buf_len)
    {
        int status = SUCCESS;
        unsigned char* str_bits = nullptr;
        unsigned char* buff = nullptr;
        uint32_t offset = 0;

        if (buf == nullptr || buf_len == 0)
        {
            Log::Line(Log::WARN, "AesKeyMessage::Decode: Decode(%p, %u)", buf, buf_len);
            return INVALID_ARG;
        }

        // decode the basemessage part of the struct
        status = BaseMessage::Decode(buf, buf_len);
        if (status < 0)
        {
            Log::Line(Log::WARN, "AesKeyMessage::Decode: BaseMessage::Decode failed: %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
        }

        // cast of the constness of buff. It's const in the header to show it won't be changed,
        // but it needs to be non-const for later casts
        buff = const_cast<unsigned char*>(buf);
        if (buff == nullptr)
        {
            Log::Line(Log::EMERG, "AesKeyMessage::Decode: reinterpet_cast failed.");
            return GENERAL_FAILURE;
        }

        // decode key_len
        status = DecodeUint32_t(buf + offset, buf_len - offset, key_len);
        if (status < 0)
        {
            Log::Line(Log::WARN, "AesKeyMessage:::Decode: BaseMessage::DecodeUint32_t failed %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
            status = SUCCESS;
        }

        // decode key
        if (buf_len < offset + key_len)
        {
            Log::Line(Log::WARN, "AesKeyMessage::Decode: Given a buf too short: buf_len %u < offset %u + arg_len %u", buf_len, offset, key_len);
            return BUFFER_TOO_SMALL;
        }
        str_bits = buff + offset;
        key = (unsigned char*)malloc(key_len);
        if (key == nullptr)
        {
            Log::Line(Log::EMERG, "AesKeyMessage::Decode: malloc failed");
            return MALLOC_FAILURE;
        }
        memcpy(key, str_bits, key_len);
        offset += key_len;

        // decode iv_len
        status = DecodeUint32_t(buf + offset, buf_len - offset, iv_len);
        if (status < 0)
        {
            Log::Line(Log::WARN, "AesKeyMessage:::Decode: BaseMessage::DecodeUint32_t failed %s", GetErrorDescription(status));
            return status;
        }
        else
        {
            offset += status;
            status = SUCCESS;
        }

        // decode key
        if (buf_len < offset + iv_len)
        {
            Log::Line(Log::WARN, "AesKeyMessage::Decode: Given a buf too short: buf_len %u < offset %u + arg_len %u", buf_len, offset, iv_len);
            return BUFFER_TOO_SMALL;
        }
        str_bits = buff + offset;
        iv = (unsigned char*)malloc(iv_len);
        if (key == nullptr)
        {
            Log::Line(Log::EMERG, "AesKeyMessage::Decode: malloc failed");
            return MALLOC_FAILURE;
        }
        memcpy(iv, str_bits, iv_len);
        offset += iv_len;

        return offset;
    }

    int AesKeyMessage::EncodedLength() const
    {
        return BaseMessage::EncodedLength() + 4 + key_len + 4 + iv_len;
    }
}
