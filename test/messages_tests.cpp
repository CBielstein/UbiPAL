// Cameron Bielstein, 1/2/15
// error_tests.cpp
// Unit tests for error.h & error.cpp for UbiPAL

// tested code
#include "../src/messages.h"

// test code
#include "messages_tests.h"
#include "test_helpers.h"

// ubipal
#include "../src/error.h"

// standard
#include <string>
#include <string.h>

namespace UbiPAL
{
    int MessagesTests::MessagesTestBaseMessageEncodeStringDecodeString()
    {
        int status = SUCCESS;
        std::string test_in("Super Bowl XLIX");
        std::string test_result;
        char* buf = nullptr;
        uint32_t buf_len = 0;

        buf_len = sizeof(char) * test_in.size() + 4;
        buf = (char*) malloc(buf_len);
        if (buf == nullptr)
        {
            status = MALLOC_FAILURE;
            goto exit;
        }

        status = BaseMessage::EncodeString(buf, buf_len, test_in);
        if (status < 0)
        {
            goto exit;
        }
        else
        {
            status = SUCCESS;
        }

        status = BaseMessage::DecodeString(buf, buf_len, test_result);
        if (status < 0)
        {
            goto exit;
        }
        else
        {
            status = SUCCESS;
        }

        if (test_in.compare(test_result) != 0)
        {
            status = GENERAL_FAILURE;
            goto exit;
        }
        else
        {
            status = SUCCESS;
        }

        exit:
            free(buf);
            return status;
    }

    int MessagesTests::MessagesTestBaseMessageEncodeDecode()
    {
        int status = SUCCESS;
        BaseMessage bm;
        BaseMessage bm2;
        char msg[MAX_MESSAGE_SIZE];

        bm.type = MESSAGE;
        bm.to = std::string("robert");
        bm.from = std::string("cameron");

        status = bm.Encode(msg, MAX_MESSAGE_SIZE);
        if (status < 0)
        {
            return status;
        }

        status = bm2.Decode(msg, MAX_MESSAGE_SIZE);
        if (status < 0)
        {
            return status;
        }

        if (bm.type != bm2.type || bm.to.compare(bm2.to) != 0 || bm.from.compare(bm2.from) != 0)
        {
            fprintf(stderr, "Failed comparison. types: %d == %d, to: %s == %s, from: %s == %s\n",
                    bm.type, bm2.type, bm.to.c_str(), bm2.to.c_str(), bm.from.c_str(), bm.from.c_str());
            return GENERAL_FAILURE;
        }

        return SUCCESS;
    }

    int MessagesTests::MessagesTestMessageEncodeDecode()
    {
        int status = SUCCESS;
        const char* m_arg = "please";
        Message m(m_arg, strlen(m_arg));
        Message m2;
        char msg[MAX_MESSAGE_SIZE];

        m.to = std::string("robert");
        m.from = std::string("cameron");
        m.message = std::string("door_open");

        status = m.Encode(msg, MAX_MESSAGE_SIZE);
        if (status < 0)
        {
            return status;
        }

        status = m2.Decode(msg, MAX_MESSAGE_SIZE);
        if (status < 0)
        {
            return status;
        }

        if (m.type != m2.type || m.type != MESSAGE || m2.type != MESSAGE || m.to.compare(m2.to) != 0 || m.from.compare(m2.from) != 0 ||
            m.message.compare(m2.message) != 0 || m.arg_len != m2.arg_len || memcmp(m.argument, m2.argument, m.arg_len) != 0)
        {
            fprintf(stderr, "Failed comparison. types: %d == %d, to: %s == %s, from: %s == %s, message: %s == %s, arg_len: %u == %u, argument: %s == %s\n",
                    m.type, m2.type, m.to.c_str(), m2.to.c_str(), m.from.c_str(), m.from.c_str(), m.message.c_str(), m2.message.c_str(), m.arg_len, m2.arg_len, m.argument, m2.argument);
            return GENERAL_FAILURE;
        }

        return SUCCESS;
    }

    int MessagesTests::MessagesTestMessageDefaultConstructor()
    {
        int status = SUCCESS;
        Message m;

        if (m.type != MESSAGE)
        {
            return GENERAL_FAILURE;
        }

        return status;
    }

    int MessagesTests::MessagesTestMessageConstructor()
    {
        int status = SUCCESS;
        const char* test = "I gotta say it was a good day.";
        Message m(test, strlen(test));

        if (m.type != MESSAGE || m.arg_len != strlen(test) || memcmp(test, m.argument, m.arg_len) != 0)
        {
            return GENERAL_FAILURE;
        }

        return status;
    }

    int MessagesTests::MessagesTestNamespaceCertificateEncodeDecode()
    {
        int status = SUCCESS;

        NamespaceCertificate nc;
        char* buf = nullptr;
        uint32_t buf_len = 0;
        NamespaceCertificate nc_result;

        nc.id = std::string("elynn");
        nc.description = std::string("jessica");
        nc.address = std::string("cameron");
        nc.port = std::string("#sadgrads");

        buf_len = nc.EncodedLength();
        if (buf_len < 0)
        {
            status = buf_len;
            goto exit;
        }

        buf = (char*) malloc(buf_len);
        if (buf == nullptr)
        {
            status = MALLOC_FAILURE;
            goto exit;
        }

        status = nc.Encode(buf, buf_len);
        if (status < 0)
        {
            goto exit;
        }
        else
        {
            status = SUCCESS;
        }

        status = nc_result.Decode(buf, buf_len);
        if (status < 0)
        {
            goto exit;
        }
        else
        {
            status = SUCCESS;
        }

        if (nc.id.compare(nc_result.id) != 0 ||
            nc.description.compare(nc_result.description) != 0 ||
            nc.address.compare(nc_result.address) != 0 ||
            nc.port.compare(nc_result.port) != 0 ||
            nc.type != nc_result.type ||
            nc.to.compare(nc_result.to) != 0 ||
            nc.from.compare(nc_result.from) != 0)
        {
            status = GENERAL_FAILURE;
            goto exit;
        }
        else
        {
            status = SUCCESS;
            goto exit;
        }

        exit:
            free(buf);
            return status;
    }

    int MessagesTests::MessagesTestBaseMessageEncodeUint32_tDecodeUint32_t()
    {
        int status = SUCCESS;
        char buf[UINT32_T_TEST_BUF_LEN];
        const uint32_t number = 1337;
        uint32_t result_number = 0;

        status = BaseMessage::EncodeUint32_t(buf, UINT32_T_TEST_BUF_LEN, number);
        if (status < SUCCESS)
        {
            return status;
        }

        status = BaseMessage::DecodeUint32_t(buf, UINT32_T_TEST_BUF_LEN, result_number);
        if (status < SUCCESS)
        {
            return status;
        }

        if (number == result_number)
        {
            return SUCCESS;
        }
        else
        {
            return GENERAL_FAILURE;
        }
    }

    int MessagesTests::MessagesTestAccessControlListEncodeDecode()
    {
        int status = SUCCESS;
        char* buf = nullptr;
        AccessControlList acl1;
        AccessControlList acl2;

        acl1.to = std::string("chris");
        acl1.from = std::string("shelley");

        acl1.rules.push_back("this is a test rule");
        acl1.rules.push_back("so is this");
        acl1.rules.push_back("my creativity is lagging");

        status = acl1.EncodedLength();
        if (status < 0)
        {
            goto exit;
        }

        buf = (char*) malloc(status);
        if (buf == nullptr)
        {
            status = MALLOC_FAILURE;
            goto exit;
        }

        status = acl1.Encode(buf, status);
        if (status < 0)
        {
            fprintf(stderr, "MessagesTests::MessagesTestAccessControlListDecode: acl1.Encode failed %s\n", GetErrorDescription(status));
            goto exit;
        }

        status = acl2.Decode(buf, status);
        if (status < 0)
        {
            fprintf(stderr, "MessagesTests::MessagesTestAccessControlListDecode: acl2.Decode %s\n", GetErrorDescription(status));
            goto exit;
        }


        if (acl1.type != ACCESS_CONTROL_LIST || acl1.type != acl2.type || acl1.from.compare(acl2.from) != 0 ||
            acl1.to.compare(acl2.to) != 0 || acl1.rules.size() != acl2.rules.size())
        {
            status = GENERAL_FAILURE;
            goto exit;
        }

        // check all rules
        for (unsigned int i = 0; i < acl1.rules.size(); ++i)
        {
            if (acl1.rules[i].compare(acl2.rules[i]) != 0)
            {
                status = GENERAL_FAILURE;
                goto exit;
            }
        }

        status = SUCCESS;

        exit:
            free(buf);
            return status;
    }

    void MessagesTests::RunMessagesTests(unsigned int& module_count, unsigned int& module_fails)
    {
        TestHelpers::RunTestFunc(MessagesTestBaseMessageEncodeStringDecodeString, SUCCESS,
                                 "MessagesTestBaseMessageEncodeStringDecodeString", module_count, module_fails);
        TestHelpers::RunTestFunc(MessagesTestBaseMessageEncodeUint32_tDecodeUint32_t, SUCCESS,
                                 "MessagesTestBaseMessageEncodeUint32_tDecodeUint32_t", module_count, module_fails);
        TestHelpers::RunTestFunc(MessagesTestBaseMessageEncodeDecode, SUCCESS,
                                 "MessagesTestBaseMessageEncodeDecode", module_count, module_fails);
        TestHelpers::RunTestFunc(MessagesTestMessageEncodeDecode, SUCCESS,
                                 "MessagesTestMessageEncodeDecode", module_count, module_fails);
        TestHelpers::RunTestFunc(MessagesTestNamespaceCertificateEncodeDecode, SUCCESS,
                                 "MessagesTestNamespaceCertificateEncodeDecode", module_count, module_fails);
        TestHelpers::RunTestFunc(MessagesTestMessageDefaultConstructor, SUCCESS,
                                 "MessagesTestMessageDefaultConstructor", module_count, module_fails);
        TestHelpers::RunTestFunc(MessagesTestMessageConstructor, SUCCESS,
                                 "MessagesTestMessageConstructor", module_count, module_fails);
        TestHelpers::RunTestFunc(MessagesTestAccessControlListEncodeDecode, SUCCESS,
                                 "MessagesTestAccessControlListEncodeDecode", module_count, module_fails);
    }
}
