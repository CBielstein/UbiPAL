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
        int length = 0;
        BaseMessage bm;
        BaseMessage bm2;
        char* msg = nullptr;

        bm.type = MESSAGE;
        bm.to = std::string("robert");
        bm.from = std::string("cameron");

        length = bm.EncodedLength();
        if (length < 0)
        {
            return length;
        }

        msg = (char*) malloc(length);
        if (msg == nullptr)
        {
            return MALLOC_FAILURE;
        }

        status = bm.Encode(msg, length);
        if (status < 0)
        {
            return status;
        }

        status = bm2.Decode(msg, length);
        if (status < 0)
        {
            return status;
        }

        if (bm != bm2)
        {
            return GENERAL_FAILURE;
        }

        return SUCCESS;
    }

    int MessagesTests::MessagesTestMessageEncodeDecode()
    {
        int status = SUCCESS;
        int length = 0;
        const char* m_arg = "please";
        Message m(m_arg, strlen(m_arg));
        Message m2;
        char* msg = nullptr;

        m.to = std::string("robert");
        m.from = std::string("cameron");
        m.message = std::string("door_open");

        length = m.EncodedLength();
        if (length < 0)
        {
            return length;
        }

        msg = (char*) malloc(length);
        if (msg == nullptr)
        {
            return MALLOC_FAILURE;
        }

        status = m.Encode(msg, length);
        if (status < 0)
        {
            return status;
        }

        status = m2.Decode(msg, length);
        if (status < 0)
        {
            return status;
        }

        if (m != m2)
        {
            return GENERAL_FAILURE;
        }

        return SUCCESS;
    }

    int MessagesTests::MessagesTestMessageDefaultConstructor()
    {
        int status = SUCCESS;
        Message m;

        if (m.type != MESSAGE || m.msg_id.empty())
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

        if (m.type != MESSAGE || m.arg_len != strlen(test) || memcmp(test, m.argument, m.arg_len) != 0 || m.msg_id.empty())
        {
            return GENERAL_FAILURE;
        }

        return status;
    }

    int MessagesTests::MessagesTestMessageCopyConstructor()
    {
        const char* msg = "It's all good 'til somebody catches a feeling, and I'm feeling again.";

        Message m(msg, strlen(msg));
        m.message = std::string("Good song");

        Message m2 = m;
        if (m.argument == m2.argument)
        {
            return GENERAL_FAILURE;
        }

        return (m == m2) ? SUCCESS : GENERAL_FAILURE;
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

        if (nc != nc_result)
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
        int length = 0;
        char* buf = nullptr;
        AccessControlList acl1;
        AccessControlList acl2;

        acl1.to = std::string("chris");
        acl1.from = std::string("shelley");

        acl1.rules.push_back("this is a test rule");
        acl1.rules.push_back("so is this");
        acl1.rules.push_back("my creativity is lagging");

        length = acl1.EncodedLength();
        if (length < 0)
        {
            status = length;
            goto exit;
        }

        buf = (char*) malloc(length);
        if (buf == nullptr)
        {
            status = MALLOC_FAILURE;
            goto exit;
        }

        status = acl1.Encode(buf, length);
        if (status < 0)
        {
            fprintf(stderr, "MessagesTests::MessagesTestAccessControlListDecode: acl1.Encode failed %s\n", GetErrorDescription(status));
            goto exit;
        }

        status = acl2.Decode(buf, length);
        if (status < 0)
        {
            fprintf(stderr, "MessagesTests::MessagesTestAccessControlListDecode: acl2.Decode %s\n", GetErrorDescription(status));
            goto exit;
        }


        if (acl1 != acl2)
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

    int MessagesTests::MessagesTestAccessControlListDefaultConstructor()
    {
        AccessControlList acl;
        if (acl.type == ACCESS_CONTROL_LIST && !acl.msg_id.empty())
        {
            return SUCCESS;
        }
        else
        {
            return GENERAL_FAILURE;
        }
    }

    int MessagesTests::MessagesTestBaseMessageDefaultConstructor()
    {
        BaseMessage bm;

        if (bm.msg_id.empty() || bm.msg_id.size() != 36)
        {
            return GENERAL_FAILURE;
        }
        else
        {
            return SUCCESS;
        }
    }

    int MessagesTests::MessagesTestBaseMessageEqualityTestPass()
    {
        BaseMessage bm1;
        bm1.type = 1;
        bm1.to = std::string("lauren");
        bm1.from = std::string("meredith");

        BaseMessage bm2 = bm1;

        return (bm1 == bm2) ? SUCCESS : GENERAL_FAILURE;
    }

    int MessagesTests::MessagesTestBaseMessageEqualityTestFail()
    {
        BaseMessage bm1;
        bm1.type = 1;
        bm1.to = std::string("lauren");
        bm1.from = std::string("meredith");

        BaseMessage bm2 = bm1;

        bm2.from = std::string("jonathan");

        return (bm1 != bm2) ? SUCCESS : GENERAL_FAILURE;
    }

    int MessagesTests::MessagesTestMessageEqualityTestPass()
    {
        const char* arg = "Let's get it started in here!";
        Message m(arg, strlen(arg));
        m.message = std::string("Let's get it started in ha");

        Message m2 = m;

        return (m == m2) ? SUCCESS : GENERAL_FAILURE;
    }

    int MessagesTests::MessagesTestMessageEqualityTestFail()
    {
        const char* arg = "Let's get it started in here!";
        Message m(arg, strlen(arg));
        m.message = std::string("Let's get it started in ha");

        Message m2 = m;

        m.from = std::string("fail!!");

        return (m != m2) ? SUCCESS : GENERAL_FAILURE;
    }

    int MessagesTests::MessagesTestNamespaceCertificateEqualityTestPass()
    {
        NamespaceCertificate nc;

        nc.id = std::string("NASA");
        nc.description = std::string("She blinded me with science.");
        nc.address = std::string("Houston, Texas");
        nc.port = std::string("Cape Canaveral, Florida");

        NamespaceCertificate nc2 = nc;

        return (nc == nc2) ? SUCCESS : GENERAL_FAILURE;
    }

    int MessagesTests::MessagesTestNamespaceCertificateEqualityTestFail()
    {
         NamespaceCertificate nc;

        nc.id = std::string("NASA");
        nc.description = std::string("She blinded me with science.");
        nc.address = std::string("Houston, Texas");
        nc.port = std::string("Cape Canaveral, Florida");

        NamespaceCertificate nc2 = nc;

        nc2.port = std::string("We have a problem.");

        return (nc != nc2) ? SUCCESS : GENERAL_FAILURE;
    }

    int MessagesTests::MessagesTestAccessControlListEqualityTestPass()
    {
        std::vector<std::string> rules_vector;
        rules_vector.push_back(std::string("This is the end."));
        rules_vector.push_back(std::string("Close your eyes and count to ten."));

        AccessControlList acl1;
        acl1.rules = rules_vector;
        acl1.id = std::string("Skyfall");

        AccessControlList acl2 = acl1;

        return (acl1 == acl2) ? SUCCESS : GENERAL_FAILURE;
    }

    int MessagesTests::MessagesTestAccessControlListEqualityTestFail()
    {
        std::vector<std::string> rules_vector;
        std::vector<std::string> rules_vector2;
        rules_vector.push_back(std::string("This is the end."));
        rules_vector.push_back(std::string("Close your eyes and count to ten."));

        rules_vector2.push_back(std::string("Close your eyes and count to ten."));
        rules_vector2.push_back(std::string("This is the end."));

        AccessControlList acl1;
        acl1.rules = rules_vector;
        acl1.id = std::string("Skyfall");

        AccessControlList acl2 = acl1;

        acl2.rules = rules_vector2;

        return (acl1 != acl2) ? SUCCESS : GENERAL_FAILURE;
    }

    void MessagesTests::RunMessagesTests(unsigned int& module_count, unsigned int& module_fails)
    {
        TestHelpers::RunTestFunc(MessagesTestBaseMessageDefaultConstructor, SUCCESS,
                                 "MessagesTestBaseMessageDefaultConstructor", module_count, module_fails);
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
        TestHelpers::RunTestFunc(MessagesTestMessageCopyConstructor, SUCCESS,
                                 "MessagesTestMessageCopyConstructor", module_count, module_fails);
        TestHelpers::RunTestFunc(MessagesTestAccessControlListEncodeDecode, SUCCESS,
                                 "MessagesTestAccessControlListEncodeDecode", module_count, module_fails);
        TestHelpers::RunTestFunc(MessagesTestAccessControlListDefaultConstructor, SUCCESS,
                                 "MessagesTestAccessControlListDefaultConstructor", module_count, module_fails);
        TestHelpers::RunTestFunc(MessagesTestBaseMessageEqualityTestPass, SUCCESS,
                                 "MessagesTestBaseMessageEqualityTestPass", module_count, module_fails);
        TestHelpers::RunTestFunc(MessagesTestBaseMessageEqualityTestFail, SUCCESS,
                                 "MessagesTestBaseMessageEqualityTestFail", module_count, module_fails);
        TestHelpers::RunTestFunc(MessagesTestMessageEqualityTestPass, SUCCESS,
                                 "MessagesTestMessageEqualityTestPass", module_count, module_fails);
        TestHelpers::RunTestFunc(MessagesTestMessageEqualityTestFail, SUCCESS,
                                 "MessagesTestMessageEqualityTestFail", module_count, module_fails);
        TestHelpers::RunTestFunc(MessagesTestNamespaceCertificateEqualityTestPass, SUCCESS,
                                 "MessagesTestNamespaceCertificateEqualityTestPass", module_count, module_fails);
        TestHelpers::RunTestFunc(MessagesTestNamespaceCertificateEqualityTestFail, SUCCESS,
                                 "MessagesTestNamespaceCertificateEqualityTestFail", module_count, module_fails);
        TestHelpers::RunTestFunc(MessagesTestAccessControlListEqualityTestPass, SUCCESS,
                                 "MessagesTestAccessControlListEqualityTestPass", module_count, module_fails);
        TestHelpers::RunTestFunc(MessagesTestAccessControlListEqualityTestFail, SUCCESS,
                                 "MessagesTestAccessControlListEqualityTestFail", module_count, module_fails);
    }
}
