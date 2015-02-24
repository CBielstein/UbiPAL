// Cameron Bielstein, 1/20/15
// ubipal_service_tests.cpp
// Unit tests for .h & error.cpp for UbiPAL

// Header
#include "ubipal_service_tests.h"

// tested code
#include "../src/ubipal_service.h"

// Ubipal
#include "test_helpers.h"
#include "../src/error.h"
#include "../src/rsa_wrappers.h"

// Standard
#include <string.h>

namespace UbiPAL
{
    int UbipalServiceTests::UbipalServiceTestDefaultConstructor()
    {
        UbipalService us;

        if (us.private_key == nullptr || us.unicast_fd <= 0 || us.port.empty() || us.address.empty() || us.receiving || us.id.empty() || us.broadcast_fd == 0 || us.unicast_fd == 0)
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestDefaultConstructor: Constructor failed to initialize all fields: private_key = %p, unicast_fd = %d, port = %s, address = %s, receiving = %d, id = %s, broadcast_fd = %d, unicast_fd = %d\n",
                    us.private_key, us.unicast_fd, us.port.c_str(), us.address.c_str(), us.receiving, us.id.c_str(), us.broadcast_fd, us.unicast_fd);
            return GENERAL_FAILURE;
        }

        return SUCCESS;
    }

    int UbipalServiceTests::UbipalServiceTestConstructor()
    {
        int status = SUCCESS;
        RSA* test_key = nullptr;
        std::string port("1337");
        UbipalService* us = nullptr;

        // create rsa key
        status = RsaWrappers::GenerateRsaKey(test_key);
        if (status != SUCCESS)
        {
            goto exit;
        }

        us = new UbipalService(test_key, port.c_str());
        if (us == nullptr)
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestConstructor: new failed\n");
            status = MALLOC_FAILURE;
            goto exit;
        }

        if (us->private_key == nullptr || us->unicast_fd <= 0 || us->port.empty() || us->address.empty() || us->receiving || us->id.empty())
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestConstructor: Constructor failed to initialize all fields: private_key = %p, unicast_fd = %d, port = %s, address = %s, receiving = %d, id= %s\n",
                    us->private_key, us->unicast_fd, us->port.c_str(), us->address.c_str(), us->receiving, us->id.c_str());
            status = GENERAL_FAILURE;
            goto exit;
        }

        if (RsaWrappers::KeysEqual(us->private_key, test_key) != 1)
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestConstructor: Keys don't match.\n");
            status = GENERAL_FAILURE;
            goto exit;
        }

        if (us->private_key == test_key)
        {
            fprintf(stderr, "UbipalSErviceTests::UbipalServiceTestConstructor: Keys are same pointer.\n");
            status = GENERAL_FAILURE;
            goto exit;
        }

        if (port.compare(us->port) != 0)
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestConstructor: Ports don't match.\n");
            status = GENERAL_FAILURE;
            goto exit;
        }

        exit:
            delete us;
            RSA_free(test_key);
            return status;
    }

    int UbipalServiceTests::UbipalServiceTestConstructorNullNonnull()
    {
        int status = SUCCESS;
        std::string port("1337");
        UbipalService* us = nullptr;

        us = new UbipalService(NULL, port.c_str());
        if (us == nullptr)
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestConstructorNullNonnull: new failed\n");
            status = MALLOC_FAILURE;
            goto exit;
        }

        if (us->private_key == nullptr || us->unicast_fd <= 0 || us->port.empty() || us->address.empty() || us->receiving || us->id.empty())
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestConstructorNullNonnull: Constructor failed to initialize all fields: private_key = %p, unicast_fd = %d, port = %s, address = %s, receiving = %d, id = %s\n",
                    us->private_key, us->unicast_fd, us->port.c_str(), us->address.c_str(), us->receiving, us->id.c_str());
            status = GENERAL_FAILURE;
            goto exit;
        }

        if (RSA_check_key(us->private_key) != 1)
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestConstructorNullNonnull: Invalid private key.\n");
            status = GENERAL_FAILURE;
            goto exit;
        }

        if (port.compare(us->port) != 0)
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestConstructor: Ports don't match.\n");
            status = GENERAL_FAILURE;
            goto exit;
        }

        exit:
            delete us;
            return status;
    }

    int UbipalServiceTests::UbipalServiceTestConstructorNonnullNull()
    {
        int status = SUCCESS;
        RSA* test_key = nullptr;
        UbipalService* us = nullptr;

        // create rsa key
        status = RsaWrappers::GenerateRsaKey(test_key);
        if (status != SUCCESS)
        {
            goto exit;
        }

        us = new UbipalService(test_key, nullptr);
        if (us == nullptr)
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestConstructorNonnullNull: new failed\n");
            status = MALLOC_FAILURE;
            goto exit;
        }

        if (us->private_key == nullptr || us->unicast_fd <= 0 || us->port.empty() || us->address.empty() || us->receiving || us->id.empty())
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestConstructorNonnullNull: Constructor failed to initialize all fields: private_key = %p, unicast_fd = %d, port = %s, address = %s, receiving = %d, id = %s\n",
                    us->private_key, us->unicast_fd, us->port.c_str(), us->address.c_str(), us->receiving, us->id.c_str());
            status = GENERAL_FAILURE;
            goto exit;
        }

        if (RsaWrappers::KeysEqual(us->private_key, test_key) != 1)
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestConstructor: Keys don't match.\n");
            status = GENERAL_FAILURE;
            goto exit;
        }

        if (us->private_key == test_key)
        {
            fprintf(stderr, "UbipalSErviceTests::UbipalServiceTestConstructor: Keys are same pointer.\n");
            status = GENERAL_FAILURE;
            goto exit;
        }

        exit:
            delete us;
            RSA_free(test_key);
            return status;
    }

    int UbipalServiceTests::UbipalServiceTestEndRecv()
    {
        int status = SUCCESS;

        UbipalService us;
        us.receiving = true;

        status = us.EndRecv();

        if (status != SUCCESS)
        {
            return status;
        }
        else if (us.receiving == true)
        {
            return GENERAL_FAILURE;
        }
        else
        {
            return SUCCESS;
        }
    }

    int UbipalServiceTests::UbipalServiceTestSetAddress()
    {
        int status = SUCCESS;

        UbipalService us;

        std::string test_string("cheese.com");
        status = us.SetAddress(test_string);
        if (status != SUCCESS || test_string.compare(us.address) != 0)
        {
            return GENERAL_FAILURE;
        }

        return status;
    }

    int UbipalServiceTests::UbipalServiceTestSetPort()
    {
        int status = SUCCESS;

        UbipalService us;

        std::string test_string("1234");
        status = us.SetPort(test_string);
        if (status != SUCCESS || test_string.compare(us.port) != 0)
        {
            return GENERAL_FAILURE;
        }

        return status;
    }

    int test_callback(UbipalService* us, Message message)
    {
        return SUCCESS;
    }

    int UbipalServiceTests::UbipalServiceTestRegisterCallback()
    {
        int status = SUCCESS;
        UbipalService us;

        std::string test_message("test_message");

        status = us.RegisterCallback(test_message, test_callback);
        if (status != SUCCESS)
        {
            return status;
        }

        std::unordered_map<std::string, UbipalCallback>::const_iterator returned_itr = us.callback_map.find(test_message);

        if (returned_itr->second != test_callback)
        {
            return GENERAL_FAILURE;
        }

        return status;
    }

    int test_callback2(UbipalService* us, Message message)
    {
        return SUCCESS + 1;
    }

    int UbipalServiceTests::UbipalServiceTestRegisterCallbackUpdate()
    {
        int status = SUCCESS;
        UbipalService us;

        std::string test_message("test_message");

        status = us.RegisterCallback(test_message, test_callback);
        if (status != SUCCESS)
        {
            return status;
        }

        std::unordered_map<std::string, UbipalCallback>::const_iterator returned_itr = us.callback_map.find(test_message);

        if (returned_itr->second != test_callback)
        {
            return GENERAL_FAILURE;
        }

        status = us.RegisterCallback(test_message, test_callback2);
        if (status != SUCCESS)
        {
            return status;
        }

        if (returned_itr->second == test_callback || returned_itr->second != test_callback2)
        {
            return GENERAL_FAILURE;
        }

        return status;
    }

    int UbipalServiceTests::UbipalServiceTestSetDescription()
    {
        int status = SUCCESS;
        std::string desc("Go Seahawks!");

        UbipalService us;

        status = us.SetDescription(desc);
        if (status != SUCCESS)
        {
            return status;
        }
        else if (us.description.empty() || us.description.compare(desc) != 0)
        {
            return GENERAL_FAILURE;
        }

        return status;
    }

    int UbipalServiceTests::UbipalServiceTestSaveReadFile()
    {
        int status = SUCCESS;
        int returned_value = 0;
        UbipalService us1;
        std::string line("test_save_service");

        status = us1.SaveService(line);
        if (status != SUCCESS);
        {
            remove(line.c_str());
            return status;
        }

        UbipalService us2(line);

        returned_value = RsaWrappers::KeysEqual(us1.private_key, us2.private_key);
        if (returned_value == 0)
        {
            remove(line.c_str());
            return GENERAL_FAILURE;
        }
        else if (returned_value < 0)
        {
            remove(line.c_str());
            return returned_value;
        }

        if (us1.port != us2.port)
        {
            remove(line.c_str());
            return GENERAL_FAILURE;
        }

        remove(line.c_str());
        return status;
    }

    int UbipalServiceTests::UbipalServiceTestConditionParse()
    {
        int status = SUCCESS;
        std::vector<std::string> conds;
        UbipalService us;

        std::string rule = "alice can send OPEN to bob_door if bob_house confirms IS_PRESENT(bob)";
        status = us.GetConditionsFromRule(rule, conds);
        if (conds.size() != 1)
        {
            return GENERAL_FAILURE;
        }
        if (conds[0] != std::string("bob_house confirms IS_PRESENT(bob)"))
        {
            return GENERAL_FAILURE;
        }

        conds.clear();
        rule += ", bob_clock confirms TIME_IS(12:00)";
        status = us.GetConditionsFromRule(rule, conds);
        if (conds.size() != 2)
        {
            return GENERAL_FAILURE;
        }
        if (conds[0] != std::string("bob_house confirms IS_PRESENT(bob)") || conds[1] != std::string("bob_clock confirms TIME_IS(12:00)"))
        {
            return GENERAL_FAILURE;
        }

        return status;
    }

    void UbipalServiceTests::RunUbipalServiceTests(unsigned int& module_count, unsigned int& module_fails)
    {
        TestHelpers::RunTestFunc(UbipalServiceTestDefaultConstructor, SUCCESS,
                                 "UbipalServiceTestDefaultConstructor", module_count, module_fails);
        TestHelpers::RunTestFunc(UbipalServiceTestConstructor, SUCCESS,
                                 "UbipalServiceTestConstructor", module_count, module_fails);
        TestHelpers::RunTestFunc(UbipalServiceTestConstructorNullNonnull, SUCCESS,
                                 "UbipalServiceTestConstructorNullNonnull", module_count, module_fails);
        TestHelpers::RunTestFunc(UbipalServiceTestConstructorNonnullNull, SUCCESS,
                                 "UbipalServiceTestConstructorNonnullNull", module_count, module_fails);
        TestHelpers::RunTestFunc(UbipalServiceTestEndRecv, SUCCESS,
                                 "UbipalServiceTestEndRecv", module_count, module_fails);
        TestHelpers::RunTestFunc(UbipalServiceTestSetAddress, SUCCESS,
                                 "UbipalServiceTestSetAddress", module_count, module_fails);
        TestHelpers::RunTestFunc(UbipalServiceTestSetPort, SUCCESS,
                                 "UbipalServiceTestSetPort", module_count, module_fails);
        TestHelpers::RunTestFunc(UbipalServiceTestSetDescription, SUCCESS,
                                 "UbipalServiceTestSetDescription", module_count, module_fails);
        TestHelpers::RunTestFunc(UbipalServiceTestRegisterCallback, SUCCESS,
                                 "UbipalServiceTestRegisterCallback", module_count, module_fails);
        TestHelpers::RunTestFunc(UbipalServiceTestRegisterCallbackUpdate, SUCCESS,
                                 "UbipalServiceTestRegisterCallbackUpdate", module_count, module_fails);
        TestHelpers::RunTestFunc(UbipalServiceTestSaveReadFile, SUCCESS,
                                 "UbipalServiceTestSaveReadFile", module_count, module_fails);
        TestHelpers::RunTestFunc(UbipalServiceTestConditionParse, SUCCESS,
                                 "UbipalServiceTestConditionParse", module_count, module_fails);
    }
}
