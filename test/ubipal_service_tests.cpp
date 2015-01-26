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

        if (us.private_key == nullptr || us.sockfd <= 0 || us.port.empty() || us.address.empty() ||  us.receiving)
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestDefaultConstructor: Constructor failed to initialize all fields: private_key = %p, sockfd = %d, port = %s, address = %s, receiving = %d\n",
                    us.private_key, us.sockfd, us.port.c_str(), us.address.c_str(), us.receiving);
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

        if (us->private_key == nullptr || us->sockfd <= 0 || us->port.empty() || us->address.empty() || us->receiving)
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestConstructor: Constructor failed to initialize all fields: private_key = %p, sockfd = %d, port = %s, address = %s, receiving = %d\n",
                    us->private_key, us->sockfd, us->port.c_str(), us->address.c_str(), us->receiving);
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

        if (us->private_key == nullptr || us->sockfd <= 0 || us->port.empty() || us->address.empty() || us->receiving)
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestConstructorNullNonnull: Constructor failed to initialize all fields: private_key = %p, sockfd = %d, port = %s, address = %s, receiving = %d\n",
                    us->private_key, us->sockfd, us->port.c_str(), us->address.c_str(), us->receiving);
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

        if (us->private_key == nullptr || us->sockfd <= 0 || us->port.empty() || us->address.empty() || us->receiving)
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestConstructorNonnullNull: Constructor failed to initialize all fields: private_key = %p, sockfd = %d, port = %s, address = %s, receiving = %d\n",
                    us->private_key, us->sockfd, us->port.c_str(), us->address.c_str(), us->receiving);
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
    }
}
