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
        status = us.BeginRecv(UbipalService::BeginRecvFlags::NON_BLOCKING);

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
        std::vector<Statement> conds;
        UbipalService us;

        std::string rule = "alice CAN SEND MESSAGE OPEN to bob_door if bob_house CONFIRMS IS_PRESENT";
        status = us.GetConditionsFromRule(rule, conds);
        if (status != SUCCESS)
        {
            return status;
        }
        if (conds.size() != 1)
        {
            return GENERAL_FAILURE;
        }
        if (conds[0].type != Statement::Type::CONFIRMS || conds[0].name1 != "bob_house" || conds[0].name2 != "IS_PRESENT")
        {
            return GENERAL_FAILURE;
        }

        conds.clear();
        rule += ", bob_clock CONFIRMS TIME";
        status = us.GetConditionsFromRule(rule, conds);
        if (conds.size() != 2)
        {
            return GENERAL_FAILURE;
        }
        if ((conds[0].type != Statement::Type::CONFIRMS || conds[0].name1 != "bob_house" || conds[0].name2 != "IS_PRESENT") ||
            (conds[1].type != Statement::Type::CONFIRMS || conds[1].name1 != "bob_clock" || conds[1].name2 != "TIME"))
        {
            return GENERAL_FAILURE;
        }

        return status;
    }

    int UbipalServiceTests::UbipalServiceTestParseTimeDate()
    {
        int status = SUCCESS;
        UbipalService us;

        std::string future_time = "23:59";
        std::string future_date = "99999999999999999999";
        std::string past_time = "00:01";
        std::string past_date = "01";

        // Check time future pass
        status = us.EvaluateStatement("CurrentTime() < " + future_time);
        if (status != SUCCESS)
        {
            fprintf(stderr, "Failed time future pass");
            return status;
        }

        // Check time future fail
        status = us.EvaluateStatement("CurrentTime() > " + future_time);
        if (status != FAILED_EVALUATION)
        {
            fprintf(stderr, "Failed time future fail");
            return status;
        }

        // Check time past pass
        status = us.EvaluateStatement("CurrentTime() > " + past_time);
        if (status != SUCCESS)
        {
            fprintf(stderr, "Failed time past pass");
            return status;
        }

        // Check time past fail
        status = us.EvaluateStatement("CurrentTime() < " + past_time);
        if (status != FAILED_EVALUATION)
        {
            fprintf(stderr, "Failed time past fail");
            return status;
        }

        // Check date future pass
        status = us.EvaluateStatement("CurrentDate() < " + future_date);
        if (status != SUCCESS)
        {
            fprintf(stderr, "Failed date future pass");
            return status;
        }

        // Check date future fail
        status = us.EvaluateStatement("CurrentDate() > " + future_date);
        if (status != FAILED_EVALUATION)
        {
            fprintf(stderr, "Failed date future fail");
            return status;
        }

        // Check time past pass
        status = us.EvaluateStatement("CurrentDate() > " + past_date);
        if (status != SUCCESS)
        {
            fprintf(stderr, "Failed date past pass");
            return status;
        }

        // Check date past fail
        status = us.EvaluateStatement("CurrentDate() < " + past_date);
        if (status != FAILED_EVALUATION)
        {
            fprintf(stderr, "Failed date past fail");
            return status;
        }

        return SUCCESS;
    }

    int UbipalServiceTests::UbipalServiceTestDiscoverService()
    {
        int status = SUCCESS;

        UbipalService us;

        NamespaceCertificate nc;
        nc.id = "Elynn";
        us.untrusted_services["Elynn"] = nc;
        nc.id = "Jessica";
        us.untrusted_services["Jessica"] = nc;
        nc.id = "Cameron";
        us.untrusted_services["Cameron"] = nc;

        AccessControlList elynn_acl;
        elynn_acl.id = "Elynn";
        elynn_acl.from = "Elynn";
        elynn_acl.rules.push_back("Jessica CAN SEND MESSAGE Test TO Elynn");
        us.external_acls["Elynn"].push_back(elynn_acl);

        std::vector<std::string> rules;
        rules.push_back("Elynn IS A student");
        rules.push_back("Jessica IS A student");
        rules.push_back("Cameron IS A student");

        AccessControlList acl;
        status = us.CreateAcl("students", rules, acl);
        if (status != SUCCESS)
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestDiscoverService: UbipalService::CreateAcl failed: %s\n", GetErrorDescription(status));
            return status;
        }

        std::vector<std::string> statement;
        statement.push_back("X IS A student");
        std::map<std::string, std::set<std::string>> result_names;
        status = us.FindNamesForStatements(statement, result_names);
        if (status != SUCCESS)
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestDiscoverService: UbipalService::FindNamesForStatements failed: %s\n", GetErrorDescription(status));
            return status;
        }

        if (result_names.size() != 1)
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestDiscoverService: UbipalService::FindNamesForStatement returned too many variables. Should be 1, it said %lu\n",
                    result_names.size());
            return GENERAL_FAILURE;
        }
        if (result_names[std::string("X")].size() != 3)
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestDiscoverService: UbipalService::FindNamesForStatement returned too many results. Should be 3, it said %lu\n",
                    result_names[std::string("X")].size());
            return GENERAL_FAILURE;
        }
        if  (result_names[std::string("X")].count("Jessica") != 1 || result_names[std::string("X")].count("Cameron") != 1 || result_names[std::string("X")].count("Elynn") != 1)
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestDiscoverService: UbipalService::FindNamesForStatement returned invalid numbers for Jessica, Elynn, Cameron: %lu %lu %lu\n",
                    result_names[std::string("X")].count("Jessica"), result_names[std::string("X")].count("Elynn"), result_names[std::string("X")].count("Cameron"));
            return GENERAL_FAILURE;
        }

        // test no matches
        statement.clear();
        statement.push_back("X IS A professor");
        result_names.clear();
        status = us.FindNamesForStatements(statement, result_names);
        if (status != NOT_IN_ACLS)
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestDiscoverService: UbipalService::FindNamesForStatements didn't say the expected GENERAL_FAILURE: %s\n",
                    GetErrorDescription(status));
            return (status == SUCCESS) ? GENERAL_FAILURE : status;
        }

        statement.clear();
        statement.push_back("X IS A student");
        statement.push_back("X CAN SEND MESSAGE Test TO Elynn");
        result_names.clear();
        status = us.FindNamesForStatements(statement, result_names);
        if (status != SUCCESS)
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestDiscoverService: UbipalService::FindNamesForStatements failed: %s\n", GetErrorDescription(status));
            return status;
        }
        if (result_names.size() != 1)
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestDiscoverService: UbipalService::FindNamesForStatement returned too many variables. Should be 1, it said %lu\n",
                    result_names.size());
            return GENERAL_FAILURE;
        }
        if (result_names[std::string("X")].size() != 1)
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestDiscoverService: UbipalService::FindNamesForStatement returned too many results. Should be 1, it said %lu\n",
                    result_names[std::string("X")].size());
            return GENERAL_FAILURE;
        }
        if  (result_names[std::string("X")].count("Jessica") != 1)
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestDiscoverService: UbipalService::FindNamesForStatement did not include Jessica");
            return GENERAL_FAILURE;
        }

        return SUCCESS;
    }

    int UbipalServiceTests::UbipalServiceTestParseDelegation()
    {
        int status = SUCCESS;

        // create service
        UbipalService lauren;
        lauren.id = "Lauren";

        // add rules
        std::vector<std::string> rules;
        rules.push_back("Meredith CAN SAY Y CAN SEND MESSAGE TWO_STEP TO Lauren");
        rules.push_back("Josh CAN SAY Y CAN SEND MESSAGE SWING TO Lauren");
        rules.push_back("Cameron CAN SEND MESSAGE WALTZ TO Lauren");
        AccessControlList acl;
        status = lauren.CreateAcl("delegation", rules, acl);
        if (status != SUCCESS)
        {
            return status;
        }

        AccessControlList mere;
        mere.id = "Meredith";
        mere.rules.push_back("X CAN SEND MESSAGE TWO_STEP TO Lauren");
        lauren.external_acls["Meredith"].push_back(mere);

        AccessControlList josh;
        josh.id = "Josh";
        josh.rules.push_back("X CAN SEND MESSAGE POLKA TO Lauren");
        lauren.external_acls["Josh"].push_back(josh);

        // run tests
        status = lauren.EvaluateStatement("Cameron CAN SEND MESSAGE WALTZ TO Lauren", NULL);
        if (status != SUCCESS)
        {
            return status;
        }

        status = lauren.EvaluateStatement("Cameron CAN SEND MESSAGE TWO_STEP TO Lauren", NULL);
        if (status != SUCCESS)
        {
            return status;
        }

        status = lauren.EvaluateStatement("Cameron CAN SEND MESSAGE SWING TO Lauren", NULL);
        if (status != NOT_IN_ACLS)
        {
            return (status == SUCCESS) ? GENERAL_FAILURE : status;
        }

        status = lauren.EvaluateStatement("Cameron CAN SEND MESSAGE POLKA TO Lauren", NULL);
        if (status != NOT_IN_ACLS)
        {
            return (status == SUCCESS) ? GENERAL_FAILURE : status;
        }

        status = lauren.EvaluateStatement("Cameron CAN SEND MESSAGE SALSA TO Lauren", NULL);
        if (status != NOT_IN_ACLS)
        {
            return (status == SUCCESS) ? GENERAL_FAILURE : status;
        }

        return SUCCESS;
    }

    int UbipalServiceTests::UbipalServiceTestParseDelegationVariable()
    {
        int status = SUCCESS;

        // create service
        UbipalService lauren;
        lauren.id = "Lauren";

        // add rules
        std::vector<std::string> rules;
        rules.push_back("X CAN SAY Y CAN SEND MESSAGE TWO_STEP TO Lauren");
        rules.push_back("X CAN SAY Y CAN SEND MESSAGE SWING TO Lauren");
        rules.push_back("Cameron CAN SEND MESSAGE WALTZ TO Lauren");
        AccessControlList acl;
        status = lauren.CreateAcl("delegation", rules, acl);
        if (status != SUCCESS)
        {
            return status;
        }

        AccessControlList mere;
        mere.id = "Meredith";
        mere.rules.push_back("X CAN SEND MESSAGE TWO_STEP TO Lauren");
        lauren.external_acls["Meredith"].push_back(mere);

        AccessControlList josh;
        josh.id = "Josh";
        josh.rules.push_back("X CAN SEND MESSAGE POLKA TO Lauren");
        lauren.external_acls["Josh"].push_back(josh);

        // run tests
        status = lauren.EvaluateStatement("Cameron CAN SEND MESSAGE WALTZ TO Lauren", NULL);
        if (status != SUCCESS)
        {
            return status;
        }

        status = lauren.EvaluateStatement("Cameron CAN SEND MESSAGE TWO_STEP TO Lauren", NULL);
        if (status != SUCCESS)
        {
            return status;
        }

        status = lauren.EvaluateStatement("Cameron CAN SEND MESSAGE SWING TO Lauren", NULL);
        if (status != NOT_IN_ACLS)
        {
            return (status == SUCCESS) ? GENERAL_FAILURE : status;
        }

        status = lauren.EvaluateStatement("Cameron CAN SEND MESSAGE POLKA TO Lauren", NULL);
        if (status != NOT_IN_ACLS)
        {
            return (status == SUCCESS) ? GENERAL_FAILURE : status;
        }

        status = lauren.EvaluateStatement("Cameron CAN SEND MESSAGE SALSA TO Lauren", NULL);
        if (status != NOT_IN_ACLS)
        {
            return (status == SUCCESS) ? GENERAL_FAILURE : status;
        }

        return SUCCESS;
    }

    int UbipalServiceTests::UbipalServiceTestParseDelegationVariableConditions()
    {
        int status = SUCCESS;

        // create service
        UbipalService lauren;
        lauren.id = "Lauren";

        // add rules
        std::vector<std::string> rules;
        rules.push_back("X CAN SAY Y CAN SEND MESSAGE TWO_STEP TO Lauren if X IS MERE");
        rules.push_back("X CAN SAY Y CAN SEND MESSAGE SWING TO Lauren");
        rules.push_back("X CAN SAY Y CAN SEND MESSAGE SALSA TO Lauren if X IS NOBODY");
        rules.push_back("Cameron CAN SEND MESSAGE WALTZ TO Lauren");
        rules.push_back("Meredith IS MERE");
        AccessControlList acl;
        status = lauren.CreateAcl("delegation", rules, acl);
        if (status != SUCCESS)
        {
            return status;
        }

        AccessControlList mere;
        mere.id = "Meredith";
        mere.rules.push_back("X CAN SEND MESSAGE TWO_STEP TO Lauren");
        lauren.external_acls["Meredith"].push_back(mere);

        AccessControlList josh;
        josh.id = "Josh";
        josh.rules.push_back("X CAN SEND MESSAGE POLKA TO Lauren");
        lauren.external_acls["Josh"].push_back(josh);

        AccessControlList other;
        josh.id = "Other";
        josh.rules.push_back("X CAN SEND MESSAGE SALSA TO Lauren");
        lauren.external_acls["Other"].push_back(other);

        // run tests
        status = lauren.EvaluateStatement("Cameron CAN SEND MESSAGE WALTZ TO Lauren", NULL);
        if (status != SUCCESS)
        {
            return status;
        }

        status = lauren.EvaluateStatement("Cameron CAN SEND MESSAGE TWO_STEP TO Lauren", NULL);
        if (status != SUCCESS)
        {
            return status;
        }

        status = lauren.EvaluateStatement("Cameron CAN SEND MESSAGE SWING TO Lauren", NULL);
        if (status != NOT_IN_ACLS)
        {
            return (status == SUCCESS) ? GENERAL_FAILURE : status;
        }

        status = lauren.EvaluateStatement("Cameron CAN SEND MESSAGE POLKA TO Lauren", NULL);
        if (status != NOT_IN_ACLS)
        {
            return (status == SUCCESS) ? GENERAL_FAILURE : status;
        }

        status = lauren.EvaluateStatement("Cameron CAN SEND MESSAGE SALSA TO Lauren", NULL);
        if (status != NOT_IN_ACLS)
        {
            return (status == SUCCESS) ? GENERAL_FAILURE : status;
        }

        return SUCCESS;
    }

    int UbipalServiceTests::UbipalServiceTestUpperCase()
    {
        std::string upper_letters = UbipalService::UpperCase("This is A test of letters");
        if (upper_letters != std::string("THIS IS A TEST OF LETTERS"))
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestUpperCase: %s did not equal %s\n", upper_letters.c_str(), "THIS IS A TEST OF LETTERS");
            return GENERAL_FAILURE;
        }

        std::string symbols = "*909/?.<";
        std::string upper_symbols = UbipalService::UpperCase(symbols);
        if (upper_symbols != symbols)
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestUpperCase: %s did not equal %s\n", upper_symbols.c_str(), symbols.c_str());
            return GENERAL_FAILURE;
        }

        std::string mixed = "Hello? Is it M3 you're looking for?";
        std::string upper_mixed = UbipalService::UpperCase(mixed);
        if (upper_mixed != std::string("HELLO? IS IT M3 YOU'RE LOOKING FOR?"))
        {
            fprintf(stderr, "UbipalServiceTests::UbipalServiceTestUpperCase: %s did not equal %s\n", upper_mixed.c_str(), "HELLO? IS IT M3 YOU'RE LOOKING FOR?");
            return GENERAL_FAILURE;
        }

        return SUCCESS;
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
        TestHelpers::RunTestFunc(UbipalServiceTestParseTimeDate, SUCCESS,
                                 "UbipalServiceTestParseTimeDate", module_count, module_fails);
        TestHelpers::RunTestFunc(UbipalServiceTestDiscoverService, SUCCESS,
                                 "UbipalServiceTestDiscoverService", module_count, module_fails);
        TestHelpers::RunTestFunc(UbipalServiceTestParseDelegation, SUCCESS,
                                 "UbipalServiceTestParseDelegation", module_count, module_fails);
        TestHelpers::RunTestFunc(UbipalServiceTestParseDelegationVariable, SUCCESS,
                                 "UbipalServiceTestParseDelegationVariable", module_count, module_fails);
        TestHelpers::RunTestFunc(UbipalServiceTestParseDelegationVariableConditions, SUCCESS,
                                 "UbipalServiceTestParseDelegationVariableConditions", module_count, module_fails);
        TestHelpers::RunTestFunc(UbipalServiceTestUpperCase, SUCCESS,
                                 "UbipalServiceTestUpperCase", module_count, module_fails);
    }
}
