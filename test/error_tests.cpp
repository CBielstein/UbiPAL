// Cameron Bielstein, 1/2/15
// error_tests.cpp
// Unit tests for error.h & error.cpp for UbiPAL

#include "error_tests.h"

namespace UbiPAL
{
    // Simply tests returning success. This only breaks if SUCCESS is somehow hidden
    int error_tests::error_test_return_success()
    {
        return SUCCESS;
    }

    // Testing getting the string for an error code
    // This will have to be updated if the description for success is changed
    int error_tests::error_test_string_success()
    {
        int status = SUCCESS;
        const char* msg = get_error_description(status);
        status = strcmp(msg, "SUCCESS: No errors.");
        if (status == 0)
        {
            return SUCCESS;
        }
        else
        {
            return GENERAL_FAILURE;
        }
    }

    // Testing a value that does not have a description
    // This may need to be changed over time
    int error_tests::error_test_string_invalid()
    {
        // hex for int32 max value, should be well out of the way of error codes
        int status = 0x7FFFFFFF;
        const char* msg = get_error_description(status);
        status = strcmp(msg, "Error code does not have description.");
        if (status == 0)
        {
            return SUCCESS;
        }
        else
        {
            return GENERAL_FAILURE;
        }
    }


    void error_tests::run_error_tests(unsigned int& module_count, unsigned int& module_fails)
    {
        Test_Helpers::run_test_func(error_test_return_success, SUCCESS,
                                    "error_test_return_success", module_count, module_fails);
        Test_Helpers::run_test_func(error_test_string_success, SUCCESS,
                                    "error_test_string_success", module_count, module_fails);
        Test_Helpers::run_test_func(error_test_string_invalid, SUCCESS,
                                    "error_test_string_invalid", module_count, module_fails);
    }
}
