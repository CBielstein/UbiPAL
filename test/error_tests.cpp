// Cameron Bielstein, 1/2/15
// error_tests.cpp
// Unit tests for error.h & error.cpp for UbiPAL

#include "error_tests.h"

namespace UbiPAL
{
    // Simply tests returning success. This only breaks if SUCCESS is somehow hidden
    int ErrorTests::ErrorTestReturnSuccess()
    {
        return SUCCESS;
    }

    // Testing getting the string for an error code
    // This will have to be updated if the description for success is changed
    int ErrorTests::ErrorTestStringSuccess()
    {
        int status = SUCCESS;
        const char* msg = GetErrorDescription(status);
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
    int ErrorTests::ErrorTestStringInvalid()
    {
        // hex for int32 max value, should be well out of the way of error codes
        int status = 0x7FFFFFFF;
        const char* msg = GetErrorDescription(status);
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


    void ErrorTests::RunErrorTests(unsigned int& module_count, unsigned int& module_fails)
    {
        TestHelpers::RunTestFunc(ErrorTestReturnSuccess, SUCCESS,
                                 "ErrorTestReturnSuccess", module_count, module_fails);
        TestHelpers::RunTestFunc(ErrorTestStringSuccess, SUCCESS,
                                 "ErrorTestStringSuccess", module_count, module_fails);
        TestHelpers::RunTestFunc(ErrorTestStringInvalid, SUCCESS,
                                 "ErrorTestStringInvalid", module_count, module_fails);
    }
}
