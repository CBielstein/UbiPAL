// Cameron Bielstein, 1/1/2015 (Happy New Year!)
// error.cpp
// Includes error return codes and descriptions for UbiPAL

#include "error.h"

namespace UbiPAL
{
    const char* get_error_description(const int& error_code)
    {
        switch (error_code)
        {
            case SUCCESS: return "SUCCESS: No errors.";
            case GENERAL_FAILURE: return "GENERAL_FAILURE: An error occurred.";
            case NULL_ARG: return "NULL_ARG: An argument was NULL.";
            case INVALID_ARG: return "INVALID_ARG: Invalid argument was provided.";
            default: return "Error code does not have description.";
        }
    }
}
