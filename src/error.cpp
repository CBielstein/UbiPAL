// Cameron Bielstein, 1/1/2015 (Happy New Year!)
// error.cpp
// Includes error return codes and descriptions for UbiPAL

// Header
#include "error.h"

namespace UbiPAL
{
    const char* GetErrorDescription(const int& error_code)
    {
        switch (error_code)
        {
            case SUCCESS: return "SUCCESS: No errors.";
            case GENERAL_FAILURE: return "GENERAL_FAILURE: An error occurred.";
            case NULL_ARG: return "NULL_ARG: An argument was NULL.";
            case INVALID_ARG: return "INVALID_ARG: Invalid argument was provided.";
            case OPEN_FILE_FAILED: return "OPEN_FILE_FAILED: A file failed to open.";
            case FAILED_FILE_WRITE: return "FAILED_FILE_WRITE: An attempted write to a file failed.";
            case FAILED_FILE_READ: return "FAILED_FILE_READ: An attempted read of a file failed.";
            case OPENSSL_ERROR: return "OPENSSL_ERROR: An error occurred inside the OpenSSL library.";
            case MALLOC_FAILURE: return "MALLOC_FAILURE: An operation (likely malloc) failed to allocate memory.";
            case MESSAGE_TOO_LONG: return "MESSAGE_TOO_LONG: The message is too long for the given RSA key to encrypt.";
            case NETWORKING_FAILURE: return "NETWORKING_FAILURE: An error occurred during networking code.";
            default: return "Error code does not have description.";
        }
    }
}
