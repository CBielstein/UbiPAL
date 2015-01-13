// Cameron Bielstein, 1/1/2015 (Happy New Year!)
// error.h
// Includes error return codes and descriptions for UbiPAL

#ifndef UBIPAL_SRC_ERROR_H
#define UBIPAL_SRC_ERROR_H

namespace UbiPAL
{
    // Return codes
    // Note: When a code is added here, make sure to add a descrition in get_error_description in error.cpp
    // 0 is nominal, < 0 is error
    enum
    {
        SUCCESS = 0,
        GENERAL_FAILURE = -1,
        NULL_ARG = -2,
        INVALID_ARG = -3,
        OPEN_FILE_FAILED = -4,
        FAILED_FILE_WRITE = -5,
        FAILED_FILE_READ = -6,
        OPENSSL_ERROR = -7,
        MALLOC_FAILURE = -8,
        MESSAGE_TOO_LONG = -9,
    };

    // get_error_description
    // Takes error code and returns a string description of that code
    // args
    //          [IN] error_code: integer error code to be described
    // return
    //          const char*: static string description of error code
    const char* GetErrorDescription(const int& error_code);
}

#endif
