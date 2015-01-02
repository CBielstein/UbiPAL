// Cameron Bielstein, 1/1/2015 (Happy New Year!)
// error.h
// Includes error return codes and descriptions for UbiPAL

#ifndef ERROR_H
#define ERROR_H

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
    };

    // get_error_description
    // Takes error code and returns a string description of that code
    // args
    //          [IN] error_code: integer error code to be described
    // return
    //          Static string description of error code
    const char* get_error_description(const int& error_code);
}

#endif
