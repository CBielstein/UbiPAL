// Cameron Bielstein, 1/12/15
// macros.h
// A file of helpful macros for UbiPAL

#ifndef UBIPAL_SRC_MACROS_H
#define UBIPAL_SRC_MACROS_H

// FUNCTION_START
// place at the beginning of each function to declare status and check_return
// status: used to keep return code, should be kept clean to only UbiPAL error codes
// check_return: Return values from functions outside of UbiPAL
#define FUNCTION_START int status = SUCCESS; int returned_value = 0;

// FUNCTION_END
// Very last part of a function, returns the status
// check_return = ret_val to avoid set but unused error
#define FUNCTION_END { returned_value = returned_value; return status; }

// RETURN_STATUS
// Sets status to code, then jumps to function exit code
// args
//      [IN] code: a UbiPAL error code to return from the function
#define RETURN_STATUS(code) { status = code; goto exit; }

#endif
