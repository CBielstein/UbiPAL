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
            case MULTIPLE_RECV: return "MULTIPLE_RECV: Multiple calls to recv cannot happen at once on the same object. Recv had already been called.";
            case THREAD_FAILURE: return "THREAD_FAILURE: An error occurred with threading code.";
            case BUFFER_TOO_SMALL: return "BUFFER_TOO_SMALL: A buffer of memory is too small for the attempted operation.";
            case INVALID_NETWORK_ENCODING: return "INVALID_NETWORK_ENCODING: Invalid network encoding.";
            case MESSAGE_WRONG_DESTINATION: return "MESSAGE_WRONG_DESTINATION: A message was received at a service to which it was not addressed.";
            case SIGNATURE_INVALID: return "SIGNATURE_INVALID: A message signature failed validation on the receiving end.";
            case NAMESPACE_CERTIFICATE_NOT_FOUND: return "NAMESPACE_CERTIFICATE_NOT_FOUND: The desired namespace certificate could not be located.";
            case NOT_IN_ACLS: return "NOT_IN_ACLS: Access to sending a message could not be granted because the ACLs on hand do not allow it.";
            case FAILED_CONDITIONS: return "FAILED_CONDITIONS: Access to sending a message could not be granted because the conditions did not hold.";
            case NOT_FOUND: return "NOT_FOUND: The requested object was not found.";
            case WAIT_ON_CONDITIONS: return "WAITIN_ON_CONDITIONS: The evaluation must wait on conditions checks to complete before being completed.";
            case TIMEOUT_CONDITIONS: return "TIMEOUT_CONDITION: The requested message timed out during condition checks.";
            case INVALID_SYNTAX: return "INVALID_SYNTAX: The syntax of a given UbiPAL statement is invalid.";
            case FAILED_EVALUATION: return "FAILED_EVALUATION: The given statement failed evaulation.";
            case NOT_IMPLEMENTED: return "NOT_IMPLEMENTED: The attempted functionality is not yet implemented.";
            default: return "Error code does not have description.";
        }
    }
}
