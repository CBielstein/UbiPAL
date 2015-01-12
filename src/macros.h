// Cameron Bielstein, 1/12/15
// macros.h
// A file of helpful macros for UbiPAL

#ifndef UBIPAL_SRC_MACROS_H
#define UBIPAL_SRC_MACROS_H

#define FUNCTION_START int status = SUCCESS; int ret_val = 0;
#define FUNCTION_END { return status; }

#define RETURN_STATUS(code) { status = code; goto exit; }

#endif
