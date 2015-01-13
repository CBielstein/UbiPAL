// Cameron Bielstein, 1/6/15
// log.cpp
// Logging for UbiPAL

#include "log.h"

#include "error.h"
#include "macros.h"

#include <stdio.h>
#include <ctime>
#include <stdarg.h>
#include <mutex>

namespace UbiPAL
{
    // static and const variables used for this file

    // A constant std::string holding the default log name
    const static std::string DEFAULT_LOG_NAME("log.txt");

    // mutex for Configure
    static std::mutex configuration_mutex;

    // the level of the log, used for filtering
    // any value greater than this, should not be logged
    // default value is INFO
    static Log::Level log_level = Log::INFO;

    // the file path of the log
    static std::string file_name;

    // the logfile itself
    static FILE* log_file;

    // if true, print all logged messages to stderr as well as log
    // helpful for debugging, demoing, etc.
    static bool print_stderr = false;

    int Log::Line(const Level& level, const char* format, ...)
    {
        FUNCTION_START;

        char* timestamp = nullptr;
        char* message = nullptr;
        time_t curr_time;

        // if the log level is too high, just return success
        if (level > log_level)
        {
            RETURN_STATUS(SUCCESS);
        }

        if (!IsValidLevel(level))
        {
            Log::Line(DEBUG, "Log::Line passed invalid Level: %d", level);
            RETURN_STATUS(INVALID_ARG);
        }

        if (format == nullptr)
        {
            Log::Line(WARN, "Log::Line passed NULL format string");
            RETURN_STATUS(NULL_ARG);
        }

        // if the log_file pointer is null, call Configure then continue
        if (log_file == nullptr)
        {
            status = Log::Configure();
            if (status != SUCCESS)
            {
                RETURN_STATUS(status);
            }
        }

        // note: failures below this point in the function will not log the failure to avoid cyclical failures

        // create timestamp
        curr_time = time(NULL);
        if (curr_time < 0)
        {
            fprintf(stderr, "Log::Line: time(NULL) failed. Returned: %lu\n", curr_time);
            RETURN_STATUS(GENERAL_FAILURE);
        }

        timestamp = ctime(&curr_time);
        if (timestamp == nullptr)
        {
            fprintf(stderr, "Log::Line: ctime() returned NULL\n");
            RETURN_STATUS(GENERAL_FAILURE);
        }

        // remove newline character
        // man says this is format DDD MMM DD HH:MM:SS YYYY\n\0
        timestamp[24] = '\0';

        // create line
        va_list args;

        // get size required for line
        va_start(args, format);
        ret_val = vsnprintf(NULL, 0, format, args);
        va_end(args);
        if (ret_val < 0)
        {
            fprintf(stderr, "Log::Line, vsnprintf() failed and returned %d\n", ret_val);
            RETURN_STATUS(GENERAL_FAILURE);
        }

        // allocate enough space for the message and a null character
        message = (char*)malloc(ret_val+1);
        if (message == nullptr)
        {
            fprintf(stderr, "Log::Line: malloc failed to allocate space for a message.\n");
            RETURN_STATUS(GENERAL_FAILURE);
        }

        va_start(args, format);
        ret_val = vsnprintf(message, ret_val + 1, format, args);
        va_end(args);
        if (ret_val < 0)
        {
            fprintf(stderr, "Log::Line: vsnprintf() failed to create the message from the format string and arguments, returned %d\n", ret_val);
            RETURN_STATUS(GENERAL_FAILURE);
        }

        // output to log file
        ret_val = fprintf(log_file, "%s: %s\n", timestamp, message);
        if (ret_val < 0)
        {
            fprintf(stderr, "Log::Line: fprintf failed to print to log_file, returned %d\n", ret_val);
            RETURN_STATUS(FAILED_FILE_WRITE);
        }

        // print to stderr if appropriate
        if (print_stderr)
        {
            ret_val = fprintf(stderr, "%s: %s\n", timestamp, message);
            if (ret_val < 0)
            {
                fprintf(stderr, "Log::Line: fprintf failed to print to stderr, returned %d\n", ret_val);
                RETURN_STATUS(FAILED_FILE_WRITE);
            }
        }

        // return with the number of bytes printed
        if (ret_val > 0)
        {
            RETURN_STATUS(ret_val);
        }
        else
        {
            fprintf(stderr, "Log::Line: something went wrong and reported %d bytes printed\n", ret_val);
            RETURN_STATUS(GENERAL_FAILURE);
        }

        exit:
            free(message);
            FUNCTION_END;
    }

    int Log::SetLevel(const Level& level)
    {
        if (!IsValidLevel(level))
        {
            return INVALID_ARG;
        }

        log_level = level;

        return SUCCESS;
    }

    int Log::SetFile(const std::string& new_file_name)
    {
        FUNCTION_START;

        // lock
        configuration_mutex.lock();

        if (new_file_name.empty())
        {
            return INVALID_ARG;
        }

        // try to open the file first
        FILE* test_file = fopen(new_file_name.c_str(), "a");

        // if the file cannot be opened, this is an invalid argument
        if (test_file == NULL)
        {
            return INVALID_ARG;
        }

        if (log_file != nullptr)
        {
            // close the old file, swap in the new one
            ret_val = fclose(log_file);

            if (ret_val < 0)
            {
                // if we failed, this is a problem, but further access
                // is UB, so we need to swap it anyway, but can't write
                // to new file yet, so we can simply print it and continue
                fprintf(stderr, "Log::SetFile: fclose failed to close log_file: %s, continuing and opening new file.\n", file_name.c_str());
            }
        }

        log_file = test_file;
        file_name = new_file_name;

        test_file = nullptr;

        // unlock
        configuration_mutex.unlock();

        FUNCTION_END;
    }

    int Log::SetPrint(const bool& print)
    {
        print_stderr = print;
        return SUCCESS;
    }

    bool Log::IsValidLevel(const Level& level)
    {
        return (level == EMERG) ||
               (level == WARN) ||
               (level == INFO) ||
               (level == DEBUG);
    }

    int Log::Configure()
    {
        int status = SUCCESS;
        int ret_val = 0;

        // lock
        configuration_mutex.lock();

        // if the file pointer is active, close it
        if (log_file != nullptr)
        {
            ret_val = fclose(log_file);
        }

        // if it fails to close, we cannot log, so print an error
        // but we need not fail, since we can open a new file and continue
        if (ret_val != 0)
        {
            fprintf(stderr, "Log::Configure: fclose failed to close log_file, returned: %d\n", ret_val);
        }

        // if we don't have a file name, set it to default
        if (file_name.empty())
        {
            file_name = DEFAULT_LOG_NAME;
        }

        // open the file based on the file name
        log_file = fopen(file_name.c_str(), "a");
        if (log_file == nullptr)
        {
            fprintf(stderr, "Log::Configure: fopen failed to open %s\n", file_name.c_str());
            status = OPEN_FILE_FAILED;
        }

        // unlock
        configuration_mutex.unlock();

        // return
        return status;
    }

    const std::string Log::GetDefaultLogName()
    {
        return DEFAULT_LOG_NAME;
    }

    const Log::Level Log::GetLogLevel()
    {
        return log_level;
    }

    void Log::SetLogLevel(const Level& level)
    {
        log_level = level;
    }

    const std::string Log::GetFileName()
    {
        return file_name;
    }

    void Log::SetFileName(std::string& name)
    {
        file_name = name;
    }

    FILE* Log::GetLogFile()
    {
        return log_file;
    }

    void Log::SetLogFile(FILE* file)
    {
        log_file = file;
    }

    const bool Log::GetPrintStderr()
    {
        return print_stderr;
    }

    void Log::SetPrintStdErr(bool print)
    {
        print_stderr = print;
    }
}
