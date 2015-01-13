// Cameron Bielstein, 1/3/15
// log.h
// Logging for UbiPAL

#ifndef UBIPAL_SRC_LOG_H
#define UBIPAL_SRC_LOG_H

#include <string>

namespace UbiPAL
{
    // Log
    // Logging functions for UbiPAL. This class is designed to be mostly static so that it
    // may be safely called from anywhere in code without the need to have an object.
    class Log
    {
        public:
            // Level
            // Level of messages, which can be used to filter the log
            // lower numbers are more important
            // subset of RFC 5424
            // note: if anything is changed here, ensure it is also changed in Log::IsValidLevel
            enum Level
            {
                // severe failures
                EMERG,
                // events outside the system normal operation
                WARN,
                // normal system events
                INFO,
                // messages for debug purposes, not important to user
                DEBUG,
            };

            // Line
            // Log::Line prints a new line in the log including a timestamp
            // if print_stderr is true, line also prints to stderr
            // only lines less than or equal to log_level will be logged
            // args
            //          [IN] level: the level at which to log, from log::level above
            //          [IN] format: the format string, like printf
            //          [IN] ... : input for the format string, like printf
            // return
            //          int: number of bytes logged on success, negative on error
            //          The function could behave successfully and return 0 if level > log_level, for example
            static int Line(const Level& level, const char* format, ...);

            // SetLevel
            // Changes the level printed to the log
            // args
            //          [IN] level: log::level to accept, only this and lower priorities are printed
            // return
            //          int: SUCCESS on success
            static int SetLevel(const Level& level);

            // SetFile
            // Changes the file used for the log
            // args
            //          [IN] file_name: name of the new file to be used for the log
            // return
            //          int: SUCCESS on success
            static int SetFile(const std::string& file_name);

            // SetPrint
            // Sets whether log lines should be printed to stderr or not
            // args
            //          [IN] print: true for print to screen and log file, false for only to file
            // return
            //          int: SUCCESS on success
            static int SetPrint(const bool& print);

        private:
            // IsValidLevel
            // Given a Level value, ensures that the level is actually an enum value as defined
            // This is necessary as per the rules on valid enum values
            // explained here: http://stackoverflow.com/questions/4969233/how-to-check-if-enum-value-is-valid
            // args
            //          [IN] level: a level value to check
            // return
            //          bool: true if level is included in level
            static bool IsValidLevel(const Level& level);

            // Configure
            // Is called when one of the member variables are empty or NULL to initialize the log variables
            // return
            //          int: SUCCESS on success, error code otherwise
            static int Configure();

            // Enable testing
            friend class LogTests;

            // Getters and Setters to enable testing
            static const std::string GetDefaultLogName();
            static const Level GetLogLevel();
            static void SetLogLevel(const Log::Level& level);
            static const std::string GetFileName();
            static void SetFileName(std::string& name);
            static FILE* GetLogFile();
            static void SetLogFile(FILE* file);
            static const bool GetPrintStderr();
            static void SetPrintStdErr(bool print);
    };
}

#endif
