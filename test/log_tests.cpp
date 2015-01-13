// Cameron Bielstein, 1/2/15
// log_tests.cpp
// Unit tests for log.h & log.cpp for UbiPAL

#include "log_tests.h"
#include "test_helpers.h"
#include "../src/log.h"
#include <cstdio>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>

namespace UbiPAL
{
    int LogTests::LogTestIsValidLevelTrue()
    {
        if (Log::IsValidLevel(Log::DEBUG))
        {
            return SUCCESS;
        }
        else
        {
            return GENERAL_FAILURE;
        }
    }

    int LogTests::LogTestIsValidLevelFalse()
    {
        if (!Log::IsValidLevel((Log::Level)-42))
        {
            return SUCCESS;
        }
        else
        {
            return GENERAL_FAILURE;
        }
    }


    int LogTests::LogTestSetPrintTrue()
    {
        int status = SUCCESS;

        status = Log::SetPrint(true);

        if (status != SUCCESS)
        {
            return status;
        }

        if (Log::GetPrintStderr())
        {
            return SUCCESS;
        }
        else
        {
            return GENERAL_FAILURE;
        }
    }

    int LogTests::LogTestSetPrintFalse()
    {
        int status = SUCCESS;

        status = Log::SetPrint(false);

        if (status != SUCCESS)
        {
            return status;
        }

        if (!Log::GetPrintStderr())
        {
            return SUCCESS;
        }
        else
        {
            return GENERAL_FAILURE;
        }
    }

    int LogTests::LogTestSetLevelValid()
    {
        int status = SUCCESS;

        status = Log::SetLevel(Log::DEBUG);

        if (status != SUCCESS)
        {
            return status;
        }

        if (Log::GetLogLevel() != Log::DEBUG)
        {
            return GENERAL_FAILURE;
        }

        status = Log::SetLevel(Log::EMERG);

        if (status != SUCCESS)
        {
            return status;
        }

        if (Log::GetLogLevel() != Log::EMERG)
        {
            return GENERAL_FAILURE;
        }

        return SUCCESS;
    }

    int LogTests::LogTestSetLevelInvalid()
    {
        int status = SUCCESS;

        status = Log::SetLevel((Log::Level)-42);

        if (status == INVALID_ARG)
        {
            return SUCCESS;
        }
        else
        {
            return GENERAL_FAILURE;
        }
    }

    int LogTests::LogTestSetLogFile()
    {
        int status = SUCCESS;

        std::string empty;
        Log::SetFileName(empty);
        Log::SetLogFile(nullptr);

        std::string national_champions("NationalChampions.txt");
        status = Log::SetFile(national_champions);

        if (status != SUCCESS)
        {
            goto exit;
        }

        if (Log::GetFileName().compare(national_champions) == 0 &&
            Log::GetLogFile() != nullptr)
        {
            status = SUCCESS;
            goto exit;
        }
        else
        {
            status = GENERAL_FAILURE;
            goto exit;
        }

        exit:
            remove(national_champions.c_str());
            return status;
    }

    int LogTests::LogTestSetLogFileEmpty()
    {
        int status = SUCCESS;

        std::string empty;
        std::string test("test");
        Log::SetFileName(test);
        Log::SetLogFile(nullptr);

        status = Log::SetFile(empty);

        if (Log::GetFileName().compare(test) == 0 &&
            Log::GetLogFile() == nullptr &&
            status == INVALID_ARG)
        {
            return SUCCESS;
        }
        else
        {
            return GENERAL_FAILURE;
        }
    }

    int LogTests::LogTestConfigureAllEmpty()
    {
        int status = SUCCESS;

        std::string empty;
        Log::SetFileName(empty);
        Log::SetLogFile(nullptr);

        status = Log::Configure();

        if (status != SUCCESS)
        {
            goto exit;
        }

        if (Log::GetFileName().compare(Log::GetDefaultLogName()) == 0 &&
            Log::GetLogFile() != nullptr &&
            status == SUCCESS)
        {
            status = SUCCESS;
            goto exit;
        }
        else
        {
            status = GENERAL_FAILURE;
            goto exit;
        }

        exit:
            remove(Log::GetDefaultLogName().c_str());
            return status;
    }

    int LogTests::LogTestConfigureFilePointerEmpty()
    {
        int status = SUCCESS;

        std::string oregon_ducks("OregonDucks.txt");
        Log::SetFileName(oregon_ducks);
        Log::SetLogFile(nullptr);

        status = Log::Configure();

        if (status != SUCCESS)
        {
            goto exit;
        }

        if (Log::GetFileName().compare(oregon_ducks) == 0 &&
            Log::GetLogFile() != nullptr &&
            status == SUCCESS)
        {
            status = SUCCESS;
            goto exit;
        }
        else
        {
            status = GENERAL_FAILURE;
            goto exit;
        }

        exit:
            remove(oregon_ducks.c_str());
            return status;
    }

    int LogTests::LogTestConfigureFileNameEmpty()
    {
        int status = SUCCESS;

        std::string empty;
        Log::SetFileName(empty);
        Log::SetLogFile(nullptr);

        status = Log::Configure();

        if (status != SUCCESS)
        {
            goto exit;
        }

        Log::SetFileName(empty);
        Log::Configure();

        if (Log::GetFileName().compare(Log::GetDefaultLogName()) == 0 &&
            Log::GetLogFile() != nullptr &&
            status == SUCCESS)
        {
            status = SUCCESS;
            goto exit;
        }
        else
        {
            status = GENERAL_FAILURE;
            goto exit;
        }

        exit:
            remove(Log::GetDefaultLogName().c_str());
            return status;
    }

    int LogTests::LogTestLine()
    {
        int status = 0;
        int returned_value = 0;
        FILE* read_file = nullptr;
        struct stat stats;
        char* read_line = nullptr;
        std::string read_str;
        size_t ret_size = 0;

        std::string sports_center("sports_center.txt");
        status = Log::SetFile(sports_center);
        if (status != SUCCESS)
        {
            goto exit;
        }

        Log::SetLogLevel(Log::DEBUG);
        status = Log::Line(Log::DEBUG, "This is %s Center", "Sports");
        if (status < 0)
        {
            goto exit;
        }

        // flush the write
        returned_value = fflush(Log::GetLogFile());
        if (returned_value != 0)
        {
            status = FAILED_FILE_WRITE;
            goto exit;
        }

        read_file = fopen(sports_center.c_str(), "r");
        if (read_file == nullptr)
        {
            status = OPEN_FILE_FAILED;
            goto exit;
        }

        returned_value = stat(sports_center.c_str(), &stats);
        if (returned_value < 0)
        {
            status = FAILED_FILE_READ;
            goto exit;
        }

        read_line = (char*)malloc(stats.st_size + 1);
        if (read_line == nullptr)
        {
            status = GENERAL_FAILURE;
            goto exit;
        }

        returned_value = fread(read_line, 1, stats.st_size, read_file);
        if (returned_value != stats.st_size)
        {
            status = FAILED_FILE_READ;
            goto exit;
        }

        // ensure null-terminated
        read_line[stats.st_size] = '\0';

        read_str = std::string(read_line);
        ret_size = read_str.find("This is Sports Center");

        if (ret_size == std::string::npos)
        {
            fprintf(stderr, "LogTests::LogTestLine: mismatch. Read: %s, expected: %s\n", read_str.c_str(), "This is Sports Center");
            status = GENERAL_FAILURE;
            goto exit;
        }
        else
        {
            status = SUCCESS;
            goto exit;
        }

        exit:
            remove(sports_center.c_str());
            free(read_line);
            return status;
    }

    int LogTests::LogTestLineConfigure()
    {
        int status = 0;
        int returned_value = 0;
        FILE* read_file = nullptr;
        struct stat stats;
        char* read_line = nullptr;
        std::string read_str;
        size_t ret_size = 0;

        std::string empty;
        Log::SetFileName(empty);
        Log::SetLogFile(nullptr);

        Log::SetLogLevel(Log::DEBUG);
        status = Log::Line(Log::DEBUG, "%d + %d = %d", 1, 1, 2);
        if (status < 0)
        {
            goto exit;
        }

        // flush the write
        returned_value = fflush(Log::GetLogFile());
        if (returned_value != 0)
        {
            status = FAILED_FILE_WRITE;
            goto exit;
        }

        read_file = fopen(Log::GetDefaultLogName().c_str(), "r");
        if (read_file == nullptr)
        {
            status = OPEN_FILE_FAILED;
            goto exit;
        }

        returned_value = stat(Log::GetDefaultLogName().c_str(), &stats);
        if (returned_value < 0)
        {
            status = FAILED_FILE_READ;
            goto exit;
        }

        read_line = (char*)malloc(stats.st_size + 1);
        if (read_line == nullptr)
        {
            status = GENERAL_FAILURE;
            goto exit;
        }

        returned_value = fread(read_line, 1, stats.st_size, read_file);
        if (returned_value != stats.st_size)
        {
            status = FAILED_FILE_READ;
            goto exit;
        }

        // ensure null-terminated
        read_line[stats.st_size] = '\0';

        read_str = std::string(read_line);
        ret_size = read_str.find("1 + 1 = 2");

        if (ret_size == std::string::npos)
        {
            status = GENERAL_FAILURE;
            goto exit;
        }
        else
        {
            status = SUCCESS;
            goto exit;
        }

        exit:
            fclose(read_file);
            remove(Log::GetDefaultLogName().c_str());
            free(read_line);
            return status;
    }

    int LogTests::LogTestLineNull()
    {
        int status = SUCCESS;

        status = Log::Line(Log::EMERG, NULL);

        if (status == NULL_ARG)
        {
            return SUCCESS;
        }
        else
        {
            return GENERAL_FAILURE;
        }
    }

    int LogTests::LogTestFlush()
    {
        int status = SUCCESS;
        int returned_value = 0;
        FILE* read_file = nullptr;
        char* read_line = nullptr;
        struct stat stats;
        std::string read_str;
        size_t ret_size = 0;
        std::string test_string("This is a test of the emergency broadcast system.");

        status = Log::SetFile(Log::GetDefaultLogName());
        if (status != SUCCESS)
        {
            goto exit;
        }

        returned_value = fwrite(test_string.c_str(), 1, strlen(test_string.c_str()), Log::GetLogFile());
        if ((unsigned int)returned_value < strlen(test_string.c_str()))
        {
            status = FAILED_FILE_WRITE;
            goto exit;
        }

        status = Log::FlushLog();
        if (status != SUCCESS)
        {
            goto exit;
        }

        read_file = fopen(Log::GetDefaultLogName().c_str(), "r");
        if (read_file == nullptr)
        {
            status = OPEN_FILE_FAILED;
            goto exit;
        }

        returned_value = stat(Log::GetDefaultLogName().c_str(), &stats);
        if (returned_value < 0)
        {
            status = FAILED_FILE_READ;
            goto exit;
        }

        read_line = (char*)malloc(stats.st_size + 1);
        if (read_line == nullptr)
        {
            status = GENERAL_FAILURE;
            goto exit;
        }

        returned_value = fread(read_line, 1, stats.st_size, read_file);
        if (returned_value != stats.st_size)
        {
            status = FAILED_FILE_READ;
            goto exit;
        }

        // ensure null-terminated
        read_line[stats.st_size] = '\0';

        read_str = std::string(read_line);
        ret_size = read_str.find(test_string.c_str());

        if (ret_size == std::string::npos)
        {
            status = GENERAL_FAILURE;
            goto exit;
        }
        else
        {
            status = SUCCESS;
            goto exit;
        }

        exit:
            fclose(read_file);
            remove(Log::GetDefaultLogName().c_str());
            free(read_line);
            return status;
    }

    int LogTests::LogTestFlushNull()
    {
        int status = SUCCESS;
        Log::SetLogFile(NULL);
        status = Log::FlushLog();
        return status;
    }

    void LogTests::RunLogTests(unsigned int& module_count, unsigned int& module_fails)
    {
        TestHelpers::RunTestFunc(LogTestIsValidLevelTrue, SUCCESS,
                                 "LogTestIsValidLevelTrue", module_count, module_fails);
        TestHelpers::RunTestFunc(LogTestIsValidLevelFalse, SUCCESS,
                                 "LogTestIsValidLevelFalse", module_count, module_fails);
        TestHelpers::RunTestFunc(LogTestSetPrintTrue, SUCCESS,
                                 "LogTestSetPrintTrue", module_count, module_fails);
        TestHelpers::RunTestFunc(LogTestSetPrintFalse, SUCCESS,
                                 "LogTestSetPrintFalse", module_count, module_fails);
        TestHelpers::RunTestFunc(LogTestSetLevelValid, SUCCESS,
                                 "LogTestSetLevelValid", module_count, module_fails);
        TestHelpers::RunTestFunc(LogTestSetLevelInvalid, SUCCESS,
                                 "LogTestSetLevelInvalid", module_count, module_fails);
        TestHelpers::RunTestFunc(LogTestSetLogFile, SUCCESS,
                                 "LogTestSetLogFile", module_count, module_fails);
        TestHelpers::RunTestFunc(LogTestSetLogFileEmpty, SUCCESS,
                                 "LogTestSetLogFileEmpty", module_count, module_fails);
        TestHelpers::RunTestFunc(LogTestConfigureAllEmpty, SUCCESS,
                                 "LogTestConfigureAllEmpty", module_count, module_fails);
        TestHelpers::RunTestFunc(LogTestConfigureFilePointerEmpty, SUCCESS,
                                 "LogTestConfigureFilePointerEmpty", module_count, module_fails);
        TestHelpers::RunTestFunc(LogTestConfigureFileNameEmpty, SUCCESS,
                                 "LogTestConfigureFileNameEmpty", module_count, module_fails);
        TestHelpers::RunTestFunc(LogTestLine, SUCCESS,
                                 "LogTestLine", module_count, module_fails);
        TestHelpers::RunTestFunc(LogTestLineConfigure, SUCCESS,
                                 "LogTestLineConfigure", module_count, module_fails);
        TestHelpers::RunTestFunc(LogTestLineNull, SUCCESS,
                                 "LogTestLineNull", module_count, module_fails);
        TestHelpers::RunTestFunc(LogTestFlush, SUCCESS,
                                 "LogTestFlush", module_count, module_fails);
        TestHelpers::RunTestFunc(LogTestFlushNull, SUCCESS,
                                 "LogTestFlushNull", module_count, module_fails);
    }
}
