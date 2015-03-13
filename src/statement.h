// Cameron Bielstein, 3/15/15
// statement.h
// Header for the Statement object for UbiPAL. Represents a parsed statement.

#ifndef UBIPAL_SRC_STATEMENT_H
#define UBIPAL_SRC_STATEMENT_H

#include <string> // std::string

namespace UbiPAL
{
    // Statement
    // A struct to hold a parsed UbiPAL statement
    // STATEMENT
    //          - NAME says NAME CONNECTIVE NAME
    //          - NAME says NAME CONNECTIVE NAME CONNECTIVE NAME
    //          - CurrentTime() COMPARISON INTEGER
    //          - CurrentDate() COMPARISON INTEGER
    //          - NAME says NAME CONNECTIVE STATEMENT
    //          - NAME confirms NAME
    //
    // CONNECTIVE
    //          - {is a, is, can send message, to}
    //
    // COMPARISON
    //          - { <, > }
    //
    // Examples: (a, b, c for variables)
    // a says b is a c
    // a says b is c
    // a says b can send message c to d
    // CurrentTime() a b // CurrentTime() > 9:00, CurrentTime() < 17:00
    // CurrentDate() a b // CurrentDate() < UNIX_TIME (seconds since epoch)
    // a says b can say STATEMENT
    // a confirms b
    class Statement
    {
        public:
            // Type
            // The types of UbiPAL statements.
            enum Type
            {
                IS_A,
                IS,
                CAN_SEND_MESSAGE,
                CAN_SAY,
                CURRENT_TIME,
                CURRENT_DATE,
                CONFIRMS,
                INVALID,
            };

            // Statement
            // Default construct, sets everything to empty string, 0, or nullptr
            Statement();

            // ~Statement
            // Destructor. Frees any sub-statements on this structure
            ~Statement();

            // operator=
            // Copy assignment. Deep copy.
            // args
            //          [IN] rhs: Another Statement object to deep copy
            // returns
            //          Statement&: this Statement after copying
            Statement& operator=(const Statement& rhs);

            std::string root;
            Type type;
            std::string name1;
            std::string name2;
            std::string name3;
            std::string comparison;
            uint32_t num1;
            uint32_t num2;
            Statement* statement;

        private:
            // FreeStatementHelper
            // Recursively frees the statement objects.
            // args
            //          [IN] statement: A statement to be deeply deleted
            // return
            //          void
            void FreeStatementHelper(Statement* statement);

            // StatementDeepCopyHelper
            // Recursively copy a statement object
            // args
            //          [IN/OUT]:
            void StatementDeepCopyHelper(Statement*& statement, const Statement* rhs_statement);
    };
    // Comparison operators to allow use in a set
    bool operator<(const Statement lhs, const Statement rhs);

}

#endif
