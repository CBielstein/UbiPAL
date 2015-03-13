// Cameron Bielstein, 3/15/15
// statement.cpp
// Implementation for the Statement object for UbiPAL. Represents a parsed statement.

// Header
#include "statement.h"

namespace UbiPAL
{
    Statement::Statement()
    {
        root = std::string();
        type = INVALID;
        name1 = std::string();
        name2 = std::string();
        name3 = std::string();
        comparison = std::string();
        num1 = 0;
        num2 = 0;
        statement = nullptr;
    }

    void Statement::FreeStatementHelper(Statement* statement)
    {
        if (statement == nullptr)
        {
            return;
        }
        else
        {
            FreeStatementHelper(statement->statement);
            delete statement;
            return;
        }
    }

    Statement::~Statement()
    {
        FreeStatementHelper(statement);
    }

    void Statement::StatementDeepCopyHelper(Statement*& statement, const Statement* rhs_statement)
    {
        if (rhs_statement == nullptr)
        {
            return;
        }
        else
        {
            statement = new Statement;
            *statement = *rhs_statement;
            StatementDeepCopyHelper(statement->statement, rhs_statement);
            return;
        }
    }

    Statement& Statement::operator=(const Statement& rhs)
    {
        root = rhs.root;
        type = rhs.type;
        name1 = rhs.name1;
        name2 = rhs.name2;
        name3 = rhs.name3;
        comparison = rhs.comparison;
        num1 = rhs.num1;
        num2 = rhs.num2;
        StatementDeepCopyHelper(statement, rhs.statement);
        return *this;
    }

    // Comparison operators to allow use in a set
    bool operator<(const Statement lhs, const Statement rhs)
    {
        if (lhs.root < rhs.root)
        {
            return true;
        }
        else if (lhs.root == rhs.root && lhs.type < rhs.type)
        {
            return true;
        }
        else if (lhs.root == rhs.root && lhs.type == rhs.type && lhs.name1 < rhs.name1)
        {
            return true;
        }
        else if (lhs.root == rhs.root && lhs.type == rhs.type && lhs.name1 == rhs.name1 &&
                 lhs.name2 < lhs.name2)
        {
            return true;
        }
        else if (lhs.root == rhs.root && lhs.type == rhs.type && lhs.name1 == rhs.name1 &&
                 lhs.name2 == lhs.name2 && lhs.name3 < rhs.name3)
        {
            return true;
        }
        else if (lhs.root == rhs.root && lhs.type == rhs.type && lhs.name1 == rhs.name1 &&
                 lhs.name2 == lhs.name2 && lhs.name3 == rhs.name3 && lhs.comparison < rhs.comparison)
        {
            return true;
        }
        else if (lhs.root == rhs.root && lhs.type == rhs.type && lhs.name1 == rhs.name1 &&
                 lhs.name2 == lhs.name2 && lhs.name3 == rhs.name3 && lhs.comparison == rhs.comparison &&
                 lhs.num1 < rhs.num1)
        {
            return true;
        }
        else if (lhs.root == rhs.root && lhs.type == rhs.type && lhs.name1 == rhs.name1 &&
                 lhs.name2 == lhs.name2 && lhs.name3 == rhs.name3 && lhs.comparison == rhs.comparison &&
                 lhs.num1 == rhs.num1 && lhs.num2 < rhs.num2)
        {
            return true;
        }
        else if (lhs.root == rhs.root && lhs.type == rhs.type && lhs.name1 == rhs.name1 &&
                 lhs.name2 == lhs.name2 && lhs.name3 == rhs.name3 && lhs.comparison == rhs.comparison &&
                 lhs.num1 == rhs.num1 && lhs.num2 == rhs.num2 && (lhs.statement == nullptr && rhs.statement != nullptr))
        {
            return true;
        }
        else if (lhs.root == rhs.root && lhs.type == rhs.type && lhs.name1 == rhs.name1 &&
                 lhs.name2 == lhs.name2 && lhs.name3 == rhs.name3 && lhs.comparison == rhs.comparison &&
                 lhs.num1 == rhs.num1 && lhs.num2 == rhs.num2
                 && (lhs.statement != nullptr && rhs.statement != nullptr && *lhs.statement < *rhs.statement))
        {
            return true;
        }
        else
        {
            return false;
        }
    }
}
