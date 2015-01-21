// Cameron Bielstein, 1/19/15
// ubipal_acl.h
// Represents an access control rule in UbiPAL

#ifndef UBIPAL_SRC_UBIPAL_ACL_H
#define UBIPAL_SRC_UBIPAL_ACL_H

// Standard
#include <string>
#include <vector>
#include <uuid/uuid.h>

namespace UbiPAL
{
    struct UbipalAcl
    {
        // helps identify this acl locally, is not broadcasted
        std::string name;
        // used to identify the acl for later revokation
        uuid_t identifier;
        std::vector<std::string> rules;
        bool is_public;
    };
}

#endif
