#pragma once
#include "flt.h"

BOOLEAN UnicodeContainsLiteral(
    const PUNICODE_STRING haystack,
    PCWSTR needle,
    BOOLEAN ignore_case
);