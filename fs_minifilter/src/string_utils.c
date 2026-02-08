#include "string_utils.h"

BOOLEAN UnicodeContainsLiteral(
    const PUNICODE_STRING haystack,
    PCWSTR needle,
    BOOLEAN ignore_case
)
{
    UNICODE_STRING needle_unicode;
    RtlInitUnicodeString(&needle_unicode, needle);

    if (!haystack || !haystack->Buffer || haystack->Length == 0) return FALSE;
    if (!needle_unicode.Buffer || needle_unicode.Length == 0) return FALSE;
    if (haystack->Length < needle_unicode.Length) return FALSE;

    USHORT hChars = haystack->Length / sizeof(WCHAR);
    USHORT nChars = needle_unicode.Length / sizeof(WCHAR);

    for (USHORT i = 0; i <= hChars - nChars; i++) {
        UNICODE_STRING slice;
        slice.Buffer = haystack->Buffer + i;
        slice.Length = needle_unicode.Length;
        slice.MaximumLength = needle_unicode.Length;

        if (RtlCompareUnicodeString(&slice, &needle_unicode, ignore_case) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}