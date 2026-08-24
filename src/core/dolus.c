#include "dolus.h"
#include <stdlib.h>
#include <string.h>

static const char *error_strings[] = {
    "Success",
    "Unknown error",
    "Out of memory",
    "Invalid argument",
    "Not found",
    "Resource busy",
    "Timeout",
    "Permission denied",
    "I/O error",
    "Configuration error",
    "Network error",
    "Database error",
    "Cryptographic error"
};

const char *dolus_error_string(dolus_error_t err) {
    int idx = -err;
    if (idx >= 0 && idx < (int)(sizeof(error_strings) / sizeof(error_strings[0]))) {
        return error_strings[idx];
    }
    return "Unknown error code";
}

const char *dolus_version(void) {
    return DOLUS_VERSION;
}

const char *dolus_author(void) {
    return DOLUS_AUTHOR;
}