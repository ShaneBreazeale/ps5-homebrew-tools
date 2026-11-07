/* SPDX-License-Identifier: GPL-3.0-or-later
 * Freestanding helper used by the pinned resident's OBS log_msg path.
 * Keep its existing strlen semantics; no user pointers or new entry points.
 * The caller remains responsible for a valid NUL-terminated resident string.
 */
#include <stddef.h>

size_t strlen(const char *text) {
    const char *end = text;
    while (*end) ++end;
    return (size_t)(end - text);
}
