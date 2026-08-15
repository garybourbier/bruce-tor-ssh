/* timegm.c — ESP32 compat: timegm is not in newlib.
 * On ESP32/lwIP the default timezone is UTC, so mktime() == timegm(). */
#include <time.h>

time_t timegm(struct tm *tm)
{
    return mktime(tm);
}
