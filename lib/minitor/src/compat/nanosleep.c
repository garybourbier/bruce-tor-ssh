/* nanosleep.c — ESP32 compat: nanosleep is not in newlib.
 * Uses FreeRTOS vTaskDelay; resolution limited to portTICK_PERIOD_MS. */
#include <time.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

int nanosleep(const struct timespec *req, struct timespec *rem)
{
    if (req == NULL)
        return -1;
    uint32_t ms = (uint32_t)(req->tv_sec * 1000UL) +
                  (uint32_t)(req->tv_nsec / 1000000UL);
    vTaskDelay(pdMS_TO_TICKS(ms > 0 ? ms : 1));
    if (rem) { rem->tv_sec = 0; rem->tv_nsec = 0; }
    return 0;
}
