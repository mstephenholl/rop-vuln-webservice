#include "temperature.h"
#include <cstdio>
#include <cstdlib>

// Candidate sysfs paths for temperature reading (millidegrees C)
static const char* SENSOR_PATHS[] = {
    "/sys/class/thermal/thermal_zone0/temp",
    "/sys/class/hwmon/hwmon0/device/temp1_input",
    "/sys/class/hwmon/hwmon0/temp1_input",
    NULL
};

static const float MOCK_TEMP = 42.5f;

float temperature::read_celsius() {
    char buf[32];
    for (int i = 0; SENSOR_PATHS[i] != NULL; i++) {
        FILE* f = fopen(SENSOR_PATHS[i], "r");
        if (!f) continue;

        if (fgets(buf, sizeof(buf), f)) {
            fclose(f);
            int millideg = atoi(buf);
            return millideg / 1000.0f;
        }
        fclose(f);
    }
    // No sensor found — return mock value for dev/testing
    return MOCK_TEMP;
}
