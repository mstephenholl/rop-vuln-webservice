#include "led.h"
#include <cstdio>
#include <cstring>

static const char* LED_BASE = "/sys/class/leds/beaglebone:green:usr";

// Default triggers to restore on cleanup
static const char* DEFAULT_TRIGGERS[] = {
    "heartbeat",  // usr0
    "mmc0",       // usr1
    "mmc1",       // usr2
    "none"        // usr3
};

static void write_file(const char* path, const char* value) {
    FILE* f = fopen(path, "w");
    if (!f) return; // silently ignore on non-BBB hardware
    fputs(value, f);
    fclose(f);
}

void led::init() {
    char path[128];
    for (int i = 0; i < 4; i++) {
        snprintf(path, sizeof(path), "%s%d/trigger", LED_BASE, i);
        write_file(path, "none");
        // Start with all LEDs off
        snprintf(path, sizeof(path), "%s%d/brightness", LED_BASE, i);
        write_file(path, "0");
    }
}

void led::set(int led_num, bool on) {
    if (led_num < 0 || led_num > 3) return;
    char path[128];
    snprintf(path, sizeof(path), "%s%d/brightness", LED_BASE, led_num);
    write_file(path, on ? "1" : "0");
}

void led::cleanup() {
    char path[128];
    for (int i = 0; i < 4; i++) {
        // Turn off
        snprintf(path, sizeof(path), "%s%d/brightness", LED_BASE, i);
        write_file(path, "0");
        // Restore default trigger
        snprintf(path, sizeof(path), "%s%d/trigger", LED_BASE, i);
        write_file(path, DEFAULT_TRIGGERS[i]);
    }
}
