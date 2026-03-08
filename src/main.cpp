#include "server.h"
#include "handlers.h"
#include "temperature.h"
#include "led.h"

#include <cstdio>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>

static const int HTTP_PORT = 8080;

// Global shutdown flag
static std::atomic<bool> g_running(true);

static void signal_handler(int) {
    g_running.store(false);
}

// LED 0: heartbeat — 500ms on, 500ms off
static void heartbeat_thread() {
    bool on = false;
    while (g_running.load()) {
        on = !on;
        led::set(0, on);
        // Sleep 500ms in 10ms increments for responsive shutdown
        for (int i = 0; i < 50 && g_running.load(); i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
}

// LEDs 1-3: temperature indicator
// <= 35C: LED1 only | <= 70C: LED1+2 | > 70C: LED1+2+3
// >= 102.9C (98%): all 3 flash at ~3Hz
static void temp_monitor_thread() {
    while (g_running.load()) {
        float temp = temperature::read_celsius();

        if (temp >= temperature::CRITICAL) {
            // Flash all 3 at ~3Hz (167ms on/167ms off)
            bool flash_on = true;
            while (g_running.load() && temperature::read_celsius() >= temperature::CRITICAL) {
                led::set(1, flash_on);
                led::set(2, flash_on);
                led::set(3, flash_on);
                flash_on = !flash_on;
                // Sleep ~167ms in 10ms increments
                for (int i = 0; i < 17 && g_running.load(); i++) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
            }
        } else if (temp > temperature::TWO_THIRDS) {
            led::set(1, true);
            led::set(2, true);
            led::set(3, true);
        } else if (temp > temperature::THIRD) {
            led::set(1, true);
            led::set(2, true);
            led::set(3, false);
        } else {
            led::set(1, true);
            led::set(2, false);
            led::set(3, false);
        }

        // Check every 500ms
        for (int i = 0; i < 50 && g_running.load(); i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
}

int main() {
    printf("ROP-Vulnerable Webservice (Educational)\n");
    printf("========================================\n");

    // Install signal handlers for clean shutdown
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Initialize LEDs
    led::init();
    printf("LEDs initialized\n");

    // Read initial temperature
    float temp = temperature::read_celsius();
    printf("Current temperature: %.1f C\n", temp);

    // Start threads
    std::thread hb_thread(heartbeat_thread);
    std::thread tm_thread(temp_monitor_thread);
    printf("LED threads started (heartbeat + temp monitor)\n");

    // Run HTTP server (blocks until g_running is false)
    server_run(HTTP_PORT, g_running);

    // Shutdown
    printf("\nShutting down...\n");

    // Wait for threads
    if (hb_thread.joinable()) hb_thread.join();
    if (tm_thread.joinable()) tm_thread.join();

    // Stop Pi computation if running
    g_pi_calc.stop();

    // Cleanup LEDs
    led::cleanup();
    printf("Cleanup complete\n");

    return 0;
}
