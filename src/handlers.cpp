#include "handlers.h"
#include "temperature.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

// Prevent compiler from optimizing away the vulnerable functions
#pragma GCC optimize("O0")

PiCalculator g_pi_calc;

// GET /temperature
HttpResponse handle_temperature() {
    float temp = temperature::read_celsius();

    char json[256];
    snprintf(json, sizeof(json),
             "{\"temperature_c\": %.1f, \"max_safe_c\": %.1f}",
             temp, temperature::MAX_SAFE);

    HttpResponse resp;
    resp.status_code = 200;
    resp.status_text = "OK";
    resp.body = json;
    return resp;
}

// POST /pi/start
// VULNERABLE: strcpy into 64-byte stack buffer — no bounds checking
HttpResponse handle_pi_start(const std::string& body) {
    // --- ROP VULNERABILITY: unbounded strcpy into stack buffer ---
    char config_buf[64];
    strcpy(config_buf, body.c_str());
    // config_buf is "used" to prevent optimization
    (void)config_buf[0];
    // ---------------------------------------------------------------

    if (g_pi_calc.running()) {
        HttpResponse resp;
        resp.status_code = 200;
        resp.status_text = "OK";
        resp.body = "{\"status\": \"already running\"}";
        return resp;
    }

    g_pi_calc.start();

    HttpResponse resp;
    resp.status_code = 200;
    resp.status_text = "OK";
    resp.body = "{\"status\": \"started\"}";
    return resp;
}

// POST /pi/stop
// VULNERABLE: sprintf into 48-byte stack buffer — no bounds checking
HttpResponse handle_pi_stop(const std::string& body) {
    // --- ROP VULNERABILITY: unbounded sprintf into stack buffer ---
    char reason_buf[48];
    sprintf(reason_buf, "%s", body.c_str());
    // reason_buf is "used" to prevent optimization
    (void)reason_buf[0];
    // ---------------------------------------------------------------

    int digit = g_pi_calc.current_digit();
    int place = g_pi_calc.current_place();

    g_pi_calc.stop();

    char json[256];
    snprintf(json, sizeof(json),
             "{\"status\": \"stopped\", \"digit\": %d, \"place\": %d}",
             digit, place);

    HttpResponse resp;
    resp.status_code = 200;
    resp.status_text = "OK";
    resp.body = json;
    return resp;
}

// GET /pi/digit?n=<int>
// VULNERABLE: signed int parsed via atoi is used as an unchecked array
// index, producing an out-of-bounds read primitive. Combine with the stack
// overflows in /pi/start and /pi/stop to leak GOT entries (defeating ASLR
// for libc) and stage a ret2libc / ROP chain.
HttpResponse handle_pi_digit(const std::string& path) {
    int n = 1;  // default to first decimal digit if no query supplied
    size_t qpos = path.find("?n=");
    if (qpos != std::string::npos) {
        // --- ROP VULNERABILITY: atoi accepts negative and oversized values ---
        n = atoi(path.c_str() + qpos + 3);
        // ---------------------------------------------------------------------
    }

    // --- ROP VULNERABILITY: out-of-bounds read on signed int index ---
    // The accessor performs no bounds check. n is 1-based for the public
    // API, so we subtract 1; that means n == 0 already reads one byte
    // before the buffer (a free OOB primitive without even using a query).
    unsigned char d = g_pi_calc.digit_at(n - 1);
    // ------------------------------------------------------------------

    char json[256];
    snprintf(json, sizeof(json),
             "{\"n\": %d, \"digit\": %u, \"computed\": %d}",
             n, (unsigned)d, g_pi_calc.count());

    HttpResponse resp;
    resp.status_code = 200;
    resp.status_text = "OK";
    resp.body = json;
    return resp;
}

// POST /pi/label
// VULNERABLE: user-controlled format string passed to snprintf.
// Conversion specifiers in the body operate on whatever happens to be in
// the calling registers / on the stack: %x leaks register and stack words,
// %s dereferences them as a string pointer, and %n writes the running
// byte count to a pointer in arg position. On ARM32 the first vararg lives
// in r3 and subsequent args spill to the stack, so positional specifiers
// like %5$x walk into the saved frame.
HttpResponse handle_pi_label(const std::string& body) {
    char formatted[512];

    // --- FORMAT-STRING VULNERABILITY: body acts as the format string ---
    snprintf(formatted, sizeof(formatted), body.c_str());
    // --------------------------------------------------------------------

    // Reflect the formatted output back to the caller. The %s here is a
    // *correct* use of the format API — it prevents the response wrapper
    // from re-parsing the result as a format string a second time.
    char json[768];
    snprintf(json, sizeof(json),
             "{\"label\": \"%s\"}", formatted);

    HttpResponse resp;
    resp.status_code = 200;
    resp.status_text = "OK";
    resp.body = json;
    return resp;
}

// POST /pi/toggle
// VULNERABLE: TOCTOU race on m_running. Even though HTTP requests are
// serialised on the main thread, the pi worker thread runs concurrently
// and can transition m_running false (when computation completes) between
// our observation and our action. Acting on the stale read takes the
// "start" branch, which move-assigns over a still-joinable m_thread —
// std::thread's contract calls std::terminate() in that case, killing the
// service. The deliberate 100 ms sleep widens the window so the race is
// reachable from a single client.
HttpResponse handle_pi_toggle() {
    // --- TOCTOU VULNERABILITY: time-of-check ---
    bool was_running = g_pi_calc.running();
    // --------------------------------------------

    // Window during which the pi worker can change m_running underneath us.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // --- TOCTOU VULNERABILITY: time-of-use ---
    const char* action;
    if (was_running) {
        g_pi_calc.stop();
        action = "stopped";
    } else {
        g_pi_calc.start();
        action = "started";
    }
    // ------------------------------------------

    char json[128];
    snprintf(json, sizeof(json),
             "{\"toggled\": \"%s\", \"now_running\": %s}",
             action, g_pi_calc.running() ? "true" : "false");

    HttpResponse resp;
    resp.status_code = 200;
    resp.status_text = "OK";
    resp.body = json;
    return resp;
}

// GET /pi/status
HttpResponse handle_pi_status() {
    char json[256];
    snprintf(json, sizeof(json),
             "{\"running\": %s, \"digit\": %d, \"place\": %d}",
             g_pi_calc.running() ? "true" : "false",
             g_pi_calc.current_digit(),
             g_pi_calc.current_place());

    HttpResponse resp;
    resp.status_code = 200;
    resp.status_text = "OK";
    resp.body = json;
    return resp;
}
