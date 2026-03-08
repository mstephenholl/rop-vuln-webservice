#ifndef SERVER_H
#define SERVER_H

#include <atomic>
#include <string>

// Simple parsed HTTP request
struct HttpRequest {
    std::string method;   // "GET", "POST", etc.
    std::string path;     // "/temperature", "/pi/start", etc.
    std::string body;     // POST body (raw bytes)
};

// HTTP response helper
struct HttpResponse {
    int         status_code;
    std::string status_text;
    std::string body;
};

// Start HTTP server on given port; blocks until g_running becomes false
void server_run(int port, std::atomic<bool>& g_running);

#endif // SERVER_H
