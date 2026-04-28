#include "server.h"
#include "handlers.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>

static const int BODY_BUF_SIZE = 4096;

// Parse a raw HTTP request into method, path, and body
static HttpRequest parse_request(const char* raw, int len) {
    HttpRequest req;
    // Extract method
    const char* sp1 = strchr(raw, ' ');
    if (!sp1) return req;
    req.method.assign(raw, sp1 - raw);

    // Extract path
    const char* sp2 = strchr(sp1 + 1, ' ');
    if (!sp2) return req;
    req.path.assign(sp1 + 1, sp2 - (sp1 + 1));

    // Extract body (after \r\n\r\n)
    const char* body_start = strstr(raw, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
        int body_len = len - (body_start - raw);
        if (body_len > 0) {
            req.body.assign(body_start, body_len);
        }
    }

    return req;
}

// Format and send an HTTP response
static void send_response(int client_fd, const HttpResponse& resp) {
    char header[256];
    snprintf(header, sizeof(header),
             "HTTP/1.1 %d %s\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n"
             "\r\n",
             resp.status_code, resp.status_text.c_str(),
             resp.body.size());
    write(client_fd, header, strlen(header));
    if (!resp.body.empty()) {
        write(client_fd, resp.body.c_str(), resp.body.size());
    }
}

// Route request to the appropriate handler
static HttpResponse route(const HttpRequest& req) {
    if (req.method == "GET" && req.path == "/temperature") {
        return handle_temperature();
    }
    if (req.method == "POST" && req.path == "/pi/start") {
        return handle_pi_start(req.body);
    }
    if (req.method == "POST" && req.path == "/pi/stop") {
        return handle_pi_stop(req.body);
    }
    if (req.method == "GET" && req.path == "/pi/status") {
        return handle_pi_status();
    }
    if (req.method == "GET" &&
        (req.path == "/pi/digit" || req.path.compare(0, 10, "/pi/digit?") == 0)) {
        return handle_pi_digit(req.path);
    }

    HttpResponse resp;
    resp.status_code = 404;
    resp.status_text = "Not Found";
    resp.body = "{\"error\": \"not found\"}";
    return resp;
}

void server_run(int port, std::atomic<bool>& g_running) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        return;
    }

    if (listen(server_fd, 8) < 0) {
        perror("listen");
        close(server_fd);
        return;
    }

    printf("HTTP server listening on port %d\n", port);

    struct pollfd pfd;
    pfd.fd = server_fd;
    pfd.events = POLLIN;

    while (g_running.load()) {
        // Poll with 1-second timeout for clean shutdown checks
        int ret = poll(&pfd, 1, 1000);
        if (ret < 0) {
            if (g_running.load()) perror("poll");
            break;
        }
        if (ret == 0) continue; // timeout — check g_running again

        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (g_running.load()) perror("accept");
            continue;
        }

        // Read request
        char buf[BODY_BUF_SIZE];
        int n = read(client_fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            HttpRequest req = parse_request(buf, n);
            HttpResponse resp = route(req);
            send_response(client_fd, resp);
        }

        close(client_fd);
    }

    close(server_fd);
    printf("HTTP server stopped\n");
}
