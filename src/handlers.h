#ifndef HANDLERS_H
#define HANDLERS_H

#include "server.h"
#include "pi_calc.h"
#include <string>

// Global Pi calculator instance (shared with handlers)
extern PiCalculator g_pi_calc;

// Endpoint handlers
HttpResponse handle_temperature();
HttpResponse handle_pi_start(const std::string& body);
HttpResponse handle_pi_stop(const std::string& body);
HttpResponse handle_pi_status();

#endif // HANDLERS_H
