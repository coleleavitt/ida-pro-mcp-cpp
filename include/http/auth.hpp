#pragma once

#include <httplib.h>
#include <string>

extern std::string SESSION_TOKEN;

bool validate_bearer_token(const httplib::Request &req);

void send_auth_error(httplib::Response &res);
