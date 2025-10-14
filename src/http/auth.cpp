#include "http/auth.hpp"

std::string SESSION_TOKEN = "ida-mcp-static-token-for-claude";

bool validate_bearer_token(const httplib::Request &req) {
    auto auth_header = req.get_header_value("Authorization");
    return auth_header == ("Bearer " + SESSION_TOKEN);
}

void send_auth_error(httplib::Response &res) {
    res.status = 401;
    res.set_header("WWW-Authenticate", "Bearer realm=\"ida-mcp\"");
    res.set_content(R"({"error": "Unauthorized. Use Bearer )" + SESSION_TOKEN + "\"}", "application/json");
}
