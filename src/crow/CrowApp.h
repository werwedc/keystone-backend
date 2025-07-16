#pragma once
#include "crow.h"
#include "jwt-cpp/traits/kazuho-picojson/traits.h"

#include <chrono> 
#include <jwt-cpp/jwt.h>
#include "../core/client/AccountManager.h"

struct CorsMiddleware {
    struct context {};

    void before_handle(crow::request& req, crow::response& res, context& ctx) {
        // This function will now only set the headers specific to an OPTIONS preflight.
        // It will NOT set the Access-Control-Allow-Origin header.
        if (req.method == "OPTIONS"_method) {
            res.add_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE");
            res.add_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
            res.code = 204;
            res.end();
        }
    }

    void after_handle(crow::request& req, crow::response& res, context& ctx) {
        // This is the single, correct place to add the origin header.
        // It will be added once to every response, including the one for OPTIONS.
        res.add_header("Access-Control-Allow-Origin", "*");
    }
};

class CrowApp {
public:
	CrowApp(AccountManager& accountManager);
	void initializeRoutes();
	void run(int port);
private:
	crow::App<CorsMiddleware> app;
	AccountManager& m_accountManager;
};