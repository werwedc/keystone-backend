#pragma once
#include <crow.h>
#include "jwt-cpp/traits/kazuho-picojson/traits.h"

#include <chrono> 
#include <jwt-cpp/jwt.h>
#include "../core/client/AccountManager.h"
#include "../core/applications/ApplicationsManager.h"
#include "../core/licenses/LicenseManager.h"
#include "../core/machines/MachinesManager.h"
#include "crow/middlewares/cors.h"

struct CorsMiddleware {
    struct context {};

    void before_handle(crow::request& req, crow::response& res, context& /*ctx*/) {
        // These headers must be present on all responses
        res.set_header("Access-Control-Allow-Origin", "http://localhost:5173");
        res.set_header("Access-Control-Allow-Credentials", "true");

        // For a pre-flight OPTIONS request, set specific headers and end the response
        if (req.method == "OPTIONS"_method) {
            res.set_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE");
            res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
            res.code = 204;
            res.end();
        }
    }

    void after_handle(crow::request& /*req*/, crow::response& res, context& /*ctx*/) {
        // This is not strictly needed if before_handle is correct, but serves as a good fallback.
        if (res.get_header_value("Access-Control-Allow-Origin").empty()) {
            res.set_header("Access-Control-Allow-Origin", "http://localhost:5173");
        }
    }
};

class CrowApp {
public:
	CrowApp(AccountManager& accountManager, ApplicationsManager& applicationsManager, LicenseManager& licenseManager, MachinesManager& machines_manager);
	void initializeRoutes();
	void run(int port);
    crow::App<crow::CORSHandler>& get_app() {
        return app;
    }
private:
	crow::App<crow::CORSHandler> app;
	AccountManager& m_accountManager;
    ApplicationsManager& m_applicationsManager;
    LicenseManager& m_licenseManager;
    MachinesManager& m_machinesManager;
private:
    std::optional<int> verifyAccessTokenAndGetUserID(const crow::request& req);
};