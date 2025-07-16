#pragma once
#include "crow.h"
#include "jwt-cpp/traits/kazuho-picojson/traits.h"

#include <chrono> 
#include <jwt-cpp/jwt.h>
#include "../core/client/AccountManager.h"


class CrowApp {
public:
	CrowApp(AccountManager& accountManager);
	void initializeRoutes();
	void run(int port);
private:
	crow::SimpleApp app;
	AccountManager& m_accountManager;
};