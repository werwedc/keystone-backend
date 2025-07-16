#pragma once
#include "crow.h"
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