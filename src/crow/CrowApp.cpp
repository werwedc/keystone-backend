#include "CrowApp.h"

CrowApp::CrowApp(AccountManager& accountManager) 
	:m_accountManager(accountManager)
{

}

void CrowApp::initializeRoutes()
{
	CROW_ROUTE(app, "/about")([]() {
		return "Hello world";
		});

}

void CrowApp::run(int port)
{
	app.port(port).multithreaded().run();
}
