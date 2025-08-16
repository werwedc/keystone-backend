#include "Server.h"
#include <iostream>
#include "sodium.h"

Server::Server(Config config) : m_config(std::move(config)) {

}

void Server::run() {
    if (!setupDatabase()) {
        return;
    }
    setupAccountManager();
    setupApplicationsManager();
    setupLicenseManager();
    setupMachinesManager();
    initializeLibSodium();
    runTests();
	initializeRoutes();
}

bool Server::setupDatabase() {
    try {
        m_dbManager = std::make_unique<DatabaseManager>(m_config.db_conn_string, m_config.db_pool_size);
        std::cout << "Database connection pool initialized." << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Could not connect to the database: " << e.what() << std::endl;
        return false;
    }
}

void Server::setupAccountManager() {
    m_accountManager = std::make_unique<AccountManager>(*m_dbManager);
}

void Server::setupApplicationsManager() {
    m_applicationsManager = std::make_unique<ApplicationsManager>(*m_accountManager, *m_dbManager);
}

void Server::setupLicenseManager() {
    m_licenseManager = std::make_unique<LicenseManager>(*m_applicationsManager, *m_dbManager);
}

void Server::setupMachinesManager() {
    m_machinesManager = std::make_unique<MachinesManager>(*m_dbManager, *m_licenseManager);
}


void Server::initializeLibSodium() {
    if (sodium_init() < 0) {
        std::cerr << "Error: Could not initialize libsodium!" << std::endl;
    }
}

void Server::initializeRoutes() {
    m_crowApp = std::make_unique<CrowApp>(*m_accountManager, *m_applicationsManager, *m_licenseManager, *m_machinesManager, m_config.jwt_secret);

    auto& app = m_crowApp->get_app();

    auto& cors = app.get_middleware<crow::CORSHandler>();
    cors.global()
        .origin("http://localhost:5173")
        .methods("POST"_method, "GET"_method, "DELETE"_method, "PUT"_method, "OPTIONS"_method)
        .headers("Content-Type", "Authorization");

    m_crowApp->initializeRoutes();
    m_crowApp->run(8080);
}

void Server::runTests() {

}
