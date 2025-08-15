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
    m_dbManager = std::make_unique<DatabaseManager>(m_config.db_conn_string);

    if (m_dbManager->connect()) {
        std::cout << "Succesfully connected to the database\n";
    }
    else {
        std::cerr << "Could not connect to the database. Exiting." << std::endl;
        return false;
    }
    return true;
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

// In Server::initializeRoutes()

void Server::initializeRoutes() {
    m_crowApp = std::make_unique<CrowApp>(*m_accountManager, *m_applicationsManager, *m_licenseManager, *m_machinesManager);

    auto& app = m_crowApp->get_app();

    // Get a handle to the CORS middleware
    auto& cors = app.get_middleware<crow::CORSHandler>();

    // Configure the rules
    cors.global()
        .origin("http://localhost:5173")
        .methods("POST"_method, "GET"_method, "DELETE"_method, "PUT"_method)
        .headers("Content-Type", "Authorization");

    // Continue with your original logic
    m_crowApp->initializeRoutes();
    m_crowApp->run(8080);
}

void Server::runTests() {
    //m_accountManager->createAccount("werwedc@gmail.com", "Werwedc!!1111");
    //m_applicationsManager->createApplication(6, "Minecraft");
    //m_applicationsManager->createApplication(6, "Gay dating app for women");
    //m_licenseManager->createLicense(5, "235wibtu", 1);
}
