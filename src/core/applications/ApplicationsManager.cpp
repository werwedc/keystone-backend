#include "ApplicationsManager.h"

//Constructor
ApplicationsManager::ApplicationsManager(AccountManager& account_manager, DatabaseManager& db_manager)
    : m_account_manager(account_manager), m_db_manager(db_manager) {
}
//TODO: expires at
bool ApplicationsManager::createApplication(int user_id, const std::string& name) {
    try {
        pqxx::work tx(*m_db_manager.getConnection());
        std::string sql = "INSERT INTO applications (account_id, name) "
            "VALUES ($1, $2) RETURNING id;";

        const pqxx::result result = tx.exec_params(sql, user_id, name);
        tx.commit();

        if (!result.empty()) {
            const int new_id = result[0][0].as<int>();
            std::cout << "Successfully created application with ID: " << new_id << std::endl;
            return true;
        }
        return false;
    }
    catch (const std::exception& e) {
        std::cerr << "Error while creating application: " << e.what() << std::endl;
        return false;
    }
}

bool ApplicationsManager::deleteApplication(int application_id) {
    try {
        pqxx::work tx(*m_db_manager.getConnection());
        std::string sql = "DELETE FROM applications WHERE id = $1;";

        pqxx::result result = tx.exec_params(sql, application_id);
        tx.commit();
        return result.affected_rows() > 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Error while deleting application: " << e.what() << std::endl;
        return false;
    }
}

bool ApplicationsManager::setActive(int application_id, bool active) {
    try {
        pqxx::work tx(*m_db_manager.getConnection());
        std::string sql = "UPDATE applications SET active = $1 WHERE id = $2;";
        pqxx::result result = tx.exec_params(sql, active, application_id);
        tx.commit();
        return result.affected_rows() > 0;
    }  catch (const std::exception& e) {
        std::cerr << "Error while setting active: " << e.what() << std::endl;
        return false;
    }
}

bool ApplicationsManager::renameApplication(int application_id, std::string& name) {
    try {
        pqxx::work tx(*m_db_manager.getConnection());
        std::string sql = "UPDATE applications SET name = $1 WHERE id = $2;";
        pqxx::result result = tx.exec_params(sql, name, application_id);
        tx.commit();
        return result.affected_rows() > 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Error while renaming application: " << e.what() << std::endl;
    }
}

std::vector<ApplicationDetails> ApplicationsManager::getApplications(int user_id) {
    std::vector<ApplicationDetails> applications;
    try {
        pqxx::read_transaction tx(*m_db_manager.getConnection());
        std::string sql = "SELECT id, name, active FROM applications WHERE account_id = $1;";
        pqxx::result result = tx.exec_params(sql, user_id);
        for (const pqxx::row& row : result) {
            ApplicationDetails application;
            application.id = row[0].as<int>();
            application.user_id = user_id;
            application.name = row[1].as<std::string>();
            application.active = row[2].as<bool>();
            applications.push_back(application);
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error while getting applications: " << e.what() << std::endl;
    }
    return applications;
}


