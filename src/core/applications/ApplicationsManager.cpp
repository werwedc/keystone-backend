#include "ApplicationsManager.h"
#include <pqxx/pqxx>
#include <iostream>

ApplicationsManager::ApplicationsManager(AccountManager& account_manager, DatabaseManager& db_manager)
    : m_account_manager(account_manager), m_db_manager(db_manager) {
}

/**
 * @brief Creates a new application associated with a user account.
 * @param user_id The ID of the account that owns this application.
 * @param name The name of the new application.
 * @return True if the application was created successfully, false otherwise.
 */
bool ApplicationsManager::createApplication(int user_id, const std::string& name) {
    try {
        auto conn = m_db_manager.getConnection();
        pqxx::work tx(*conn);
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

/**
 * @brief Deletes an application from the database.
 * @param application_id The ID of the application to delete.
 * @return True if the deletion was successful, false otherwise.
 */
bool ApplicationsManager::deleteApplication(int application_id) {
    try {
        auto conn = m_db_manager.getConnection();
        pqxx::work tx(*conn);
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

/**
 * @brief Updates the status for a specific application.
 * @param application_id The ID of the application to modify.
 * @param status The new status string (e.g., "active", "paused").
 * @return True on successful update, false otherwise.
 */
bool ApplicationsManager::setStatus(int application_id, const std::string& status) {
    try {
        auto conn = m_db_manager.getConnection();
        pqxx::work tx(*conn);
        std::string sql = "UPDATE applications SET status = $1 WHERE id = $2;";
        pqxx::result result = tx.exec_params(sql, status, application_id);
        tx.commit();
        return result.affected_rows() > 0;
    }  catch (const std::exception& e) {
        std::cerr << "Error while setting status: " << e.what() << std::endl;
        return false;
    }
}

/**
 * @brief Sets the expiration date of an application based on a duration from its creation date.
 * @param application_id The ID of the application to modify.
 * @param duration The duration (in seconds) from the creation time at which the application should expire.
 * @return True on successful update, false otherwise.
 */
bool ApplicationsManager::setDuration(int application_id, const std::chrono::seconds &duration) {
    try {
        auto conn = m_db_manager.getConnection();
        pqxx::work tx(*conn);
        std::string update_sql = R"(
            UPDATE applications
            SET expires_at = created_at + ($1 * INTERVAL '1 second')
            WHERE id = $2;
        )";

        tx.exec_params(update_sql, duration.count(), application_id);
        tx.commit();
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error while setting duration of an application: " << e.what() << std::endl;
        return false;
    }
}

/**
 * @brief Checks if an application is currently expired.
 * @param application_id The ID of the application to check.
 * @return True if the application's `expires_at` date is in the past, false otherwise. Returns true on error.
 */
bool ApplicationsManager::isExpired(int application_id) {
    try {
        auto conn = m_db_manager.getConnection();
        pqxx::read_transaction tx(*conn);
        std::string sql = R"(
            SELECT EXISTS (
                SELECT 1
                FROM applications
                WHERE id = $1 AND expires_at < NOW()
            );
        )";
        pqxx::result result = tx.exec_params(sql, application_id);

        if (result.empty()) {
            return true;
        }
        return result[0][0].as<bool>();
    } catch (const std::exception& e) {
        std::cerr << "Error while checking if application is expired: " << e.what() << std::endl;
        return true;
    }
}

/**
 * @brief Renames an application.
 * @param application_id The ID of the application to rename.
 * @param name The new name for the application.
 * @return True on successful update, false otherwise.
 */
bool ApplicationsManager::renameApplication(int application_id, const std::string& name) {
    try {
        auto conn = m_db_manager.getConnection();
        pqxx::work tx(*conn);
        std::string sql = "UPDATE applications SET name = $1 WHERE id = $2;";
        pqxx::result result = tx.exec_params(sql, name, application_id);
        tx.commit();
        return result.affected_rows() > 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Error while renaming application: " << e.what() << std::endl;
        return false;
    }
}

/**
 * @brief Retrieves the details of a single application by its ID.
 * @param application_id The ID of the application to fetch.
 * @return An std::optional containing the ApplicationDetails struct if found, otherwise std::nullopt.
 */
std::optional<ApplicationDetails> ApplicationsManager::getApplication(int application_id) {
    try {
        auto conn = m_db_manager.getConnection();
        pqxx::read_transaction tx(*conn);
        std::string sql = "SELECT account_id, name, status FROM applications WHERE id = $1;";
        pqxx::result result = tx.exec_params(sql, application_id);

        if (result.empty()) {
            return std::nullopt;
        }

        ApplicationDetails application;
        application.id = application_id;
        application.user_id = result[0][0].as<int>();
        application.name = result[0][1].as<std::string>();
        application.status = result[0][2].as<std::string>();

        return application;
    }
    catch (const std::exception& e) {
        std::cerr << "Error while getting application: " << e.what() << std::endl;
        return std::nullopt;
    }
}

/**
 * @brief Retrieves all applications associated with a specific user account.
 * @param user_id The ID of the user whose applications are to be fetched.
 * @return A vector of ApplicationDetails structs. The vector will be empty if no applications are found or an error occurs.
 */
std::vector<ApplicationDetails> ApplicationsManager::getApplications(int user_id) {
    std::vector<ApplicationDetails> applications;
    try {
        auto conn = m_db_manager.getConnection();
        pqxx::read_transaction tx(*conn);
        std::string sql = "SELECT id, name, status FROM applications WHERE account_id = $1;";
        pqxx::result result = tx.exec_params(sql, user_id);
        for (const pqxx::row& row : result) {
            ApplicationDetails application;
            application.id = row[0].as<int>();
            application.user_id = user_id;
            application.name = row[1].as<std::string>();
            application.status = row[2].as<std::string>();
            applications.push_back(application);
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error while getting applications: " << e.what() << std::endl;
    }
    return applications;
}
