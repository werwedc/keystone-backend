#include "LicenseManager.h"
#include <iostream>
#include <sstream>

LicenseManager::LicenseManager(ApplicationsManager &applications_manager, DatabaseManager &db_manager)
    : m_applications_manager(applications_manager), m_db_manager(db_manager) {
}

/**
 * @brief Creates a new license for a given application.
 * @param application_id The ID of the application this license belongs to.
 * @param license_key The unique key for this license.
 * @param tier The numerical tier of the license.
 * @return True if the license was created successfully, false otherwise.
 */
bool LicenseManager::createLicense(int application_id, const std::string &license_key, int tier) {
    try {
        pqxx::work tx(*m_db_manager.getConnection());
        std::string sql = "INSERT INTO licenses (application_id, license_key, tier) "
            "VALUES ($1, $2, $3) RETURNING id;";

        const pqxx::result result = tx.exec_params(sql, application_id, license_key, tier);
        tx.commit();

        if (!result.empty()) {
            const int new_id = result[0][0].as<int>();
            std::cout << "Successfully created license with ID: " << new_id << std::endl;
            return true;
        }
        return false;
    }
    catch (const std::exception& e) {
        std::cerr << "Error while creating license: " << e.what() << std::endl;
        return false;
    }
}

/**
 * @brief Deletes a license from the database.
 * @param license_id The ID of the license to delete.
 * @return True if the deletion was successful, false otherwise.
 */
bool LicenseManager::deleteLicense(int license_id) {
    try {
        pqxx::work tx(*m_db_manager.getConnection());
        std::string sql = "DELETE FROM licenses WHERE id = $1;";

        pqxx::result result = tx.exec_params(sql, license_id);
        tx.commit();
        return result.affected_rows() > 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Error while deleting license: " << e.what() << std::endl;
        return false;
    }
}

/**
 * @brief Retrieves the details of a single license by its ID.
 * @param license_id The ID of the license to fetch.
 * @return An std::optional containing the LicenseDetails struct if found, otherwise std::nullopt.
 */
std::optional<LicenseDetails> LicenseManager::getLicense(int license_id) {
    try {
        pqxx::read_transaction tx(*m_db_manager.getConnection());
        std::string sql =
            "SELECT id, application_id, license_key, flags, tier, number_of_machines, max_allowed_machines, created_at, expires_at "
            "FROM licenses WHERE id = $1;";
        pqxx::result result = tx.exec_params(sql, license_id);

        if (result.empty()) {
            return std::nullopt;
        }

        const auto& row = result[0];
        LicenseDetails license;
        license.id = row["id"].as<int>();
        license.application_id = row["application_id"].as<int>();
        license.license_key = row["license_key"].as<std::string>();

        if (!row["flags"].is_null()) {
            std::string flags_str = row["flags"].as<std::string>();
            if (flags_str.length() > 2) { // Not "{}"
                flags_str = flags_str.substr(1, flags_str.length() - 2);
                std::stringstream ss(flags_str);
                std::string segment;
                while (std::getline(ss, segment, ',')) {
                    license.flags.push_back(segment);
                }
            }
        }

        license.tier = row["tier"].as<int>();
        license.number_of_machines = row["number_of_machines"].as<int>();
        license.max_allowed_machines = row["max_allowed_machines"].as<int>();
        license.created_at = row["created_at"].as<std::string>();
        if (!result[0][8].is_null()) {
            license.expires_at = result[0][8].as<std::string>();
        }

        return license;
    } catch (const std::exception& e) {
        std::cerr << "Error while getting license: " << e.what() << std::endl;
        return std::nullopt;
    }
}

/**
 * @brief Retrieves the details of a single license by its unique key.
 * @param license_key The license key to fetch.
 * @return An std::optional containing the LicenseDetails struct if found, otherwise std::nullopt.
 */
std::optional<LicenseDetails> LicenseManager::getLicenseByKey(const std::string& license_key) {
    try {
        pqxx::read_transaction tx(*m_db_manager.getConnection());
        std::string sql =
            "SELECT id, application_id, license_key, flags, tier, number_of_machines, max_allowed_machines, created_at, expires_at "
            "FROM licenses WHERE license_key = $1;";
        pqxx::result result = tx.exec_params(sql, license_key);

        if (result.empty()) {
            return std::nullopt;
        }

        // Since we have getLicense(id), we can just reuse it to avoid duplicating the parsing logic.
        return getLicense(result[0]["id"].as<int>());

    } catch (const std::exception& e) {
        std::cerr << "Error while getting license by key: " << e.what() << std::endl;
        return std::nullopt;
    }
}

/**
 * @brief Retrieves all licenses associated with a specific application.
 * @param application_id The ID of the application whose licenses are to be fetched.
 * @return A vector of LicenseDetails structs. The vector will be empty if no licenses are found or an error occurs.
 */
std::vector<LicenseDetails> LicenseManager::getLicenses(int application_id) {
    std::vector<LicenseDetails> licenses;
    try {
        pqxx::read_transaction tx(*m_db_manager.getConnection());
        std::string sql = "SELECT id, application_id, license_key, flags, tier, number_of_machines, max_allowed_machines, created_at, expires_at FROM licenses WHERE application_id = $1;";
        pqxx::result result = tx.exec_params(sql, application_id);

        for (const auto& row : result) {
            LicenseDetails license;
            license.id = row["id"].as<int>();
            license.application_id = row["application_id"].as<int>();
            license.license_key = row["license_key"].as<std::string>();

            if (!row["flags"].is_null()) {
                std::string flags_str = row["flags"].as<std::string>();
                if (flags_str.length() > 2) {
                    flags_str = flags_str.substr(1, flags_str.length() - 2);
                    std::stringstream ss(flags_str);
                    std::string segment;
                    while(std::getline(ss, segment, ',')) {
                        license.flags.push_back(segment);
                    }
                }
            }

            license.tier = row["tier"].as<int>();
            license.number_of_machines = row["number_of_machines"].as<int>();
            license.max_allowed_machines = row["max_allowed_machines"].as<int>();
            license.created_at = row["created_at"].as<std::string>();
            if (!row["expires_at"].is_null()) {
                license.expires_at = row["expires_at"].as<std::string>();
            }
            licenses.push_back(license);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error while getting licenses for application: " << e.what() << std::endl;
    }
    return licenses;
}

/**
 * @brief Appends a list of flags to a license's existing flags.
 * @param license_id The ID of the license to modify.
 * @param flags A vector of strings representing the flags to add.
 * @return True on successful update, false otherwise.
 */
bool LicenseManager::addFlags(int license_id, const std::vector<std::string> &flags) {
    try {
        pqxx::work tx(*m_db_manager.getConnection());
        std::string sql = "UPDATE licenses SET flags = array_cat(flags, $1) WHERE id = $2;";
        pqxx::result result = tx.exec_params(sql, flags, license_id);
        tx.commit();
        return result.affected_rows() > 0;
    } catch (const std::exception& e) {
        std::cerr << "Error while adding flags: " << e.what() << std::endl;
        return false;
    }
}

/**
 * @brief Overwrites a license's flags with a new list of flags.
 * @param license_id The ID of the license to modify.
 * @param flags A vector of strings representing the new flags.
 * @return True on successful update, false otherwise.
 */
bool LicenseManager::setFlags(int license_id, const std::vector<std::string> &flags) {
    try {
        pqxx::work tx(*m_db_manager.getConnection());
        std::string sql = "UPDATE licenses SET flags = $1 WHERE id = $2;";
        pqxx::result result = tx.exec_params(sql, flags, license_id);
        tx.commit();
        return result.affected_rows() > 0;
    } catch (const std::exception& e) {
        std::cerr << "Error while setting flags: " << e.what() << std::endl;
        return false;
    }
}

/**
 * @brief Updates the tier for a specific license.
 * @param license_id The ID of the license to modify.
 * @param tier The new tier value.
 * @return True on successful update, false otherwise.
 */
bool LicenseManager::setTier(int license_id, int tier) {
    try {
        pqxx::work tx(*m_db_manager.getConnection());
        std::string sql = "UPDATE licenses SET tier = $1 WHERE id = $2;";
        pqxx::result result = tx.exec_params(sql, tier, license_id);
        tx.commit();
        return result.affected_rows() > 0;
    }  catch (const std::exception& e) {
        std::cerr << "Error while setting tier: " << e.what() << std::endl;
        return false;
    }
}

/**
 * @brief Sets the maximum number of machines that can be activated on a license.
 * @param license_id The ID of the license to modify.
 * @param max_allowed_machines The new limit for allowed machines.
 * @return True on successful update, false otherwise.
 */
bool LicenseManager::setMaxAllowedMachines(int license_id, int max_allowed_machines) {
    try {
        pqxx::work tx(*m_db_manager.getConnection());
        std::string sql = "UPDATE licenses SET max_allowed_machines = $1 WHERE id = $2;";
        pqxx::result result = tx.exec_params(sql, max_allowed_machines, license_id);
        tx.commit();
        return result.affected_rows() > 0;
    }  catch (const std::exception& e) {
        std::cerr << "Error while setting max allowed machines: " << e.what() << std::endl;
        return false;
    }
}

/**
 * @brief Sets the current count of activated machines on a license.
 * @param license_id The ID of the license to modify.
 * @param number_of_machines The new value for the number of activated machines.
 * @return True on successful update, false otherwise.
 */
bool LicenseManager::setNumberMachines(int license_id, int number_of_machines) {
    try {
        pqxx::work tx(*m_db_manager.getConnection());
        std::string sql = "UPDATE licenses SET number_of_machines = $1 WHERE id = $2;";
        pqxx::result result = tx.exec_params(sql, number_of_machines, license_id);
        tx.commit();
        return result.affected_rows() > 0;
    } catch (const std::exception& e) {
        std::cerr << "Error while setting number_of_machines: " << e.what() << std::endl;
        return false;
    }
}

/**
 * @brief Atomically increments the number of activated machines on a license.
 * @param license_id The ID of the license to modify.
 * @param number_to_add The number to add to the current machine count (typically 1).
 * @return True on successful update, false otherwise.
 */
bool LicenseManager::addNumberMachines(int license_id, int number_to_add) {
    try {
        pqxx::work tx(*m_db_manager.getConnection());
        std::string sql = "UPDATE licenses SET number_of_machines = number_of_machines + $1 WHERE id = $2;";
        pqxx::result result = tx.exec_params(sql, number_to_add, license_id);
        tx.commit();
        return result.affected_rows() > 0;
    } catch (const std::exception& e) {
        std::cerr << "Error while adding to number_of_machines: " << e.what() << std::endl;
        return false;
    }
}

/**
 * @brief Sets the expiration date of a license based on a duration from its creation date.
 * @param license_id The ID of the license to modify.
 * @param duration The duration (in seconds) from the creation time at which the license should expire.
 * @return True on successful update, false otherwise.
 */
bool LicenseManager::setDuration(int license_id, const std::chrono::seconds &duration) {
    try {
        pqxx::work tx(*m_db_manager.getConnection());
        std::string update_sql = R"(
            UPDATE licenses
            SET expires_at = created_at + ($1 * INTERVAL '1 second')
            WHERE id = $2;
        )";

        tx.exec_params(update_sql, duration.count(), license_id);
        tx.commit();
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error while setting duration of a license: " << e.what() << std::endl;
        return false;
    }
}

/**
 * @brief Checks if a license is currently expired.
 * @param license_id The ID of the license to check.
 * @return True if the license's `expires_at` date is in the past, false otherwise. Returns true on error.
 */
bool LicenseManager::isExpired(int license_id) {
    try {
        pqxx::read_transaction tx(*m_db_manager.getConnection());
        std::string sql = R"(
            SELECT EXISTS (
                SELECT 1
                FROM licenses
                WHERE id = $1 AND expires_at < NOW()
            );
        )";
        pqxx::result result = tx.exec_params(sql, license_id);

        if (result.empty()) {
            return true;
        }
        return result[0][0].as<bool>();
    } catch (const std::exception& e) {
        std::cerr << "Error while checking if license is expired: " << e.what() << std::endl;
        return true;
    }
}
