#include "LicenseManager.h"

LicenseManager::LicenseManager(ApplicationsManager &applications_manager, DatabaseManager &db_manager)
    : m_applications_manager(applications_manager), m_db_manager(db_manager) {

}

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

bool LicenseManager::deleteLicense(int license_id) {
    try {
        pqxx::work tx(*m_db_manager.getConnection());
        std::string sql = "DELETE FROM licenses WHERE id = $1;";

        pqxx::result result = tx.exec_params(sql, application_id);
        tx.commit();
        return result.affected_rows() > 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Error while deleting license: " << e.what() << std::endl;
        return false;
    }
}


std::optional<LicenseDetails> LicenseManager::getLicense(int license_id) {
    try {
        pqxx::work tx(*m_db_manager.getConnection());
        std::string sql =
            "SELECT id, application_id, license_key, flags, tier, max_allowed_machines, created_at, expires_at "
            "FROM licenses WHERE id = $1;";
        pqxx::result result = tx.exec_params(sql, license_id);
        tx.commit();

        if (result.empty()) {
            return std::nullopt; // License not found
        }

        LicenseDetails license;
        license.id = result[0][0].as<int>();
        license.application_id = result[0][1].as<int>();
        license.license_key = result[0][2].as<std::string>();

        // Handle flags (text[] to std::vector<std::string>)
        if (!result[0][3].is_null()) {
            std::string flags_str = result[0][3].as<std::string>();
            if (flags_str.length() > 2) { // Not "{}"
                flags_str = flags_str.substr(1, flags_str.length() - 2);
                std::stringstream ss(flags_str);
                std::string segment;
                while (std::getline(ss, segment, ',')) {
                    license.flags.push_back(segment);
                }
            }
        }

        license.tier = result[0][4].as<int>();
        license.max_allowed_machines = result[0][5].as<int>();
        license.created_at = result[0][6].as<std::string>();
        license.expires_at = result[0][7].as<std::string>();

        return license;
    } catch (const std::exception& e) {
        std::cerr << "Error while getting license: " << e.what() << std::endl;
        return std::nullopt;
    }
}

std::vector<LicenseDetails> LicenseManager::getLicenses(int application_id) {
    std::vector<LicenseDetails> licenses;
    try {
        pqxx::work tx(*m_db_manager.getConnection());
        std::string sql = "SELECT id, application_id, license_key, flags, tier, max_allowed_machines, created_at, expires_at FROM licenses WHERE application_id = $1;";
        pqxx::result result = tx.exec_params(sql, application_id);
        tx.commit();

        for (const auto& row : result) {
            LicenseDetails license;
            license.id = row[0].as<int>();
            license.application_id = row[1].as<int>();
            license.license_key = row[2].as<std::string>();

            // Handle flags (text[] to std::vector<std::string>)
            if (!row[3].is_null()) {
                std::string flags_str = row[3].as<std::string>();
                // Remove curly braces and split by comma
                if (flags_str.length() > 2) { // Check if not empty array {}
                    flags_str = flags_str.substr(1, flags_str.length() - 2); // Remove {}
                    std::stringstream ss(flags_str);
                    std::string segment;
                    while(std::getline(ss, segment, ',')) {
                        license.flags.push_back(segment);
                    }
                }
            }

            license.tier = row[4].as<int>();
            license.max_allowed_machines = row[5].as<int>();
            license.created_at = row[6].as<std::string>();
            license.expires_at = row[7].as<std::string>();
            licenses.push_back(license);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error while getting licenses for application: " << e.what() << std::endl;
    }
    return licenses;
}

bool LicenseManager::addFlags(int license_id, const std::vector<std::string> &flags) {
    try {
        pqxx::work tx(*m_db_manager.getConnection());

        // The `pqxx` library can convert a std::vector<std::string> directly
        // to the correct array representation for a PostgreSQL parameter.
        std::string sql = "UPDATE licenses SET flags = array_cat(flags, $1) WHERE id = $2;";

        pqxx::result result = tx.exec_params(sql, flags, license_id);

        tx.commit();
        return result.affected_rows() > 0;
    } catch (const std::exception& e) {
        std::cerr << "Error while adding flags: " << e.what() << std::endl;
        return false;
    }

}

bool LicenseManager::setFlags(int license_id, const std::vector<std::string> &flags) {
    try {
        pqxx::work tx(*m_db_manager.getConnection());

        // The `pqxx` library can convert a std::vector<std::string> directly
        // to the correct array representation for a PostgreSQL parameter.
        std::string sql = "UPDATE licenses SET flags = $1 WHERE id = $2;";

        pqxx::result result = tx.exec_params(sql, flags, license_id);

        tx.commit();
        return result.affected_rows() > 0;
    } catch (const std::exception& e) {
        std::cerr << "Error while adding flags: " << e.what() << std::endl;
        return false;
    }

}

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

bool LicenseManager::setDuration(int license_id, const std::chrono::seconds &duration) {
    try {
        pqxx::work tx(*m_db_manager.getConnection());
        std::string sql = "SELECT created_at from licenses WHERE id = $1;";

        const pqxx::result result = tx.exec_params(sql, license_id);
        tx.commit();
        if (!result.empty()) {
            std::string update_sql = R"(
                UPDATE licenses
                SET expires_at = created_at + ($1 * INTERVAL '1 second')
                WHERE id = $2;
            )";

            tx.exec_params(update_sql, duration.count(), license_id);

            tx.commit();
            return true;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error while setting duration of a license: " << e.what() << std::endl;
        return false;
    }
}

bool LicenseManager::isExpired(int license_id) {
    try {
        pqxx::work tx(*m_db_manager.getConnection());

        std::string sql = R"(
                SELECT EXISTS (
                    SELECT 1
                    FROM licenses
                    WHERE id = $1 AND expires_at < NOW()
                );
            )";
        pqxx::result result = tx.exec_params(sql, license_id);

        tx.commit();
        if (result.empty()) {
            return true;
        }
        return result[0][0].as<bool>();
    } catch (const std::exception& e) {
        std::cerr << "Error while checking if license is expired: " << e.what() << std::endl;
        // On error, treat as expired (conservative)
        return true;

    }
}
