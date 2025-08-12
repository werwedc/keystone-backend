#include "MachinesManager.h"
#include <iostream>
#include <sstream>
#include <pqxx/pqxx>

MachinesManager::MachinesManager(DatabaseManager& db_manager, LicenseManager& license_manager)
    : m_db_manager(db_manager), m_license_manager(license_manager) {
}

/**
 * @brief Attempts to register a new machine to a license.
 * @details This function will first check if the license has reached its machine limit.
 * If not, it will create a new machine record and atomically increment the `number_of_machines`
 * on the corresponding license record. The entire operation is performed in a single transaction.
 * @param license_id The ID of the license to associate the machine with.
 * @param hwid The unique hardware ID of the new machine.
 * @param ip The initial IP address of the machine.
 * @return True if the machine was created successfully, false otherwise.
 */
bool MachinesManager::createMachine(int license_id, const std::string& hwid, const std::string& ip) {
    if (isMachineLimitReached(license_id)) {
        std::cerr << "Machine limit has been reached for license ID: " << license_id << std::endl;
        return false;
    }

    try {
        pqxx::work tx(*m_db_manager.getConnection());

        std::string check_sql = "SELECT EXISTS(SELECT 1 FROM machines WHERE license_id = $1 AND hwid = $2);";
        pqxx::result check_res = tx.exec_params(check_sql, license_id, hwid);
        if (check_res[0][0].as<bool>()) {
            std::cerr << "Error: Machine with this HWID already exists for this license." << std::endl;
            return false;
        }

        std::string insert_sql = "INSERT INTO machines (license_id, hwid, ips) VALUES ($1, $2, ARRAY[$3]);";
        tx.exec_params(insert_sql, license_id, hwid, ip);

        std::string update_sql = "UPDATE licenses SET number_of_machines = number_of_machines + 1 WHERE id = $1;";
        tx.exec_params(update_sql, license_id);

        tx.commit();
        std::cout << "Successfully created machine for license ID: " << license_id << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error in createMachine transaction: " << e.what() << std::endl;
        return false;
    }
}

/**
 * @brief Deletes a machine record identified by its hardware ID.
 * @details Finds the machine by its HWID, deletes it, and atomically decrements the
 * `number_of_machines` count on the associated license. This is performed in a single transaction.
 * @param hwid The unique hardware ID of the machine to delete.
 * @return True if the machine was deleted successfully, false if the HWID was not found or an error occurred.
 */
bool MachinesManager::deleteMachine(const std::string& hwid) {
     try {
        pqxx::work tx(*m_db_manager.getConnection());

        std::string select_sql = "SELECT license_id FROM machines WHERE hwid = $1;";
        pqxx::result select_res = tx.exec_params(select_sql, hwid);

        if (select_res.empty()) {
            std::cerr << "Cannot delete machine: HWID not found." << std::endl;
            return false;
        }
        int license_id = select_res[0][0].as<int>();

        std::string delete_sql = "DELETE FROM machines WHERE hwid = $1;";
        pqxx::result delete_res = tx.exec_params(delete_sql, hwid);

        if (delete_res.affected_rows() == 0) {
            return false;
        }

        std::string update_sql = "UPDATE licenses SET number_of_machines = number_of_machines - 1 WHERE id = $1 AND number_of_machines > 0;";
        tx.exec_params(update_sql, license_id);

        tx.commit();
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error in deleteMachine transaction: " << e.what() << std::endl;
        return false;
    }
}

/**
 * @brief Appends a new IP address to a machine's historical IP list.
 * @param hwid The unique hardware ID of the machine to update.
 * @param new_ip The new IP address to add to the list.
 * @return True on successful update, false otherwise.
 */
bool MachinesManager::updateMachineIP(const std::string& hwid, const std::string& new_ip) {
    try {
        pqxx::work tx(*m_db_manager.getConnection());
        std::string sql = "UPDATE machines SET ips = array_append(ips, $1) WHERE hwid = $2;";
        pqxx::result result = tx.exec_params(sql, new_ip, hwid);
        tx.commit();
        return result.affected_rows() > 0;
    } catch (const std::exception& e) {
        std::cerr << "Error while updating machine IP: " << e.what() << std::endl;
        return false;
    }
}

/**
 * @brief Checks if a given license has reached its maximum number of activated machines.
 * @param license_id The ID of the license to check.
 * @return True if the number of active machines is greater than or equal to the maximum allowed, false otherwise.
 */
bool MachinesManager::isMachineLimitReached(int license_id) {
    auto licenseOpt = m_license_manager.getLicense(license_id);
    if (!licenseOpt) {
        return true;
    }
    return licenseOpt->number_of_machines >= licenseOpt->max_allowed_machines;
}

/**
 * @brief Retrieves the details of a single machine by its unique hardware ID.
 * @param hwid The hardware ID of the machine to find.
 * @return An std::optional containing the MachineDetails struct if found, otherwise std::nullopt.
 */
std::optional<MachineDetails> MachinesManager::getMachineByHwid(const std::string& hwid) {
    try {
        pqxx::read_transaction tx(*m_db_manager.getConnection());
        std::string sql = "SELECT id, license_id, ips, hwid, created_at, expires_at FROM machines WHERE hwid = $1;";
        pqxx::result result = tx.exec_params(sql, hwid);

        if (result.empty()) {
            return std::nullopt;
        }

        const auto& row = result[0];
        MachineDetails machine;
        machine.id = row["id"].as<int>();
        machine.license_id = row["license_id"].as<int>();
        machine.hwid = row["hwid"].as<std::string>();
        machine.created_at = row["created_at"].as<std::string>();

        if (!row["expires_at"].is_null()) {
            machine.expires_at = row["expires_at"].as<std::string>();
        }

        if (!row["ips"].is_null()) {
             std::string ip_array_str = row["ips"].as<std::string>();
             ip_array_str = ip_array_str.substr(1, ip_array_str.length() - 2); // Remove {}
             std::stringstream ss(ip_array_str);
             std::string segment;
             while(std::getline(ss, segment, ',')) {
                machine.IPs.push_back(segment);
             }
        }

        return machine;
    } catch (const std::exception& e) {
        std::cerr << "Error while getting machine by HWID: " << e.what() << std::endl;
        return std::nullopt;
    }
}

/**
 * @brief Retrieves all machine details associated with a specific license.
 * @param license_id The ID of the license whose machines are to be fetched.
 * @return A vector of MachineDetails structs. The vector will be empty if no machines are found or an error occurs.
 */
std::vector<MachineDetails> MachinesManager::getMachinesForLicense(int license_id) {
    std::vector<MachineDetails> machines;
     try {
        pqxx::read_transaction tx(*m_db_manager.getConnection());
        std::string sql = "SELECT id, license_id, ips, hwid, created_at, expires_at FROM machines WHERE license_id = $1;";
        pqxx::result result = tx.exec_params(sql, license_id);

        for (const auto& row : result) {
            MachineDetails machine;
            machine.id = row["id"].as<int>();
            machine.license_id = row["license_id"].as<int>();
            machine.hwid = row["hwid"].as<std::string>();
            machine.created_at = row["created_at"].as<std::string>();

            if (!row["expires_at"].is_null()) {
                machine.expires_at = row["expires_at"].as<std::string>();
            }

            if (!row["ips"].is_null()) {
                 std::string ip_array_str = row["ips"].as<std::string>();
                 ip_array_str = ip_array_str.substr(1, ip_array_str.length() - 2);
                 std::stringstream ss(ip_array_str);
                 std::string segment;
                 while(std::getline(ss, segment, ',')) {
                    machine.IPs.push_back(segment);
                 }
            }
            machines.push_back(machine);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error while getting machines for license: " << e.what() << std::endl;
    }
    return machines;
}

/**
 * @brief Validates and activates a machine for a given license.
 * @details This is the primary entry point for a client application "phoning home".
 * If the machine's HWID is already registered to the correct license, its IP is updated.
 * If the HWID is new, it attempts to activate it by calling createMachine().
 * If the HWID is registered to a *different* license, the activation fails.
 * @param license_id The ID of the license being activated against.
 * @param hwid The unique hardware ID of the client machine.
 * @param ip The current IP address of the client machine.
 * @return True if the machine is valid and activated/updated, false otherwise.
 */
bool MachinesManager::validateAndActivateMachine(int license_id, const std::string& hwid, const std::string& ip) {
    auto existingMachine = getMachineByHwid(hwid);

    if (existingMachine) {
        if (existingMachine->license_id != license_id) {
            std::cerr << "Error: This machine (HWID: " << hwid << ") is already registered to a different license." << std::endl;
            return false;
        }
        return updateMachineIP(hwid, ip);
    } else {
        return createMachine(license_id, hwid, ip);
    }
}
