// --- MachinesManager.h (Complete Header) ---
#pragma once

#include <vector>
#include <string>
#include <optional>
#include <pqxx/pqxx>
#include "../../database/DatabaseManager.h"
#include "../licenses/LicenseManager.h"

struct MachineDetails {
    int id;
    int license_id;
    std::vector<std::string> IPs;
    std::string hwid;
    std::string created_at;
    std::optional<std::string> expires_at;
};

class MachinesManager {
public:
    MachinesManager(DatabaseManager& db_manager, LicenseManager& license_manager);

    bool createMachine(int license_id, const std::string& hwid, const std::string& ip);
    bool deleteMachine(const std::string& hwid);
    bool updateMachineIP(const std::string& hwid, const std::string& new_ip);
    bool isMachineLimitReached(int license_id);
    std::optional<MachineDetails> getMachineByHwid(const std::string& hwid);
    std::vector<MachineDetails> getMachinesForLicense(int license_id);
private:
    DatabaseManager& m_db_manager;
    LicenseManager& m_license_manager;
};
