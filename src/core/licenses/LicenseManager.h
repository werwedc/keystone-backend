#pragma once
#include <string>
#include <vector>

#include "../../database/DatabaseManager.h"
#include "../applications/ApplicationsManager.h"

struct LicenseDetails {
    int id;
    int application_id;
    std::string license_key;
    std::vector<std::string> flags;
    int tier;
    int max_allowed_machines;
    std::string created_at;
    std::string expires_at;
};

class LicenseManager {
public:
    LicenseManager(ApplicationsManager& applications_manager, DatabaseManager& db_manager);
    bool createLicense(int application_id, const std::string& license_key, int tier);
    bool deleteLicense(int license_id);
    std::optional<LicenseDetails> getLicense(int license_id);
    std::vector<LicenseDetails> getLicenses(int application_id);
    bool addFlags(int license_id, const std::vector<std::string>& flags);
    bool setFlags(int license_id, const std::vector<std::string>& flags);
    bool setTier(int license_id, int tier);
    bool setMaxAllowedMachines(int license_id, int max_allowed_machines);
    bool setDuration(int license_id, const std::chrono::seconds& duration);
    bool isExpired(int license_id);
private:
    ApplicationsManager& m_applications_manager;
    DatabaseManager& m_db_manager;
};
