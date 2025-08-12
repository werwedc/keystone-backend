#pragma once

#include <optional>
#include <vector>
#include <pqxx/pqxx>
#include "../client/AccountManager.h"

struct ApplicationDetails {
    int id;
    int user_id;
    std::string name;
    bool active;
};

class ApplicationsManager {
public:
    ApplicationsManager(AccountManager& account_manager, DatabaseManager& db_manager);
    bool createApplication(int user_id, const std::string& name);
    bool deleteApplication(int application_id);
    bool setActive(int application_id, bool active);
    bool setDuration(int application_id, const std::chrono::seconds& duration);
    bool isExpired(int application_id);
    bool renameApplication(int application_id, const std::string& name);
    std::optional<ApplicationDetails> getApplication(int application_id);
    std::vector<ApplicationDetails> getApplications(int user_id);
private:
    AccountManager& m_account_manager;
    DatabaseManager& m_db_manager;
};
