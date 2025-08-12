#include "MachinesManager.h"

MachinesManager::MachinesManager(DatabaseManager& db_manager, LicenseManager& license_manager)
    : m_db_manager(db_manager), m_license_manager(license_manager) {
}

