# Specify the minimum version of CMake required.
cmake_minimum_required(VERSION 3.15)

# Define the project name.
project(KeystoneBackend)

# Set the C++ standard you want to use.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Find Dependencies (Modern Method) ---
# This is the most robust way to find packages with vcpkg.
# We will use the exact target names provided by the packages.
find_package(Crow CONFIG REQUIRED)
find_package(libpqxx CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

# --- Create Executable ---
add_executable(server src/main.cpp "src/database/DatabaseManager.cpp" "src/database/DatabaseManager.h" "src/core/Server.cpp" "src/core/Server.h")

# --- Link Dependencies (Modern Method) ---
# Link against the imported targets. This automatically handles
# include directories, library files (debug/release), and other settings.
# The target for Crow is "Crow::Crow"
# The target for libpqxx is "libpqxx::pqxx"
target_link_libraries(server PRIVATE
    Crow::Crow
    libpqxx::pqxx
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
)

# workaround to remove error: "C++ command-line error: invalid macro definition: _CROW_ICD-NOTFOUND"
# (see https://github.com/CrowCpp/Crow/issues/661#issuecomment-1702544225)
list(REMOVE_ITEM _CROW_ICD "_CROW_ICD-NOTFOUND")
set_target_properties(Crow::Crow PROPERTIES INTERFACE_COMPILE_DEFINITIONS "${_CROW_ICD}")
