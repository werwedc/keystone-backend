#include <crow.h>
#include "database/DatabaseManager.h"

int main()
{
    std::string conn_string = "";

    DatabaseManager dbManager(conn_string);

    if (dbManager.connect()) {
        std::cout << "Succesfully connected to the database";
    }
    else {
        std::cerr << "Could not connect to the database. Exiting." << std::endl;
        return 1; 
    }

    return 0;
}