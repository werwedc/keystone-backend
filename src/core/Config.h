#pragma once

#include <string>
#include <optional>
#include <iostream>
#include <libenvpp/env.hpp>

struct Config {
    const std::string db_conn_string;
    const std::string jwt_secret;

    static std::optional<Config> load_from_env() {
        auto pre = env::prefix("KEYSTONE");

        const auto db_conn_id = pre.register_required_variable<std::string>("DB_CONN_STRING");
        const auto jwt_secret_id = pre.register_required_variable<std::string>("JWT_SECRET");

        const auto parsed_and_validated_pre = pre.parse_and_validate();
        if (!parsed_and_validated_pre.ok()) {
            std::cerr << "!!! Configuration Error !!!\n"
                      << parsed_and_validated_pre.error_message() << std::endl;
            return std::nullopt;
        }

        return Config{
            parsed_and_validated_pre.get(db_conn_id),
            parsed_and_validated_pre.get(jwt_secret_id)
        };
    }

private:
    Config(std::string db_str, std::string jwt_str) :
        db_conn_string(std::move(db_str)), jwt_secret(std::move(jwt_str)) {}
};