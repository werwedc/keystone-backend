#include "CrowApp.h"

using traits = jwt::traits::kazuho_picojson;

CrowApp::CrowApp(AccountManager& accountManager, ApplicationsManager& applicationsManager, LicenseManager& licenseManager)
	:m_accountManager(accountManager), m_applicationsManager(applicationsManager), m_licenseManager(licenseManager)
{
}

void CrowApp::initializeRoutes()
{
	CROW_ROUTE(app, "/about")([]() {
		return "Hello world";
		});

	CROW_ROUTE(app, "/api/auth/register")
		.methods("POST"_method)
		([this](const crow::request& req) {
			// Parse JSON
			const auto body = crow::json::load(req.body);
			if (!body) {
				return crow::response(400, "Invalid JSON payload");
			}

			// Extract fields
			if (!body.has("email") || !body.has("password")) {
				return crow::response(400, "Missing required fields: email and/or password");
			}
			const std::string email = body["email"].s();
			const std::string password = body["password"].s();

			// Validate data
			if (m_accountManager.doesAccountExist(email)) {
				return crow::response(409, "Email already exists");
			}
			if (!m_accountManager.isPasswordSecure(password)) {
				return crow::response(400, "Password is not secure");
			}

			// Create account
			return m_accountManager.createAccount(email, password)
				? crow::response(201, "Account created successfully")
				: crow::response(400, "Account creation failed");
		});

	CROW_ROUTE(app, "/api/auth/login")
		.methods("POST"_method)
		([this](const crow::request& req) {
			// Parse JSON
			auto json = crow::json::load(req.body);
			if (!json) return crow::response(400, "Invalid JSON");
			if (!json.has("email")) return crow::response(400, "Missing email");
			if (!json.has("password")) return crow::response(400, "Missing password");

			const std::string email = json["email"].s();
			const std::string password = json["password"].s();

			// Authenticate
			if (!m_accountManager.tryLogIn(email, password)) {
				return crow::response(401, "Invalid credentials");
			}

			// Get account details
			auto account = m_accountManager.getAccountDetails(email);

			// Build roles
			picojson::array roles_array;
			roles_array.reserve(account->roles.size());
			for (const auto& role : account->roles) {
				roles_array.emplace_back(role);
			}

			auto make_token = [&](std::chrono::seconds ttl) {
				return jwt::create<traits>()
					.set_issuer("keystone")
					.set_type("JWT")
					.set_payload_claim("user_id", picojson::value(static_cast<int64_t>(account->id)))
					.set_payload_claim("email", picojson::value(account->email))
					.set_payload_claim("roles", picojson::value(roles_array))
					.set_issued_now()
					.set_expires_in(ttl)
					.sign(jwt::algorithm::hs256{"secret"});
			};

			// Generate tokens
			std::string access_token  = make_token(std::chrono::seconds{15 * 60});
			std::string refresh_token = make_token(std::chrono::seconds{24 * 60 * 60 * 7});

			// Store refresh token
			m_accountManager.storeRefreshTokenHash(account->id, m_accountManager.hash_token(refresh_token));

			// Respond
			return crow::response(200, crow::json::wvalue({
				{"access_token",  access_token},
				{"refresh_token", refresh_token}
			}));
	});

	CROW_ROUTE(app, "/api/auth/refresh")
		.methods("POST"_method)
		([this](const crow::request& req) {
		    // Parse JSON
		    auto json = crow::json::load(req.body);
		    if (!json) return crow::response(400, "Invalid JSON");
		    if (!json.has("refresh_token")) return crow::response(400, "Missing refresh token");

		    const std::string refresh_token = json["refresh_token"].s();

		    try {
		        // Verify refresh token
		        auto verifier = jwt::verify<traits>()
		            .with_issuer("keystone")
		            .allow_algorithm(jwt::algorithm::hs256{"secret"});

		        auto decoded = jwt::decode<traits>(refresh_token);
		        verifier.verify(decoded);

		        // Validate token hash
		        const int user_id = decoded.get_payload_claim("user_id").as_integer();
		        auto stored_hash_opt = m_accountManager.getRefreshTokenHash(user_id);
		        if (!stored_hash_opt.has_value() ||
		            m_accountManager.hash_token(refresh_token) != stored_hash_opt.value()) {
		            return crow::response(401, "Invalid refresh token");
		        }

		        // Extract claims
		        const std::string email = decoded.get_payload_claim("email").as_string();
		        const auto roles_claim = decoded.get_payload_claim("roles").as_array();

		        // Create access token
		        auto make_access_token = [&](std::chrono::seconds ttl) {
		            return jwt::create<traits>()
		                .set_issuer("keystone")
		                .set_type("JWT")
		                .set_payload_claim("user_id", picojson::value(static_cast<int64_t>(user_id)))
		                .set_payload_claim("email", picojson::value(email))
		                .set_payload_claim("roles", picojson::value(roles_claim))
		                .set_issued_now()
		                .set_expires_in(ttl)
		                .sign(jwt::algorithm::hs256{"secret"});
		        };

		        // Generate access token
		        std::string new_access_token = make_access_token(std::chrono::seconds{15 * 60});

		        return crow::response(200, crow::json::wvalue({
		            {"access_token", new_access_token}
		        }));

		    } catch (const std::exception&) {
		        return crow::response(401, "Invalid refresh token");
		    }
		});

	CROW_ROUTE(app, "/api/auth/logout")
		.methods("POST"_method)
		([this](const crow::request& req) {
			// Parse JSON
			auto json = crow::json::load(req.body);
			if (!json) return crow::response(400, "Invalid JSON");
			if (!json.has("refresh_token")) return crow::response(400, "Missing refresh token");

			const std::string refresh_token = json["refresh_token"].s();

			try {
				// Verify token
				auto decoded = jwt::decode<traits>(refresh_token);
				jwt::verify<traits>()
					.with_issuer("keystone")
					.allow_algorithm(jwt::algorithm::hs256{"secret"})
					.verify(decoded);

				// Get user ID
				const int user_id = decoded.get_payload_claim("user_id").as_integer();

				// Delete refresh token
				if (m_accountManager.deleteRefreshTokenHash(user_id)) {
					return crow::response(200, "Logged out successfully");
				}
				return crow::response(500, "Failed to log out");

			} catch (const std::exception&) {
				return crow::response(401, "Invalid refresh token");
			}
		});

	CROW_ROUTE(app, "/api/applications/create")
	.methods("POST"_method)
	([this](const crow::request& req) {
		auto json = crow::json::load(req.body);
		if (!json) return crow::response(400, "Invalid JSON");
		if (!json.has("name")) return crow::response(400, "Missing name");
		if (!json.has("access_token")) return crow::response(400, "Missing access token");

		const std::string name = json["name"].s();
		const std::string access_token = json["access_token"].s();

		// Auth
		auto user_id = verifyAccessTokenAndGetUserID(access_token);
		if (!user_id) return crow::response(401, "Invalid access token");

		if (m_applicationsManager.createApplication(*user_id, name)) {
			return crow::response(200, "Application created successfully");
		}
		return crow::response(500, "Failed to create application");
	});

	CROW_ROUTE(app, "/api/applications/delete")
		.methods("POST"_method)
		([this](const crow::request& req) {
			auto json = crow::json::load(req.body);
			if (!json) {
				return crow::response(400, "Invalid JSON");
			}
			if (!json.has("application_id")) return crow::response(400, "Missing application_id");
			if (!json.has("access_token")) return crow::response(400, "Missing access token");

			std::string access_token = json["access_token"].s();
			int application_id = json["application_id"].i();

			// Auth
			auto user_id = verifyAccessTokenAndGetUserID(access_token);
			if (!user_id) {
				return crow::response(401, "Invalid access token");
			}

			// Get application
			auto appDetailsOpt = m_applicationsManager.getApplication(application_id);
			if (!appDetailsOpt) {
				return crow::response(404, "Application not found");
			}

			const auto& appDetails = *appDetailsOpt;

			// Check ownership
			if (appDetails.user_id != *user_id) {
				return crow::response(403, "You do not own this application");
			}

			// Delete application
			if (m_applicationsManager.deleteApplication(application_id)) {
				return crow::response(200, "Application deleted successfully");
			} else {
				return crow::response(500, "Failed to delete application");
			}
		});

	CROW_ROUTE(app, "/api/applications/set_active")
		.methods("POST"_method)
		([this](const crow::request& req) {
			auto json = crow::json::load(req.body);
			if (!json) {
				return crow::response(400, "Invalid JSON");
			}
			if (!json.has("application_id")) return crow::response(400, "Missing application_id");
			if (!json.has("active")) return crow::response(400, "Missing active status");
			if (!json.has("access_token")) return crow::response(400, "Missing access token");

			std::string access_token = json["access_token"].s();
			int application_id = json["application_id"].i();
			bool active = json["active"].b();

			// Auth
			auto user_id = verifyAccessTokenAndGetUserID(access_token);
			if (!user_id) {
				return crow::response(401, "Invalid access token");
			}

			// Get application
			auto appDetailsOpt = m_applicationsManager.getApplication(application_id);
			if (!appDetailsOpt) {
				return crow::response(404, "Application not found");
			}

			const auto& appDetails = *appDetailsOpt;

			// Check ownership
			if (appDetails.user_id != *user_id) {
				return crow::response(403, "You do not own this application");
			}

			// Set active status
			if (m_applicationsManager.setActive(application_id, active)) {
				return crow::response(200, "Application active status updated successfully");
			} else {
				return crow::response(500, "Failed to update application active status");
			}
		});

	CROW_ROUTE(app, "/api/applications/rename")
		.methods("POST"_method)
		([this](const crow::request& req) {
			auto json = crow::json::load(req.body);
			if (!json) {
				return crow::response(400, "Invalid JSON");
			}
			if (!json.has("application_id")) return crow::response(400, "Missing application_id");
			if (!json.has("name")) return crow::response(400, "Missing new name");
			if (!json.has("access_token")) return crow::response(400, "Missing access token");

			std::string access_token = json["access_token"].s();
			int application_id = json["application_id"].i();
			std::string name = json["name"].s();

			// Auth
			auto user_id = verifyAccessTokenAndGetUserID(access_token);
			if (!user_id) {
				return crow::response(401, "Invalid access token");
			}

			// Get application
			auto appDetailsOpt = m_applicationsManager.getApplication(application_id);
			if (!appDetailsOpt) {
				return crow::response(404, "Application not found");
			}

			const auto& appDetails = *appDetailsOpt;

			// Check ownership
			if (appDetails.user_id != *user_id) {
				return crow::response(403, "You do not own this application");
			}

			// Rename application
			if (m_applicationsManager.renameApplication(application_id, name)) {
				return crow::response(200, "Application renamed successfully");
			} else {
				return crow::response(500, "Failed to rename application");
			}
		});

	CROW_ROUTE(app, "/api/applications/get_all")
		.methods("POST"_method)
		([this](const crow::request& req) {
			auto json = crow::json::load(req.body);
			if (!json) {
				return crow::response(400, "Invalid JSON");
			}
			if (!json.has("access_token")) return crow::response(400, "Missing access token");

			std::string access_token = json["access_token"].s();

			// Auth
			auto user_id = verifyAccessTokenAndGetUserID(access_token);
			if (!user_id) {
				return crow::response(401, "Invalid access token");
			}

			// Get applications
			std::vector<ApplicationDetails> applications = m_applicationsManager.getApplications(*user_id);

			// Build response
			crow::json::wvalue response_json;
			crow::json::wvalue::list applications_list;
			for (const auto& app_details : applications) {
				applications_list.emplace_back(crow::json::wvalue({
					{"id", app_details.id},
					{"user_id", app_details.user_id},
					{"name", app_details.name},
					{"active", app_details.active}
				}));
			}
			response_json["applications"] = std::move(applications_list);

			return crow::response(200, response_json);
		});

	CROW_ROUTE(app, "/api/licenses/create")
		.methods("POST"_method)
		([this](const crow::request& req) {
			auto json = crow::json::load(req.body);
			if (!json) {
				return crow::response(400, "Invalid JSON");
			}
			if (!json.has("application_id")) return crow::response(400, "Missing application_id");
			if (!json.has("license_key")) return crow::response(400, "Missing license_key");
			if (!json.has("tier")) return crow::response(400, "Missing tier");
			if (!json.has("access_token")) return crow::response(400, "Missing access_token");

			int application_id = json["application_id"].i();
			std::string license_key = json["license_key"].s();
			int tier = json["tier"].i();
			std::string access_token = json["access_token"].s();

			// Auth
			auto user_id = verifyAccessTokenAndGetUserID(access_token);
			if (!user_id) return crow::response(401, "Invalid access token");

			// Check ownership
			auto appDetailsOpt = m_applicationsManager.getApplication(application_id);
			if (!appDetailsOpt.has_value()) {
				return crow::response(404, "Application not found");
			}
			const auto& appDetails = *appDetailsOpt;
			if (appDetails.user_id != *user_id) {
				return crow::response(403, "You do not own this application");
			}

			// Create license
			if (m_licenseManager.createLicense(application_id, license_key, tier)) {
				return crow::response(200, "License created successfully");
			} else {
				return crow::response(500, "Failed to create license");
			}
		});
	CROW_ROUTE(app, "/api/licenses/delete")
		.methods("POST"_method)
		([this](const crow::request& req) {
			auto json = crow::json::load(req.body);
			if (!json) {
				return crow::response(400, "Invalid JSON");
			}
			if (!json.has("license_id")) return crow::response(400, "Missing license_id");
			if (!json.has("access_token")) return crow::response(400, "Missing access_token");

			int license_id = json["license_id"].i();
			std::string access_token = json["access_token"].s();

			// Auth
			auto user_id = verifyAccessTokenAndGetUserID(access_token);
			if (!user_id) return crow::response(401, "Invalid access token");

			// Get license
			auto licenseOpt = m_licenseManager.getLicense(license_id);
			if (!licenseOpt.has_value()) {
				return crow::response(404, "License not found");
			}
			const auto& licenseDetails = *licenseOpt;

			// Check ownership
			auto appDetailsOpt = m_applicationsManager.getApplication(licenseDetails.application_id);
			if (!appDetailsOpt.has_value()) {
				return crow::response(404, "Associated application not found");
			}
			const auto& appDetails = *appDetailsOpt;
			if (appDetails.user_id != *user_id) {
				return crow::response(403, "You do not own this application");
			}

			// Delete license
			if (m_licenseManager.deleteLicense(license_id)) {
				return crow::response(200, "License deleted successfully");
			} else {
				return crow::response(500, "Failed to delete license");
			}
		});
	CROW_ROUTE(app, "/api/licenses/get")
	    .methods("POST"_method)
	    ([this](const crow::request& req) {
	        auto json = crow::json::load(req.body);
	        if (!json) {
	            return crow::response(400, "Invalid JSON");
	        }
	        if (!json.has("license_id")) return crow::response(400, "Missing license_id");
	        if (!json.has("access_token")) return crow::response(400, "Missing access_token");

	        int license_id = json["license_id"].i();
	        std::string access_token = json["access_token"].s();

	        // Auth
	        auto user_id = verifyAccessTokenAndGetUserID(access_token);
	        if (!user_id) return crow::response(401, "Invalid access token");

	        // Get license
	        auto licenseOpt = m_licenseManager.getLicense(license_id);
	        if (!licenseOpt.has_value()) {
	            return crow::response(404, "License not found");
	        }
	        const auto& licenseDetails = *licenseOpt;

	        // Check ownership
	        auto appDetailsOpt = m_applicationsManager.getApplication(licenseDetails.application_id);
	        if (!appDetailsOpt.has_value()) {
	            return crow::response(404, "Associated application not found");
	        }
	        const auto& appDetails = *appDetailsOpt;
	        if (appDetails.user_id != *user_id) {
	            return crow::response(403, "You do not own this application");
	        }

	        // Build response
	        crow::json::wvalue resp;
	        resp["id"] = licenseDetails.id;
	        resp["application_id"] = licenseDetails.application_id;
	        resp["license_key"] = licenseDetails.license_key;
	        resp["tier"] = licenseDetails.tier;
	        resp["max_allowed_machines"] = licenseDetails.max_allowed_machines;
	        resp["created_at"] = licenseDetails.created_at;
	        resp["expires_at"] = licenseDetails.expires_at;

	        // Add flags
	        crow::json::wvalue::list flags_list;
	        for (const auto& flag : licenseDetails.flags) {
	            flags_list.emplace_back(flag);
	        }
	        resp["flags"] = std::move(flags_list);

	        return crow::response(200, resp);
	    });
	CROW_ROUTE(app, "/api/licenses/get_all")
	    .methods("POST"_method)
	    ([this](const crow::request& req) {
	        auto json = crow::json::load(req.body);
	        if (!json) {
	            return crow::response(400, "Invalid JSON");
	        }
	        if (!json.has("application_id")) return crow::response(400, "Missing application_id");
	        if (!json.has("access_token")) return crow::response(400, "Missing access_token");

	        int application_id = json["application_id"].i();
	        std::string access_token = json["access_token"].s();

	        // Auth
	        auto user_id = verifyAccessTokenAndGetUserID(access_token);
	        if (!user_id) return crow::response(401, "Invalid access token");

	        // Check ownership
	        auto appDetailsOpt = m_applicationsManager.getApplication(application_id);
	        if (!appDetailsOpt.has_value()) {
	            return crow::response(404, "Application not found");
	        }
	        const auto& appDetails = *appDetailsOpt;
	        if (appDetails.user_id != *user_id) {
	            return crow::response(403, "You do not own this application");
	        }

	        // Get licenses
	        auto licenses = m_licenseManager.getLicenses(application_id);

	        // Build response
	        crow::json::wvalue resp;
	        crow::json::wvalue::list licenses_list;
	        for (const auto& license : licenses) {
	            crow::json::wvalue license_json;
	            license_json["id"] = license.id;
	            license_json["application_id"] = license.application_id;
	            license_json["license_key"] = license.license_key;
	            license_json["tier"] = license.tier;
	            license_json["max_allowed_machines"] = license.max_allowed_machines;
	            license_json["created_at"] = license.created_at;
	            license_json["expires_at"] = license.expires_at;

	            // Add flags
	            crow::json::wvalue::list flags_list;
	            for (const auto& flag : license.flags) {
	                flags_list.emplace_back(flag);
	            }
	            license_json["flags"] = std::move(flags_list);

	            licenses_list.emplace_back(std::move(license_json));
	        }
	        resp["licenses"] = std::move(licenses_list);

	        return crow::response(200, resp);
	    });

    CROW_ROUTE(app, "/api/licenses/set_tier")
       .methods("POST"_method)
       ([this](const crow::request& req) {
           auto json = crow::json::load(req.body);
           if (!json) return crow::response(400, "Invalid JSON");
           if (!json.has("license_id") || !json.has("tier") || !json.has("access_token")) {
               return crow::response(400, "Missing required fields");
           }

           int license_id = json["license_id"].i();
           int tier = json["tier"].i();
           std::string access_token = json["access_token"].s();

           // Auth
           auto user_id = verifyAccessTokenAndGetUserID(access_token);
           if (!user_id) return crow::response(401, "Invalid access token");

           auto licenseOpt = m_licenseManager.getLicense(license_id);
           if (!licenseOpt) return crow::response(404, "License not found");

           auto appOpt = m_applicationsManager.getApplication(licenseOpt->application_id);
           if (!appOpt || appOpt->user_id != *user_id) {
               return crow::response(403, "Permission denied");
           }

           if (m_licenseManager.setTier(license_id, tier)) {
               return crow::response(200, "License tier updated successfully");
           }
           return crow::response(500, "Failed to update license tier");
       });

    CROW_ROUTE(app, "/api/licenses/set_max_machines")
       .methods("POST"_method)
       ([this](const crow::request& req) {
           auto json = crow::json::load(req.body);
           if (!json) return crow::response(400, "Invalid JSON");
           if (!json.has("license_id") || !json.has("max_machines") || !json.has("access_token")) {
               return crow::response(400, "Missing required fields");
           }

           int license_id = json["license_id"].i();
           int max_machines = json["max_machines"].i();
           std::string access_token = json["access_token"].s();

           // Auth
           auto user_id = verifyAccessTokenAndGetUserID(access_token);
           if (!user_id) return crow::response(401, "Invalid access token");

           auto licenseOpt = m_licenseManager.getLicense(license_id);
           if (!licenseOpt) return crow::response(404, "License not found");

           auto appOpt = m_applicationsManager.getApplication(licenseOpt->application_id);
           if (!appOpt || appOpt->user_id != *user_id) {
               return crow::response(403, "Permission denied");
           }

           if (m_licenseManager.setMaxAllowedMachines(license_id, max_machines)) {
               return crow::response(200, "Max allowed machines updated successfully");
           }
           return crow::response(500, "Failed to update max allowed machines");
       });

    CROW_ROUTE(app, "/api/licenses/set_flags")
       .methods("POST"_method)
       ([this](const crow::request& req) {
           auto json = crow::json::load(req.body);
           if (!json) return crow::response(400, "Invalid JSON");
           if (!json.has("license_id") || !json.has("flags") || !json.has("access_token")) {
               return crow::response(400, "Missing required fields");
           }

           int license_id = json["license_id"].i();
           std::string access_token = json["access_token"].s();

           std::vector<std::string> flags;
           for (const auto& flag_val : json["flags"].lo()) {
               flags.push_back(flag_val.s());
           }

           // Auth
           auto user_id = verifyAccessTokenAndGetUserID(access_token);
           if (!user_id) return crow::response(401, "Invalid access token");

           auto licenseOpt = m_licenseManager.getLicense(license_id);
           if (!licenseOpt) return crow::response(404, "License not found");

           auto appOpt = m_applicationsManager.getApplication(licenseOpt->application_id);
           if (!appOpt || appOpt->user_id != *user_id) {
               return crow::response(403, "Permission denied");
           }

           if (m_licenseManager.setFlags(license_id, flags)) {
               return crow::response(200, "License flags set successfully");
           }
           return crow::response(500, "Failed to set license flags");
       });

    CROW_ROUTE(app, "/api/licenses/set_duration")
       .methods("POST"_method)
       ([this](const crow::request& req) {
           auto json = crow::json::load(req.body);
           if (!json) return crow::response(400, "Invalid JSON");
           if (!json.has("license_id") || !json.has("duration_seconds") || !json.has("access_token")) {
               return crow::response(400, "Missing required fields");
           }

           int license_id = json["license_id"].i();
           long long duration_val = json["duration_seconds"].i();
           std::string access_token = json["access_token"].s();

           // Auth
           auto user_id = verifyAccessTokenAndGetUserID(access_token);
           if (!user_id) return crow::response(401, "Invalid access token");

           auto licenseOpt = m_licenseManager.getLicense(license_id);
           if (!licenseOpt) return crow::response(404, "License not found");

           auto appOpt = m_applicationsManager.getApplication(licenseOpt->application_id);
           if (!appOpt || appOpt->user_id != *user_id) {
               return crow::response(403, "Permission denied");
           }

           if (m_licenseManager.setDuration(license_id, std::chrono::seconds(duration_val))) {
               return crow::response(200, "License duration updated successfully");
           }
           return crow::response(500, "Failed to update license duration");
       });

    CROW_ROUTE(app, "/api/licenses/is_expired")
       .methods("POST"_method)
       ([this](const crow::request& req) {
           auto json = crow::json::load(req.body);
           if (!json) return crow::response(400, "Invalid JSON");
           if (!json.has("license_id") || !json.has("access_token")) {
               return crow::response(400, "Missing required fields");
           }

           int license_id = json["license_id"].i();
           std::string access_token = json["access_token"].s();

           // Auth
           auto user_id = verifyAccessTokenAndGetUserID(access_token);
           if (!user_id) return crow::response(401, "Invalid access token");

           auto licenseOpt = m_licenseManager.getLicense(license_id);
           if (!licenseOpt) return crow::response(404, "License not found");

           auto appOpt = m_applicationsManager.getApplication(licenseOpt->application_id);
           if (!appOpt || appOpt->user_id != *user_id) {
               return crow::response(403, "Permission denied");
           }

           bool expired = m_licenseManager.isExpired(license_id);
           return crow::response(200, crow::json::wvalue({{"expired", expired}}));
       });

}

void CrowApp::run(int port)
{
	app.port(port).multithreaded().run();
}

std::optional<int> CrowApp::verifyAccessTokenAndGetUserID(const std::string &accessToken) {
	try {
		auto decoded = jwt::decode<traits>(accessToken);
		jwt::verify<traits>()
			.with_issuer("keystone")
			.allow_algorithm(jwt::algorithm::hs256{"secret"})
			.verify(decoded);

		return decoded.get_payload_claim("user_id").as_integer();
	} catch (...) {
		return std::nullopt;
	}
}
