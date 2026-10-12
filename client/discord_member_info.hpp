#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace discord_member_info {

    struct discord_role {
        std::string id;
        std::string name;
        std::int32_t position = 0;
        std::int32_t color = 0;
        bool hoist = false;
        bool managed = false;
        bool mentionable = false;
    };

    struct discord_member_info {
        bool success = false;
        bool member = false;
        std::string discord_id;
        std::string pfp_url;
        std::string username;
        std::string display_name;
        std::string global_display_name;
        std::vector<discord_role> roles;
        bool has_highest_role = false;
        discord_role highest_role;
        std::string error;
    };

    struct discord_member_info_config {
        std::wstring endpoint;
        std::string pinned_transport_public_key_base64url;
        std::string pinned_server_public_key_pem;
        std::string expected_signing_key_id;
        std::string expected_issuer = "auth-server-discord-member-info";
        std::string expected_audience = "windows-client";
        std::string expected_guild_id;
    };

    class discord_member_info_client {
    public:
        explicit discord_member_info_client( discord_member_info_config config );

        discord_member_info get_discord_member_info(
            const std::string& license_key,
            const std::string& hwid,
            const std::string& discord_id ) const;

    private:
        discord_member_info_config config_;
    };

}