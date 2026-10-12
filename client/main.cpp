#include <iostream>
#include <string>
#include "auth_module.hpp"

int main( int argc, char** argv ) {
    const std::string endpoint = argc > 1 ? argv[ 1 ] : "127.0.0.1:2230";

    std::string key;
    std::cout << "License key: ";

    if ( !std::getline( std::cin, key ) || key.empty( ) ) {
        std::cerr << "Failed to read license key." << std::endl;
        return 1;
    }

    const std::string hwid = auth::generate_hwid( );

    if ( hwid.empty( ) ) {
        std::cerr << "Failed to compute the device identifier." << std::endl;
        return 1;
    }

    auth::client_t client( endpoint );
    const auth::session_t session = client.authenticate( key, hwid );

    if ( !session.success ) {
        std::cerr << session.message << std::endl;
        return 1;
    }

    const std::uint64_t now = auth::unix_now( );
    const std::uint64_t remaining = session.expiry_unix > now ? session.expiry_unix - now : 0;
    std::cout << "Authenticated. Remaining: " << remaining << "s" << std::endl;

    if ( !session.pairing_code.empty( ) ) {
        std::cout << "Link Discord with /pair " << session.pairing_code << std::endl;
    }

    const auth::session_t check = client.validate( session );
    std::cout << ( check.success ? "Session validated by the server." : check.message ) << std::endl;

    std::cout << "Press Enter to exit..." << std::endl;
    std::cin.get( );

    return check.success ? 0 : 1;
}
