#include <iostream>
#include <string>
#include "../client/auth_module.hpp"

int main( ) {
    auth::client_t client( "127.0.0.1:2230" );
    const std::string hwid = auth::generate_hwid( );
    const auth::session_t session = client.authenticate( "AUTH-XXXXX-XXXXX-XXXXX-XXXXX", hwid );

    if ( !session.success ) {
        std::cerr << "Authentication failed: " << session.message << std::endl;
        return 1;
    }

    std::cout << "Expires at unix time " << session.expiry_unix << std::endl;

    const auth::session_t check = client.validate( session );
    std::cout << ( check.success ? "Session still valid." : check.message ) << std::endl;

    return check.success ? 0 : 1;
}
