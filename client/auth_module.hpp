#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include <cstdio>
#include <algorithm>
#include <chrono>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

namespace auth {

    class device_key_t {
    public:
        device_key_t( ) = default;
        device_key_t( const device_key_t& ) = delete;
        device_key_t& operator=( const device_key_t& ) = delete;

        ~device_key_t( ) {
            if ( key_ ) {
                NCryptFreeObject( key_ );
            }

            if ( provider_ ) {
                NCryptFreeObject( provider_ );
            }
        }

        bool initialize( ) {
            constexpr const wchar_t* key_name = L"AuthClientDeviceKeyV1";

            if ( NCryptOpenStorageProvider( &provider_, MS_KEY_STORAGE_PROVIDER, 0 ) != ERROR_SUCCESS ) {
                return false;
            }

            SECURITY_STATUS status = NCryptOpenKey( provider_, &key_, key_name, 0, 0 );

            if ( status != ERROR_SUCCESS ) {
                key_ = 0;
                status = NCryptCreatePersistedKey( provider_, &key_, BCRYPT_ECDSA_P256_ALGORITHM, key_name, 0, 0 );

                if ( status == ERROR_SUCCESS ) {
                    status = NCryptFinalizeKey( key_, 0 );
                }
            }

            return status == ERROR_SUCCESS && export_public_key( );
        }

        const std::vector<std::uint8_t>& public_blob( ) const {
            return public_blob_;
        }

        bool sign( const std::string& message, std::vector<std::uint8_t>& signature ) const {
            std::array<std::uint8_t, 32> hash = { };

            if ( !sha256( message, hash ) ) {
                return false;
            }

            DWORD required = 0;
            const DWORD hash_size = static_cast< DWORD >( hash.size( ) );

            if ( NCryptSignHash( key_, nullptr, hash.data( ), hash_size, nullptr, 0, &required, 0 ) != ERROR_SUCCESS
                || required != 64 ) {
                return false;
            }

            signature.resize( required );

            if ( NCryptSignHash( key_, nullptr, hash.data( ), hash_size, signature.data( ), required, &required, 0 )
                != ERROR_SUCCESS ) {
                return false;
            }

            return required == 64;
        }

    private:
        static bool sha256( const std::string& message, std::array<std::uint8_t, 32>& output ) {
            return BCryptHash(
                BCRYPT_SHA256_ALG_HANDLE,
                nullptr,
                0,
                reinterpret_cast< PUCHAR >( const_cast< char* >( message.data( ) ) ),
                static_cast< ULONG >( message.size( ) ),
                output.data( ),
                static_cast< ULONG >( output.size( ) ) ) >= 0;
        }

        bool export_public_key( ) {
            DWORD required = 0;

            if ( NCryptExportKey( key_, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, nullptr, 0, &required, 0 ) != ERROR_SUCCESS
                || required != 72 ) {
                return false;
            }

            public_blob_.resize( required );

            const SECURITY_STATUS status = NCryptExportKey(
                key_,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                nullptr,
                public_blob_.data( ),
                required,
                &required,
                0 );

            return status == ERROR_SUCCESS && required == 72;
        }

        NCRYPT_PROV_HANDLE provider_ = 0;
        NCRYPT_KEY_HANDLE key_ = 0;
        std::vector<std::uint8_t> public_blob_;
    };

    inline std::string base64url_encode( const std::uint8_t* data, size_t size ) {
        static constexpr char alphabet[ ] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        std::string output;
        output.reserve( ( size * 4 + 2 ) / 3 );

        for ( size_t index = 0; index < size; index += 3 ) {
            const std::uint32_t value = ( static_cast< std::uint32_t >( data[ index ] ) << 16 )
                | ( index + 1 < size ? static_cast< std::uint32_t >( data[ index + 1 ] ) << 8 : 0 )
                | ( index + 2 < size ? static_cast< std::uint32_t >( data[ index + 2 ] ) : 0 );

            output.push_back( alphabet[ ( value >> 18 ) & 63 ] );
            output.push_back( alphabet[ ( value >> 12 ) & 63 ] );

            if ( index + 1 < size ) {
                output.push_back( alphabet[ ( value >> 6 ) & 63 ] );
            }

            if ( index + 2 < size ) {
                output.push_back( alphabet[ value & 63 ] );
            }
        }

        return output;
    }

    inline std::uint64_t unix_now( ) {
        const auto since_epoch = std::chrono::system_clock::now( ).time_since_epoch( );
        return static_cast< std::uint64_t >( std::chrono::duration_cast< std::chrono::seconds >( since_epoch ).count( ) );
    }

    inline bool signed_proof(
        const device_key_t& key,
        const std::string& prefix,
        const std::string& suffix,
        std::string& nonce,
        std::string& signature ) {
        std::array<std::uint8_t, 32> nonce_bytes = { };

        if ( BCryptGenRandom(
            nullptr,
            nonce_bytes.data( ),
            static_cast< ULONG >( nonce_bytes.size( ) ),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG ) < 0 ) {
            return false;
        }

        nonce = base64url_encode( nonce_bytes.data( ), nonce_bytes.size( ) );

        std::vector<std::uint8_t> raw;

        if ( !key.sign( prefix + nonce + suffix, raw ) ) {
            return false;
        }

        signature = base64url_encode( raw.data( ), raw.size( ) );
        return true;
    }

    inline std::string generate_hwid( ) {
        char value[ 128 ] = { };
        DWORD size = sizeof( value );

        if ( RegGetValueA(
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Cryptography",
            "MachineGuid",
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
            nullptr,
            value,
            &size ) != ERROR_SUCCESS ) {
            return { };
        }

        std::array<std::uint8_t, 32> hash = { };

        if ( BCryptHash(
            BCRYPT_SHA256_ALG_HANDLE,
            nullptr,
            0,
            reinterpret_cast< PUCHAR >( value ),
            static_cast< ULONG >( strlen( value ) ),
            hash.data( ),
            static_cast< ULONG >( hash.size( ) ) ) < 0 ) {
            return { };
        }

        return base64url_encode( hash.data( ), hash.size( ) );
    }

    inline bool winsock_ready( ) {
        static const bool ready = [ ] ( ) {
            WSADATA data = { };
            return WSAStartup( MAKEWORD( 2, 2 ), &data ) == 0;
            }( );

        return ready;
    }

    inline bool parse_endpoint( const std::string& endpoint, std::string& host, std::uint16_t& port ) {
        const auto split = endpoint.rfind( ':' );

        if ( split == std::string::npos || split == 0 ) {
            host = endpoint;
            port = 2230;
            return !host.empty( );
        }

        host = endpoint.substr( 0, split );

        try {
            const unsigned long value = std::stoul( endpoint.substr( split + 1 ) );

            if ( value == 0 || value > 65535 ) {
                return false;
            }

            port = static_cast< std::uint16_t >( value );
        }
        catch ( ... ) {
            return false;
        }

        return !host.empty( );
    }

    inline bool send_all( SOCKET socket, const std::uint8_t* data, size_t size ) {
        while ( size ) {
            const int chunk = static_cast< int >( ( std::min )( size, size_t{ 65536 } ) );
            const int sent = send( socket, reinterpret_cast< const char* >( data ), chunk, 0 );

            if ( sent <= 0 ) {
                return false;
            }

            data += sent;
            size -= static_cast< size_t >( sent );
        }

        return true;
    }

    inline bool recv_exact( SOCKET socket, std::uint8_t* data, size_t size ) {
        while ( size ) {
            const int chunk = static_cast< int >( ( std::min )( size, size_t{ 65536 } ) );
            const int received = recv( socket, reinterpret_cast< char* >( data ), chunk, 0 );

            if ( received <= 0 ) {
                return false;
            }

            data += received;
            size -= static_cast< size_t >( received );
        }

        return true;
    }

    inline void write_u32le( std::uint8_t* dest, std::uint32_t value ) {
        for ( int i = 0; i < 4; ++i ) {
            dest[ i ] = static_cast< std::uint8_t >( value >> ( i * 8 ) );
        }
    }

    inline std::uint32_t read_u32le( const std::uint8_t* src ) {
        return static_cast< std::uint32_t >( src[ 0 ] )
            | ( static_cast< std::uint32_t >( src[ 1 ] ) << 8 )
            | ( static_cast< std::uint32_t >( src[ 2 ] ) << 16 )
            | ( static_cast< std::uint32_t >( src[ 3 ] ) << 24 );
    }

    inline bool native_exchange( const std::string& endpoint, const std::string& json, std::string& response ) {
        response.clear( );

        std::string host;
        std::uint16_t port = 2230;

        if ( !parse_endpoint( endpoint, host, port ) || !winsock_ready( ) ) {
            return false;
        }

        ADDRINFOA hints = { };
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        PADDRINFOA addresses = nullptr;

        if ( getaddrinfo( host.c_str( ), std::to_string( port ).c_str( ), &hints, &addresses ) != 0 || !addresses ) {
            return false;
        }

        SOCKET socket = INVALID_SOCKET;

        for ( auto* entry = addresses; entry; entry = entry->ai_next ) {
            socket = ::socket( entry->ai_family, entry->ai_socktype, entry->ai_protocol );

            if ( socket == INVALID_SOCKET ) {
                continue;
            }

            DWORD timeout = 15000;
            const char* timeout_ptr = reinterpret_cast< const char* >( &timeout );
            setsockopt( socket, SOL_SOCKET, SO_RCVTIMEO, timeout_ptr, sizeof( timeout ) );
            setsockopt( socket, SOL_SOCKET, SO_SNDTIMEO, timeout_ptr, sizeof( timeout ) );

            if ( connect( socket, entry->ai_addr, static_cast< int >( entry->ai_addrlen ) ) == 0 ) {
                break;
            }

            closesocket( socket );
            socket = INVALID_SOCKET;
        }

        freeaddrinfo( addresses );

        if ( socket == INVALID_SOCKET ) {
            return false;
        }

        std::array<std::uint8_t, 16> header = { };
        write_u32le( header.data( ), 0x54554143 );
        header[ 4 ] = 1;
        write_u32le( header.data( ) + 8, static_cast< std::uint32_t >( json.size( ) ) );

        bool ok = send_all( socket, header.data( ), header.size( ) )
            && send_all( socket, reinterpret_cast< const std::uint8_t* >( json.data( ) ), json.size( ) )
            && recv_exact( socket, header.data( ), header.size( ) );

        if ( ok ) {
            const auto json_len = read_u32le( header.data( ) + 8 );
            const auto binary_len = read_u32le( header.data( ) + 12 );

            ok = read_u32le( header.data( ) ) == 0x54554143
                && header[ 4 ] == 1
                && json_len
                && json_len <= 64 * 1024
                && binary_len == 0;

            if ( ok ) {
                response.resize( json_len );
                ok = recv_exact( socket, reinterpret_cast< std::uint8_t* >( response.data( ) ), json_len );
            }
        }

        closesocket( socket );
        return ok && !response.empty( );
    }

    inline size_t json_value_position( const std::string& json, const std::string& key ) {
        const std::string search = "\"" + key + "\"";
        size_t pos = json.find( search );

        if ( pos == std::string::npos ) {
            return pos;
        }

        pos = json.find( ':', pos + search.size( ) );

        if ( pos == std::string::npos ) {
            return pos;
        }

        ++pos;

        while ( pos < json.size( )
            && ( json[ pos ] == ' ' || json[ pos ] == '\t' || json[ pos ] == '\n' || json[ pos ] == '\r' ) ) {
            ++pos;
        }

        return pos < json.size( ) ? pos : std::string::npos;
    }

    inline bool json_bool( const std::string& json, const std::string& key, bool& out ) {
        const size_t pos = json_value_position( json, key );

        if ( pos == std::string::npos ) {
            return false;
        }

        if ( json.compare( pos, 4, "true" ) == 0 ) {
            out = true;
            return true;
        }

        if ( json.compare( pos, 5, "false" ) == 0 ) {
            out = false;
            return true;
        }

        return false;
    }

    inline bool json_string( const std::string& json, const std::string& key, std::string& out ) {
        size_t pos = json_value_position( json, key );

        if ( pos == std::string::npos || json[ pos ] != '"' ) {
            return false;
        }

        out.clear( );

        for ( ++pos; pos < json.size( ); ++pos ) {
            const char character = json[ pos ];

            if ( character == '"' ) {
                return true;
            }

            if ( character == '\\' ) {
                if ( ++pos >= json.size( ) ) {
                    return false;
                }

                out.push_back( json[ pos ] );
            }
            else {
                out.push_back( character );
            }
        }

        return false;
    }

    inline bool json_uint64( const std::string& json, const std::string& key, std::uint64_t& out ) {
        const size_t pos = json_value_position( json, key );

        if ( pos == std::string::npos ) {
            return false;
        }

        size_t end = pos;

        while ( end < json.size( ) && json[ end ] >= '0' && json[ end ] <= '9' ) {
            ++end;
        }

        if ( end == pos ) {
            return false;
        }

        try {
            out = std::stoull( json.substr( pos, end - pos ) );
            return true;
        }
        catch ( ... ) {
            return false;
        }
    }

    inline std::string json_escape( const std::string& value ) {
        std::string escaped;
        escaped.reserve( value.size( ) );

        for ( unsigned char character : value ) {
            switch ( character ) {
            case '"':
                escaped += "\\\"";
                break;
            case '\\':
                escaped += "\\\\";
                break;
            case '\n':
                escaped += "\\n";
                break;
            case '\r':
                escaped += "\\r";
                break;
            case '\t':
                escaped += "\\t";
                break;
            default:
                if ( character < 0x20 ) {
                    char encoded[ 7 ] = { };
                    std::snprintf( encoded, sizeof( encoded ), "\\u%04x", character );
                    escaped += encoded;
                }
                else {
                    escaped.push_back( static_cast< char >( character ) );
                }
            }
        }

        return escaped;
    }

    struct session_t {
        bool success = false;
        std::string message;
        std::string access_token;
        std::string pairing_code;
        std::uint64_t start_unix = 0;
        std::uint64_t expiry_unix = 0;
    };

    class client_t {
    public:
        explicit client_t( std::string endpoint ) : endpoint_( std::move( endpoint ) ) { }

        session_t authenticate( const std::string& key, const std::string& hwid ) {
            session_t result = { };

            if ( !ready_ && !( ready_ = device_key_.initialize( ) ) ) {
                result.message = "Failed to initialize the device identity key.";
                return result;
            }

            const std::uint64_t timestamp = unix_now( );
            const std::string prefix = "auth-client-auth:v1\n" + std::to_string( timestamp ) + "\n";
            const std::string suffix = "\n" + hwid + "\n" + key;

            std::string nonce;
            std::string signature;

            if ( !signed_proof( device_key_, prefix, suffix, nonce, signature ) ) {
                result.message = "Failed to sign the authentication request.";
                return result;
            }

            const std::vector<std::uint8_t>& blob = device_key_.public_blob( );
            const std::string public_key = base64url_encode( blob.data( ), blob.size( ) );

            const std::string body = "{\"op\":\"authenticate\",\"key\":\"" + json_escape( key )
                + "\",\"hwid\":\"" + json_escape( hwid )
                + "\",\"client_public_key\":\"" + public_key
                + "\",\"timestamp_unix\":" + std::to_string( timestamp )
                + ",\"nonce\":\"" + nonce
                + "\",\"signature\":\"" + signature + "\"}";

            return exchange( body, true );
        }

        session_t validate( const session_t& session ) {
            session_t result = { };

            if ( !ready_ || session.access_token.empty( ) ) {
                result.message = "Authenticate before validating the session.";
                return result;
            }

            const std::uint64_t timestamp = unix_now( );
            const std::string prefix = "auth-session-proof:v1\nvalidate\n" + session.access_token + "\n"
                + std::to_string( timestamp ) + "\n";

            std::string nonce;
            std::string signature;

            if ( !signed_proof( device_key_, prefix, "", nonce, signature ) ) {
                result.message = "Failed to sign the validation request.";
                return result;
            }

            const std::string body = "{\"op\":\"validate\",\"access_token\":\"" + json_escape( session.access_token )
                + "\",\"timestamp_unix\":" + std::to_string( timestamp )
                + ",\"nonce\":\"" + nonce
                + "\",\"signature\":\"" + signature + "\"}";

            result = exchange( body, false );

            if ( result.success ) {
                result.access_token = session.access_token;
            }

            return result;
        }

    private:
        session_t exchange( const std::string& body, bool expect_token ) {
            session_t result = { };
            std::string response;

            if ( !native_exchange( endpoint_, body, response ) ) {
                result.message = "Failed to contact the authentication server.";
                return result;
            }

            bool success = false;

            if ( !json_bool( response, "success", success ) || !success ) {
                if ( !json_string( response, "error", result.message ) ) {
                    result.message = "Authentication failed.";
                }

                return result;
            }

            if ( !json_uint64( response, "start_unix", result.start_unix )
                || !json_uint64( response, "expiry_unix", result.expiry_unix )
                || ( expect_token && !json_string( response, "access_token", result.access_token ) ) ) {
                result.message = "Invalid server response.";
                return result;
            }

            json_string( response, "pairing_code", result.pairing_code );

            result.success = true;
            result.message = "License is valid.";
            return result;
        }

        std::string endpoint_;
        device_key_t device_key_;
        bool ready_ = false;
    };

}