# SPDX-License-Identifier: MIT
package require pure-tcl-oauth2-core 0.1.0
namespace eval ::oauth2::server {}
oo::class create ::oauth2::server::Server {
    variable config store
    constructor {args} {
        set config [::oauth2::core::options {
            -issuer {} -store {} -allow_http false -clock {clock seconds}
            -code_ttl 300 -access_ttl 3600 -refresh_ttl 2592000 -signing_key {}
        } {*}$args]
        ::oauth2::core::url [dict get $config -issuer] [dict get $config -allow_http]
        if {[string first ? [dict get $config -issuer]] >= 0} {error "Issuer must not contain a query"}
        foreach key {-code_ttl -access_ttl -refresh_ttl} {::oauth2::core::integer [dict get $config $key] 1 31536000}
        set store [dict get $config -store]
        if {$store eq {}} {error "A grant store is required"}
        if {[dict get $config -signing_key] ne {}} {
            set keys [::oauth2::core::json [::tink::jwt::export_jwks [dict get $config -signing_key]]]
            foreach key [::oauth2::core::value $keys keys L] {
                if {[::oauth2::core::claim_string [lindex $key 1] alg] ne "RS256"} {error "Server ID tokens require RS256 signing keys"}
            }
        }
    }
    method now {} {{*}[dict get $config -clock]}
    method register_client {id args} {
        if {$id eq {} || [string length $id] > 255} {error "Invalid client ID"}
        set client [::oauth2::core::options {
            -redirect_uris {} -scope {} -secret {} -auth_method none
            -grants {authorization_code refresh_token} -audiences {} -introspection false
        } {*}$args]
        if {[dict get $client -auth_method] ni {none client_secret_basic client_secret_post}} {error "Unsupported client authentication"}
        if {[dict get $client -auth_method] ne "none" && [string length [dict get $client -secret]] < 32} {error "Client secrets must have at least 32 characters"}
        if {[dict get $client -auth_method] eq "none" && [dict get $client -introspection]} {error "Introspection requires a confidential client"}
        foreach grant [dict get $client -grants] {
            if {$grant ni {authorization_code refresh_token client_credentials}} {error "Unsupported grant"}
            if {$grant eq "client_credentials" && [dict get $client -auth_method] eq "none"} {error "Client credentials require client authentication"}
        }
        if {"authorization_code" in [dict get $client -grants] && ![llength [dict get $client -redirect_uris]]} {error "Redirect URIs are required"}
        foreach uri [dict get $client -redirect_uris] {::oauth2::core::url $uri [dict get $config -allow_http]}
        ::oauth2::core::scopes [dict get $client -scope]
        if {[dict get $client -audiences] eq {}} {dict set client -audiences [list [dict get $config -issuer]/resource]}
        dict set client -secret_hash [::oauth2::core::digest [dict get $client -secret]]
        dict unset client -secret
        dict set client id $id
        $store atomic [list [self] register_record $id $client]
    }
    method register_record {id client} {
        set old [$store get client $id [my now]]
        if {$old eq {}} {$store put client $id $client 253402300799} elseif {![$store replace client $id $old $client]} {::oauth2::core::fail conflict "Client registration changed"}
    }
    method client {id} {
        set record [$store get client $id [my now]]
        if {$record eq {}} {::oauth2::core::fail invalid_client "Unknown client"}
        dict get $record data
    }
    method authenticate {fields authorization} {
        set method none; set secret {}; set id {}
        if {$authorization ne {}} {
            if {[dict exists $fields client_secret] || [dict exists $fields client_id] || ![regexp {^Basic ([A-Za-z0-9+/]+=*)$} $authorization -> encoded]} {::oauth2::core::fail invalid_client "Invalid client authentication"}
            if {[catch {encoding convertfrom -profile strict utf-8 [binary decode base64 -strict $encoded]} credentials]} {::oauth2::core::fail invalid_client "Invalid client authentication"}
            set at [string first : $credentials]
            if {$at < 0} {::oauth2::core::fail invalid_client "Invalid client authentication"}
            # OAuth HTTP Basic percent-encodes the two credentials separately.
            set decoded [::oauth2::core::form_decode "id=[string range $credentials 0 [expr {$at-1}]]&secret=[string range $credentials [expr {$at+1}] end]"]
            set id [dict get $decoded id]; set secret [dict get $decoded secret]; set method client_secret_basic
        } else {
            if {![dict exists $fields client_id]} {::oauth2::core::fail invalid_client "Client ID is required"}
            set id [dict get $fields client_id]
            if {[dict exists $fields client_secret]} {set secret [dict get $fields client_secret]; set method client_secret_post}
        }
        set client [my client $id]
        if {$method ne [dict get $client -auth_method] || ($method ne "none" && ![::oauth2::core::equal [::oauth2::core::digest $secret] [dict get $client -secret_hash]])} {::oauth2::core::fail invalid_client "Client authentication failed"}
        return $client
    }
    method authorize_validate {fields} {
        foreach name {client_id redirect_uri response_type code_challenge code_challenge_method} {
            if {![dict exists $fields $name] || [dict get $fields $name] eq {}} {::oauth2::core::fail invalid_request "Incomplete authorization request"}
        }
        set client [my client [dict get $fields client_id]]
        if {"authorization_code" ni [dict get $client -grants]} {::oauth2::core::fail unauthorized_client "Grant is not permitted"}
        if {[dict get $fields redirect_uri] ni [dict get $client -redirect_uris]} {::oauth2::core::fail invalid_request "Unregistered redirect URI"}
        if {[dict get $fields response_type] ne "code"} {::oauth2::core::fail unsupported_response_type "Only code is supported"}
        if {[dict get $fields code_challenge_method] ne "S256" || ![regexp {^[A-Za-z0-9_-]{43}$} [dict get $fields code_challenge]]} {::oauth2::core::fail invalid_request "S256 PKCE is required"}
        ::oauth2::core::b64decode [dict get $fields code_challenge]
        set scope [expr {[dict exists $fields scope] ? [dict get $fields scope] : [dict get $client -scope]}]
        ::oauth2::core::scope_subset $scope [dict get $client -scope]
        set audience [expr {[dict exists $fields resource] ? [dict get $fields resource] : [lindex [dict get $client -audiences] 0]}]
        if {$audience ni [dict get $client -audiences]} {::oauth2::core::fail invalid_target "Resource is not permitted"}
        set nonce [expr {[dict exists $fields nonce] ? [dict get $fields nonce] : {}}]
        if {"openid" in [::oauth2::core::scopes $scope] && ($nonce eq {} || [dict get $config -signing_key] eq {})} {::oauth2::core::fail invalid_request "OIDC requires nonce and configured signing keys"}
        set state [expr {[dict exists $fields state] ? [dict get $fields state] : {}}]
        if {[string length $state] > 1024 || [string length $nonce] > 1024} {::oauth2::core::fail invalid_request "Oversized authorization parameter"}
        set request [dict create client_id [dict get $client id] redirect_uri [dict get $fields redirect_uri] scope $scope audience $audience \
            challenge [dict get $fields code_challenge] nonce $nonce state $state]
        set id [::oauth2::core::random]
        $store put authorization_request [::oauth2::core::digest $id] $request [expr {[my now]+600}]
        dict merge $request [dict create request_id $id]
    }
    method authorize_complete {requestId subject args} {
        set opts [::oauth2::core::options {-claims {} -consent true} {*}$args]
        if {$subject eq {} || [string length $subject] > 255} {::oauth2::core::fail access_denied "Authenticated subject is required"}
        set claims [dict get $opts -claims]
        foreach name {iss sub aud exp iat nbf nonce azp auth_time at_hash c_hash client_id scope} {
            if {[dict exists $claims $name]} {::oauth2::core::fail invalid_request "Reserved profile claim"}
        }
        ::oauth2::core::json [::oauth2::core::encode_json $claims]
        $store atomic [list [self] complete $requestId $subject $claims [dict get $opts -consent]]
    }
    method complete {requestId subject claims consent} {
        set id [::oauth2::core::digest $requestId]
        set record [$store get authorization_request $id [my now]]
        if {$record eq {} || ![$store delete authorization_request $id $record]} {::oauth2::core::fail invalid_request "Authorization request expired or consumed"}
        set request [dict get $record data]
        set response [dict create iss [dict get $config -issuer]]
        if {[dict get $request state] ne {}} {dict set response state [dict get $request state]}
        if {!$consent} {dict set response error access_denied} else {
            set code [::oauth2::core::random]
            dict set request subject $subject; dict set request claims $claims; dict set request used false
            $store put code [::oauth2::core::digest $code] $request [expr {[my now]+[dict get $config -code_ttl]}]
            dict set response code $code
        }
        dict create statusCode 302 headers [dict create Location [::oauth2::core::query_url [dict get $request redirect_uri] $response] Cache-Control no-store] body {}
    }
    method token {fields {authorization {}}} {
        set client [my authenticate $fields $authorization]
        if {![dict exists $fields grant_type]} {::oauth2::core::fail invalid_request "Grant type is required"}
        set grant [dict get $fields grant_type]
        if {$grant ni {authorization_code refresh_token client_credentials}} {::oauth2::core::fail unsupported_grant_type "Unsupported grant"}
        if {$grant ni [dict get $client -grants]} {::oauth2::core::fail unauthorized_client "Grant is not permitted"}
        set result [$store atomic [list [self] redeem $client $grant $fields]]
        # Reuse revocations must commit even though redemption is rejected.
        if {[dict exists $result error]} {::oauth2::core::fail [dict get $result error] "Grant rejected"}
        return $result
    }
    method revoke_family {id} {
        set family [$store get family $id [my now]]
        if {$family ne {}} {
            set data [dict get $family data]; dict set data revoked true
            if {![$store replace family $id $family $data]} {::oauth2::core::fail conflict "Grant changed"}
        }
    }
    method redeem {client grant fields} {
        set now [my now]; set familyId {}; set refresh false
        switch $grant {
            authorization_code {
                foreach name {code redirect_uri code_verifier} {if {![dict exists $fields $name]} {::oauth2::core::fail invalid_request "Incomplete code exchange"}}
                set id [::oauth2::core::digest [dict get $fields code]]
                set record [$store get code $id $now]
                if {$record eq {}} {::oauth2::core::fail invalid_grant "Invalid authorization code"}
                set grantData [dict get $record data]
                if {[dict get $grantData client_id] ne [dict get $client id] || [dict get $grantData redirect_uri] ne [dict get $fields redirect_uri] || \
                    ![::oauth2::core::equal [dict get $grantData challenge] [::oauth2::core::pkce_challenge [dict get $fields code_verifier]]]} {::oauth2::core::fail invalid_grant "Invalid code binding"}
                if {[dict get $grantData used]} {my revoke_family [dict get $grantData family]; return {error invalid_grant}}
                set refresh [expr {"refresh_token" in [dict get $client -grants]}]
            }
            refresh_token {
                if {![dict exists $fields refresh_token]} {::oauth2::core::fail invalid_request "Refresh token is required"}
                set id [::oauth2::core::digest [dict get $fields refresh_token]]
                set record [$store get refresh $id $now]
                if {$record eq {}} {::oauth2::core::fail invalid_grant "Invalid refresh token"}
                set grantData [dict get $record data]
                if {[dict get $grantData client_id] ne [dict get $client id]} {::oauth2::core::fail invalid_grant "Refresh client mismatch"}
                set familyId [dict get $grantData family]
                if {[dict get $grantData used]} {my revoke_family $familyId; return {error invalid_grant}}
                set family [$store get family $familyId $now]
                if {$family eq {} || [dict get $family data revoked]} {::oauth2::core::fail invalid_grant "Grant is revoked"}
                if {[dict exists $fields scope]} {
                    ::oauth2::core::scope_subset [dict get $fields scope] [dict get $grantData scope]
                    dict set grantData scope [dict get $fields scope]
                }
                set refresh true
            }
            client_credentials {
                if {[dict get $client -auth_method] eq "none"} {::oauth2::core::fail invalid_client "Client authentication is required"}
                set scope [expr {[dict exists $fields scope] ? [dict get $fields scope] : [dict get $client -scope]}]
                ::oauth2::core::scope_subset $scope [dict get $client -scope]
                if {"openid" in [::oauth2::core::scopes $scope]} {::oauth2::core::fail invalid_scope "Client credentials are not user authentication"}
                set audience [expr {[dict exists $fields resource] ? [dict get $fields resource] : [lindex [dict get $client -audiences] 0]}]
                if {$audience ni [dict get $client -audiences]} {::oauth2::core::fail invalid_target "Resource is not permitted"}
                set grantData [dict create client_id [dict get $client id] subject [dict get $client id] scope $scope audience $audience nonce {} claims {}]
            }
        }
        if {$familyId eq {}} {
            set familyId [::oauth2::core::random]
            set life [expr {$refresh ? [dict get $config -refresh_ttl] : [dict get $config -access_ttl]}]
            $store put family $familyId [dict create revoked false client_id [dict get $client id]] [expr {$now+$life}]
            set family [$store get family $familyId $now]
        }
        dict set grantData family $familyId
        dict set grantData used true
        if {$grant ne "client_credentials" && ![$store replace [expr {$grant eq "authorization_code" ? "code" : "refresh"}] $id $record $grantData]} {::oauth2::core::fail invalid_grant "Grant was consumed concurrently"}
        set access [::oauth2::core::random]
        set expiry [expr {min($now+[dict get $config -access_ttl],[dict get $family expires])}]
        set tokenData $grantData; dict set tokenData iat $now; dict set tokenData exp $expiry
        $store put access [::oauth2::core::digest $access] $tokenData $expiry $familyId
        set response [dict create access_token [list S $access] token_type {S Bearer} expires_in [list N [expr {$expiry-$now}]] scope [list S [dict get $grantData scope]]]
        if {$refresh} {
            set next [::oauth2::core::random]
            dict set tokenData used false
            $store put refresh [::oauth2::core::digest $next] $tokenData [dict get $family expires] $familyId
            dict set response refresh_token [list S $next]
        }
        if {"openid" in [::oauth2::core::scopes [dict get $grantData scope]]} {
            set claims [dict get $grantData claims]
            foreach {name value} [list iss [dict get $config -issuer] sub [dict get $grantData subject] aud [dict get $client id]] {dict set claims $name [list S $value]}
            dict set claims iat [list N $now]; dict set claims exp [list N $expiry]
            if {$grant eq "authorization_code"} {dict set claims nonce [list S [dict get $grantData nonce]]}
            dict set claims at_hash [list S [::oauth2::core::b64encode [string range [::thashlib::sha256 [encoding convertto ascii $access]] 0 15]]]
            dict set response id_token [list S [::tink::jwt::sign [dict get $config -signing_key] [list M $claims] JWT]]
        }
        return $response
    }
    method token_data {token} {
        set record [$store get access [::oauth2::core::digest $token] [my now]]
        if {$record eq {}} {return {}}
        set data [dict get $record data]
        set family [$store get family [dict get $data family] [my now]]
        if {$family eq {} || [dict get $family data revoked]} {return {}}
        return $data
    }
    method introspect {fields {authorization {}}} {
        set client [my authenticate $fields $authorization]
        if {![dict get $client -introspection]} {::oauth2::core::fail invalid_client "Client may not introspect tokens"}
        if {![dict exists $fields token]} {::oauth2::core::fail invalid_request "Token is required"}
        set data [my token_data [dict get $fields token]]
        if {$data eq {} || [dict get $data audience] ni [dict get $client -audiences]} {return {active {BOOL 0}}}
        set response [dict create active {BOOL 1} token_type {S Bearer} iss [list S [dict get $config -issuer]] \
            sub [list S [dict get $data subject]] client_id [list S [dict get $data client_id]] scope [list S [dict get $data scope]] \
            aud [list S [dict get $data audience]] iat [list N [dict get $data iat]] exp [list N [dict get $data exp]]]
        return $response
    }
    method revoke {fields {authorization {}}} {
        set client [my authenticate $fields $authorization]
        if {![dict exists $fields token]} {::oauth2::core::fail invalid_request "Token is required"}
        $store atomic [list [self] revoke_token [dict get $client id] [dict get $fields token]]
    }
    method revoke_token {clientId token} {
        foreach kind {access refresh} {
            set record [$store get $kind [::oauth2::core::digest $token] [my now]]
            if {$record ne {} && [dict get $record data client_id] eq $clientId} {my revoke_family [dict get $record data family]; return}
        }
    }
    method resource {token audience scope} {
        set data [my token_data $token]
        if {$data eq {} || [dict get $data audience] ne $audience} {::oauth2::core::fail invalid_token "Token is inactive or has the wrong audience"}
        ::oauth2::core::scope_subset $scope [dict get $data scope]
        return $data
    }
    method userinfo {token} {
        set data [my token_data $token]
        if {$data eq {} || "openid" ni [::oauth2::core::scopes [dict get $data scope]]} {::oauth2::core::fail invalid_token "An OpenID token is required"}
        dict merge [dict get $data claims] [dict create sub [list S [dict get $data subject]]]
    }
    method jwks {} {
        if {[dict get $config -signing_key] eq {}} {::oauth2::core::fail unsupported_request "Signing keys are not configured"}
        ::oauth2::core::json [::tink::jwt::export_jwks [dict get $config -signing_key]]
    }
    method metadata {} {
        set issuer [dict get $config -issuer]
        set data [dict create issuer [list S $issuer] response_types_supported {L {{S code}}} grant_types_supported {L {{S authorization_code} {S refresh_token} {S client_credentials}}} \
            code_challenge_methods_supported {L {{S S256}}} token_endpoint_auth_methods_supported {L {{S none} {S client_secret_basic} {S client_secret_post}}} authorization_response_iss_parameter_supported {BOOL 1}]
        foreach {name path} {authorization_endpoint /authorize token_endpoint /token revocation_endpoint /revoke introspection_endpoint /introspect} {dict set data $name [list S $issuer$path]}
        if {[dict get $config -signing_key] ne {}} {
            dict set data jwks_uri [list S $issuer/jwks]; dict set data userinfo_endpoint [list S $issuer/userinfo]
            dict set data id_token_signing_alg_values_supported {L {{S RS256}}}; dict set data subject_types_supported {L {{S public}}}
        }
        return $data
    }
    # Adapt a form POST. The caller validates HTTP method and content type.
    method endpoint {operation body {authorization {}}} {
        if {$operation ni {token introspect revoke}} {error "Unknown OAuth endpoint"}
        try {
            set fields [::oauth2::core::form_decode $body]
            set response [my $operation $fields $authorization]
            if {$operation eq "revoke"} {return [dict create statusCode 200 headers {Cache-Control no-store} body {}]}
            ::oauth2::core::response $response
        } trap OAUTH2 {message opts} {
            set code [lindex [dict get $opts -errorcode] 1]
            if {$code ni {invalid_request invalid_client invalid_grant unauthorized_client unsupported_grant_type invalid_scope invalid_target}} {set code server_error}
            set response [::oauth2::core::error_response $code [expr {$code eq "invalid_client" ? 401 : ($code eq "server_error" ? 500 : 400)}]]
            if {$code eq "invalid_client"} {dict set response headers WWW-Authenticate {Basic realm="oauth2"}}
            return $response
        } on error {message opts} {return [::oauth2::core::error_response server_error 500]}
    }
}
proc ::oauth2::server::create {args} {::oauth2::server::Server new {*}$args}
foreach method {register_client authorize_validate authorize_complete token introspect revoke resource userinfo metadata jwks endpoint} {
    proc ::oauth2::server::$method {server args} [format {tailcall $server %s {*}$args} $method]
}
package provide pure-tcl-oauth2-server 0.1.0
