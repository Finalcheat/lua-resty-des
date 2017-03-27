use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: DES default hello

--- config
location = /t {
    content_by_lua_block {
        local des = require "resty.des"
        local str = require "resty.string"
        local des_default = des:new("12345678")
        local encrypted = des_default:encrypt("hello")
        ngx.say("DES EBC MD5: ", str.to_hex(encrypted))
        local decrypted = des_default:decrypt(encrypted)
        ngx.say(decrypted == "hello")
    }
}

--- request
GET /t

--- error_code: 200
--- response_body
DES EBC MD5: ba16c6a0257125af
true
--- no_error_log
[error]


=== TEST 2: DES hellodes default padding(PKCS5)

--- config
location = /t {
    content_by_lua_block {
        local des = require "resty.des"
        local str = require "resty.string"
        local des_default = des:new("12345678")
        local encrypted = des_default:encrypt("hellodes")
        ngx.say("DES EBC MD5: ", str.to_hex(encrypted))
        local decrypted, err = des_default:decrypt(encrypted)
        ngx.say(decrypted == "hellodes")
    }
}

--- request
GET /t

--- error_code: 200
--- response_body
DES EBC MD5: 32caca79912a9beefeb959b7d4642fcb
true
--- no_error_log
[error]


=== TEST 3: DES hellodes no padding

--- config
location = /t {
    content_by_lua_block {
        local des = require "resty.des"
        local str = require "resty.string"
        local des_default = des:new("12345678")
        local encrypted = des_default:encrypt("hellodes", 1)
        ngx.say("DES EBC MD5: ", str.to_hex(encrypted))
        local decrypted, err = des_default:decrypt(encrypted, 1)
        ngx.say(decrypted == "hellodes")
    }
}

--- request
GET /t

--- error_code: 200
--- response_body
DES EBC MD5: 32caca79912a9bee
true
--- no_error_log
[error]
