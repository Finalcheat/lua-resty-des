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

