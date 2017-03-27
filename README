Name
====

lua-resty-des - DES encrypt and decrypt functions for ngx_lua and LuaJIT

Description
===========

This library requires an nginx build with OpenSSL,
the [ngx_lua module](http://wiki.nginx.org/HttpLuaModule), and [LuaJIT 2.0](http://luajit.org/luajit.html).

Synopsis
========

```lua
    # nginx.conf:

    lua_package_path "/path/to/lua-resty-des/lib/?.lua;;";

    server {
        location = /test {
            content_by_lua_file conf/test.lua;
        }
    }

    -- conf/test.lua:
    local des = require "resty.des"
    local str = require "resty.string"

    local des_default = des:new("12345678")

    local encrypted = des_default:encrypt("hellodes")
    ngx.say("DES EBC MD5: ", str.to_hex(encrypted))
        -- output: DES EBC MD5: 32caca79912a9beefeb959b7d4642fcb

    local decrypted = des_default:decrypt(encrypted)
    ngx.say(decrypted == "hellodes")
        -- output: true


    -- no padding
    encrypted = des_default:encrypt("hellodes", 1)
    ngx.say("DES EBC MD5: ", str.to_hex(encrypted))
        -- output: DES EBC MD5: 32caca79912a9bee

    decrypted = des_default:decrypt(encrypted, 1)
    ngx.say(decrypted == "hellodes")
        -- output: true
```
