
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_gc = ffi.gc
local ffi_str = ffi.string
local ffi_copy = ffi.copy
local C = ffi.C
local setmetatable = setmetatable
local error = error
local type = type


local _M = { _VERSION = '0.01' }

local mt = { __index = _M }


ffi.cdef[[
typedef struct engine_st ENGINE;
typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_cipher_ctx_st {
    const EVP_CIPHER *cipher;
    ENGINE *engine;
    int encrypt;
    int buf_len;
    unsigned char oiv[16];
    unsigned char iv[16];
    unsigned char buf[32];
    int num;
    void *app_data;
    int key_len;
    unsigned long flags;
    void *cipher_data;
    int final_used;
    int block_mask;
    unsigned char final[32];
} EVP_CIPHER_CTX;

void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *a);
int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *a);

const EVP_CIPHER *EVP_des_ecb(void);

int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                       ENGINE *impl, const unsigned char *key,
                       const unsigned char *iv);
int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad);
int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                      const unsigned char *in, int inl);
int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher,
        ENGINE *impl, unsigned char *key, const unsigned char *iv);
int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
        const unsigned char *in, int inl);
int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
]]

local ctx_ptr_type = ffi.typeof("EVP_CIPHER_CTX[1]")


function _M.new(self, key)
    if not key then
        return nil, "key not set"
    end
    if #key < 8 then
        return nil, "key length less then 8"
    end
    local encrypt_ctx = ffi_new(ctx_ptr_type)
    local decrypt_ctx = ffi_new(ctx_ptr_type)
    C.EVP_CIPHER_CTX_init(encrypt_ctx)
    local gen_key = ffi_new("unsigned char[8]")
    ffi_copy(gen_key, key, 8)

    if C.EVP_EncryptInit_ex(encrypt_ctx, C.EVP_des_ecb(), nil, gen_key, nil) == 0 then
        return nil, "EVP_EncryptInit_ex error"
    end

    if C.EVP_DecryptInit_ex(decrypt_ctx, C.EVP_des_ecb(), nil, gen_key, nil) == 0 then
        return nil, "EVP_DecryptInit_ex error"
    end

    -- if C.EVP_CIPHER_CTX_set_padding(encrypt_ctx, 0) ~= 1 then
    --     return nil
    -- end

    ffi_gc(encrypt_ctx, C.EVP_CIPHER_CTX_cleanup)
    return setmetatable({
        _encrypt_ctx = encrypt_ctx,
        _decrypt_ctx = decrypt_ctx,
    }, mt)
end


function _M.encrypt(self, s)
    local s_len = #s
    local max_len = s_len + 8
    local out = ffi_new("unsigned char[?]", max_len)
    local out_len = ffi_new("int[1]")
    local tmp_len = ffi_new("int[1]")
    local ctx = self._encrypt_ctx
    -- if C.EVP_EncryptInit_ex(ctx, C.EVP_des_ecb(), nil, gen_key, nil) == 0 then
    if C.EVP_EncryptInit_ex(ctx, nil, nil, nil, nil) == 0 then
        return nil, "EVP_EncryptInit_ex error"
    end

    -- if C.EVP_CIPHER_CTX_set_padding(ctx, 0) ~= 1 then
    --     return nil, "set error"
    -- end

    if C.EVP_EncryptUpdate(ctx, out, out_len, s, s_len) ~= 1 then
        return nil, "EVP_EncryptUpdate error"
    end

    if C.EVP_EncryptFinal_ex(ctx, out + out_len[0], tmp_len) == 0 then
        return nil, "EVP_EncryptFinal_ex error"
    end

    return ffi_str(out, out_len[0] + tmp_len[0])
end


function _M.decrypt(self, s)
    local s_len = #s
    local out = ffi_new("unsigned char[?]", s_len)
    local out_len = ffi_new("int[1]")
    local tmp_len = ffi_new("int[1]")
    local ctx = self._decrypt_ctx

    if C.EVP_DecryptInit_ex(ctx, nil, nil, nil, nil) == 0 then
        return nil, "EVP_DecryptInit_ex error"
    end

    if C.EVP_DecryptUpdate(ctx, out, out_len, s, s_len) == 0 then
        return nil, "EVP_DecryptUpdate error"
    end

    if C.EVP_DecryptFinal_ex(ctx, out + out_len[0], tmp_len) == 0 then
        return nil, "EVP_DecryptFinal_ex error"
    end

    return ffi_str(out, out_len[0] + tmp_len[0])
end


return _M
