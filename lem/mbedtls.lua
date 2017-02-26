-- 
-- Copyright (c) 2017 Ralph Augé, All rights reserved.
-- Redistribution and use in source and binary forms, with or without
-- modification, are permitted provided that the following conditions are met:
-- 
-- * Redistributions of source code must retain the above copyright notice,
--   this list of conditions and the following disclaimer.
-- * Redistributions in binary form must reproduce the above copyright notice,
--   this list of conditions and the following disclaimer in the documentation
--   and/or other materials provided with the distribution.
-- 
-- THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
-- AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
-- IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
-- ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
-- LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
-- CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
-- SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
-- INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
-- CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
-- ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
-- POSSIBILITY OF SUCH DAMAGE.
-- 

local io = require 'lem.io'
local utils = require 'lem.utils'
local mbedtls_core = require 'lem.mbedtls.core'

local tcp_connect = io.tcp.connect

local tls_config_mt = {}
tls_config_mt.__index = tls_config_mt

function merge_file_in_attr(conf)
  local rconf = {}

  for k, v in pairs(conf) do
    rconf[k] = v
    local m = k:match("([^_]*)_file")

    if m then
      local f, err = io.open(v, "r")
      if f then
        rconf[m] = f:read("*a")
      else
        return nil, "could not load "..k, err
      end
    end
  end

  return rconf
end

function new_tls_config(conf)
  local o = {}

  local err, derr
  conf.drbg = conf.drbg or mbedtls_core.new_drbg()
  o.config_info, err, derr = merge_file_in_attr(conf)

  if o.config_info == nil then
    return nil, err, derr
  end

  o.config = mbedtls_core.new_conf(rconf)

  o.free_context_list = {}
  o.context_map = {}

  setmetatable(o, tls_config_mt)

  return o
end

local wrapped_socket_mt = {}
wrapped_socket_mt.__index = wrapped_socket_mt

for k, f in pairs(io.Stream) do
  if k:match("^__") == nil then
    (function ()
      local key = k
      local fun = f
      wrapped_socket_mt[key] = function (self, ...)
        return fun(self.ssl_socket, ...)
        --return self.ssl_socket[key](self.ssl_socket, ...)
      end
    end)()
  end
end

function wrapped_socket_mt:write(...)
  return self.ssl_socket:write(...)
end

function wrapped_socket_mt:read(...)
  return self.ssl_socket:read(...)
end

function wrapped_socket_mt:ssl_verify()
  return self.ssl_context:verify()
end

function wrapped_socket_mt:getpeer(...)
  return self.org_socket:getpeer(...)
end

function wrapped_socket_mt:close()
  return self:ssl_close()
end

function wrapped_socket_mt:__gc()
  self.gc = 1
  return self:ssl_close()
end

function wrapped_socket_mt:ssl_close()
  if self.ssl_closed == true then
    return true
  end

  if self.gc == nil then
    utils.yield()
  end

  -- after a sock:write(), we need to yield to make sure data get sent,
  -- we then can close the socks

  self.ssl_closed = true

  if self.ssl_socket:closed() == false then
    self.ssl_socket:close()
  end

  if self.org_socket:closed() == false then
    --self.ssl_context:close_notify()
    self.org_socket:close()
  end

  local free_context_list = self.ssl_config.free_context_list
  self.ssl_context:reset()
  free_context_list[#free_context_list + 1] = self.ssl_context
  return true
end

function tls_config_mt:tcp_connect(host, port)
  local socket, err = tcp_connect(host, port)

  if socket then
    return self:ssl_wrap_socket(socket, host)
  end

  return nil, err
end

tls_config_mt.connect = tls_config_mt.tcp_connect

function tls_config_mt:ssl_wrap_socket(socket, hostname)
  local ssl
  local free_context_list = self.free_context_list

  if #free_context_list >= 1 then
    ssl = table.remove(free_context_list)
  else
    ssl = mbedtls_core.new_ssl_context(self.config)
    self.context_map[ssl] = true
  end

  if hostname then
    ssl:set_hostname(hostname)
  end

  local socket_fd = socket:fileno()

  local newsocket_fd, err = ssl:wrap_socket(socket_fd)

  if err then
    socket:close()
    return nil, err
  end

  local new_socket = io.fromfd(newsocket_fd)

  local o = {
    ssl_socket=new_socket,
    org_socket=socket,
    ssl_context=ssl,
    ssl_config=self
  }

  if _VERSION == 'Lua 5.1' then
     local prox = newproxy(true)
     getmetatable(prox).__gc = function() wrapped_socket_mt.__gc(o) end
     o.gc_mt_hack = true
  end

  return setmetatable(o, wrapped_socket_mt)
end

function new_pkey(attr)
  attr = attr or {}
  attr.drbg = attr.drbg or mbedtls_core.new_drbg()
  attr.type = attr.type or 'rsa'
  attr.format = attr.format or 'pem'
  attr.rsa_keysize = 2048
  return mbedtls_core.new_pkey(attr)
end

function new_cert(attr)
  local attr = merge_file_in_attr(attr)
  attr.drbg = attr.drbg or mbedtls_core.new_drbg()
  return mbedtls_core.new_cert(attr)
end

-- need to be less or more equivalent to x509/cert_write \
-- selfsign=1 issuer_key=ca-key.pem \
-- issuer_name=CN=LEMMbedTLS,O=LEMMbedTLS,C=FR        \
-- not_before=20130101000000 not_after=20181231235959   \
-- key_usage=key_cert_sign,crl_sign,key_encipherment \
-- ns_cert_type=ssl_ca,object_signing,object_signing_ca \
-- is_ca=1 max_pathlen=0 output_file=ca-cert.crt serial=9999
function new_ca_crt(pkey, attr)
  attr = attr or {}
  attr.not_before = attr.not_before or string.format("%d", os.date('%Y')-1) .. "0101000000"
  attr.not_after = attr.not_after   or string.format("%d", os.date('%Y')+9) .. "1231235959"

  attr.serial = attr.serial or "9999"
  attr.selfsign = attr.selfsign or 1
  attr.issuer_name="CN=LEMMbedTLS,O=LEMMbedTLS,C=FR"

  attr.issuer_key = pkey

  -- '+' should be a fine replacement for '|' to stay compatible with lua5.1
  -- as long as a flag only appear 1 time..

  attr.key_usage = mbedtls_core.opt_key_usage_map.key_cert_sign +
                   mbedtls_core.opt_key_usage_map.crl_sign +
                   mbedtls_core.opt_key_usage_map.key_encipherment
  attr.ns_cert_type = mbedtls_core.opt_ns_cert_type_map.ssl_ca +
                      mbedtls_core.opt_ns_cert_type_map.object_signing +
                      mbedtls_core.opt_ns_cert_type_map.object_signing_ca 
  attr.is_ca=1
  attr.max_pathlen= attr.max_pathlen or 0
  return new_cert(attr)
end

-- need to be less or more equivalent to x509/cert_write \
-- issuer_key=ca-key.pem subject_key=key.pem \
-- issuer_name=CN=LEMMbedTLS,O=LEMMbedTLS,C=FR        \
-- subject_name=CN=localhost,O=RA,C=FR     \
-- not_before=20130101000000 not_after=20181231235959   \
-- output_file=cert.crt ns_cert_type=ssl_server serial=9999
function new_signed_crt(ca_key, ca_crt, attr)
  attr = attr or {}

  if attr.subject_name == nil then
    return nil, "missing a subject_name attribute ie: CN=localhost,O=Bla,C=FR"
  end

  if attr.subject_key == nil then
    return nil, "missing a subject_key attribute"
  end

  attr.not_before = attr.not_before or string.format("%d", os.date('%Y')-1) .. "0101000000"
  attr.not_after = attr.not_after   or string.format("%d", os.date('%Y')+9) .. "1231235959"

  attr.issuer_crt = ca_crt
  attr.issuer_key = ca_key
  attr.ns_cert_type = attr.ns_cert_type or mbedtls_core.opt_ns_cert_type_map.ssl_server
  attr.serial = attr.serial or "9999"
  return new_cert(attr)
end


return {new_tls_config=new_tls_config,
        new_pkey=new_pkey,
        new_drbg=mbedtls_core.new_drbg,
        new_ca_crt=new_ca_crt,
        new_signed_crt=new_signed_crt}
