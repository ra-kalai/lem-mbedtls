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

function new_tls_config(conf)
  local o = {}

  conf.drbg = mbedtls_core.new_drbg()
  o.config_info = conf

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
  self:ssl_close()
end

function wrapped_socket_mt:__gc()
  self:ssl_close()
end

function wrapped_socket_mt:ssl_close()
  if self.ssl_closed == true then
    return
  end

  utils.yield()

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
end

function tls_config_mt:ssl_tcp_connect(host, port)
  local socket, err = tcp_connect(host, port)

  if socket then
    return self:ssl_wrap_socket(socket, host)
  end

  return nil, err
end

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

  return setmetatable(o, wrapped_socket_mt)
end

return {new_tls_config=new_tls_config}
