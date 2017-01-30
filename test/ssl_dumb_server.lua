local io = require 'lem.io'
local mbedtls = require 'lem.mbedtls'
local utils = require 'lem.utils'

local listen_port = arg[1] or 4443

local tlsconf, err = mbedtls.new_tls_config({
  crt_file="test/127.0.0.1.crt",
  key_file="test/127.0.0.1.pem",
})

local sock = io.tcp.listen('*', listen_port)

sock:autospawn(function (client)
  print('newclient', client:fileno())
  local newc, err = tlsconf:ssl_wrap_socket(client)
  if err == nil then
    local l = newc:read("*l")
    newc:write("HTTP/1.1 200 Ok\r\nContent-Type: text/html; charset=UTF-8\r\n\r\nBla");

    newc:ssl_close()
  else
    print('err:', err)
  end
end)
