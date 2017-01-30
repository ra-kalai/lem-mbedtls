local mbedtls = require 'lem.mbedtls'
local utils = require 'lem.utils'

local domain_name = arg[1] or 'www.google.com'
local connect_port = arg[2] or 443

local ssl_conf = {
	mode='client',
	crt_file='test/ca-list.pem',
	ssl_verify_mode=1,-- 0: don't verify
										-- 1: verify but keep going if certificate is invalid
										-- 2: if certifacte is invalid abort the connection
}

local conf, err = mbedtls.new_tls_config(ssl_conf)
assert(type(conf) == "table", "could not get a mbedtls config")

print("connecting to " .. domain_name)

local sock = conf:ssl_tcp_connect(domain_name, connect_port)
assert(type(sock) == "table", domain_name .. "didn't not respond or ssl/tls failure")


print("Is certicate valid ?", sock:ssl_verify())


utils.spawn(function ()
	while true do
		local l, err = sock:read("*l")
		if l then
			local l = l:gsub("\r","")
			print(l)
		end
		if err then
			break
		end
	end
end)

sock:write("GET / HTTP/1.0\r\nHost: ".. domain_name .. "\r\n\r\n")
