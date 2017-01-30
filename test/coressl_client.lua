local io = require 'lem.io'
local mbedtls = require 'lem.mbedtls.core'
local utils = require 'lem.utils'

local domain_name = arg[1] or 'www.google.com'
local connect_port = arg[2] or 443

local drbg = mbedtls.new_drbg()
local ssl_conf = {
	drbg=drbg,
	mode='client',
	crt=io.open('test/ca-list.pem','r'):read('*a'),
	ssl_verify_mode=1,-- 0: don't verify
										-- 1: verify but keep going if certificate is invalid
										-- 2: if certifacte is invalid abort the connection
}

local conf, err = mbedtls.new_conf(ssl_conf)
assert(type(conf) == "userdata", "could not get a mbedtls config")

print("connecting to " .. domain_name)

local sock = io.tcp.connect(domain_name, connect_port)
assert(type(sock) == "userdata", "could not connect to " .. domain_name)

local ssl = mbedtls.new_ssl_context(conf)
assert(type(ssl) == "userdata", "could not get a ssl context")

local hostname_set = ssl:set_hostname(domain_name)
assert(hostname_set == true, "could not set domain on ssl context")

local newsockfd, err = ssl:wrap_socket(sock:fileno())
if err == nil then err = '' end
assert(newsockfd,"ssl negotiation error - " .. err)

local newc = io.fromfd(newsockfd)
assert(type(newc) == "userdata", "could not obtain after ssl negotiation..?")

print("Is certicate valid ?", ssl:verify())


utils.spawn(function ()
	while true do
		local l, err = newc:read("*l")
		if l then
			local l = l:gsub("\r","")
			print(l)
		end
		if err then
			break
		end
	end
end)

newc:write("GET / HTTP/1.0\r\nHost: ".. domain_name.."\r\n\r\n")
