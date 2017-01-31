local mbedtls = require 'lem.mbedtls'
local utils = require 'lem.utils'
local client = require 'lem.http.client'
local io = require 'lem.io'


local url = arg[1] or 'https://www.google.com/'

local write, format = io.write, string.format
local function printf(...)
	return write(format(...))
end

local ssl_conf = {
	mode='client',
	crt_file='test/ca-list.pem',
	ssl_verify_mode=2,-- 0: don't verify
										-- 1: verify but keep going if certificate is invalid
										-- 2: if certifacte is invalid abort the connection
}

local conf, err = mbedtls.new_tls_config(ssl_conf)
assert(type(conf) == "table", "could not get a mbedtls config")

local running = 0

local function get(n, close)
	running = running + 1

	local c = client.new()
	c.ssl = conf

	local res = assert(c:get(url))

	printf('\n%d: HTTP/%s %d %s\n', n, res.version, res.status, res.text)
	for k, v in pairs(res.headers) do
		printf('%d: %s: %s\n', n, k, v)
	end

	local body = assert(res:body())
	printf('\n%d: #body = %d\n', n, #body)

	assert(c:close())
	running = running - 1
end

for i = 1, 2 do
	utils.spawn(get, i, (i % 2) == 0)
end

local sleeper = utils.newsleeper()
repeat
	write('.')
	sleeper:sleep(0.001)
until running == 0
