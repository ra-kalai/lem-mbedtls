lem-mbedtls
===========


About
-----

lem-mbedtls is a library for the [Lua Event Machine][lem].
This library goal is to help handling ssl socket within LEM.

[lem]: https://github.com/esmil/lem


Installation
------------

Get the source and do

    # fetch mbedtls if necessary, compile the lib, and the lem module
    make
    
    # install
    make install
    
    # test / try
    lem test/ssl_client.lua
    lem test/htest-ssl.lua

Usage
-----

Import the module using something like

    local mbedtls = require 'lem.mbedtls'

This sets `mbedtls` to a table with at the moment one function:

* __new_tls_config( ssl_config )__

  This function is used to set up a tls config object

  example client config

      new_tls_config {
        mode='client',
        crt_file='test/ca-list.pem',
        ssl_verify_mode=1,  -- 0: don't verify
                            -- 1: verify but keep going if certificate is invalid
                            -- 2: if certifacte is invalid abort the connection
      }

  example server config

      new_tls_config {
        -- mode='server', -- if 'mode' isn't defined, it default to 'server' 
        crt_file = 'test/bla.crt',
        key_file = 'test/bla.key',
      }

  *return* a table/object with the following method
    * __tlsconfig:ssl_tcp_connect(host, port)__   
      if everything go well,
        *return*  a __wrapped_socket__ object / table which work in a similar way as normal LEM socket
      else
        *return* nil, error_msg
      
    * __tlsconfig:ssl_wrap_socket(socket [, hostname])__   
      socket:  lem socket
      hostname: only necessary on client mode ssl, if you want to verify the certificate.
      if everything go well,
        *return* a wrapped_socket object / table which work in a similar way as normal LEM socket
      else
        *return* nil, error_msg

      client usage

          local sock, err = tlsconfig:ssl_tcp_connect(domain_name, connect_port)

      server usage

          local sock = io.tcp.listen('*', listen_port)
          sock:autospawn(function (client)
            local new_client, err = tlsconfig:ssl_wrap_socket(client)
            if new_client then
                ...
            end
          end


    note, about __wrapped_socket__ object
    
    it is a table containing two socket: 
    
      { org_socket=socket, ssl_socket=socket }

     * *org_socket* -- stand for original socket, you must not use it, close it as long as you are using the ssl socket
     * *ssl_socket* -- an unix socket

    All method of ssl_socket are proxyfied over the __wrapped_socket__ object except *getpeer* which is proxyfied on the *org_socket*.
    
    __wrapped_socket__ object got one extra method

    * __wrapped_socket:verify()__
      *return* true if certificate match hostname
      *return* false if certificate don't match hostname
    

License
-------

lem-mbedtls is free software. It is distributed under the terms of a Apache 2.0, Three clause BSD license and the [GNU General Public License][gpl] or [GNU Lesser General Public License][lgpl] any revision, as it suit you.

mbedTLS is distributed by ARMmbed under the Apache 2.0 license

[gpl]: http://www.fsf.org/licensing/licenses/gpl.html
[lgpl]: http://www.fsf.org/licensing/licenses/lgpl.html

Contact
-------

Please send bug reports, patches and feature requests to me <ra@apathie.net>.

