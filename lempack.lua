return {
  object_files = {
    {'.o', 'lem/mbedtls/core.o' },
    {'.o', 'mbedtls/library/libmbedtls.a' },
    {'.o', 'mbedtls/library/libmbedx509.a' },
    {'.o', 'mbedtls/library/libmbedcrypto.a' },
  },
  luaopen = {
    {'lz4', 'luaopen_lem_mbedtls_core'},
  },
  lua_files ={{"extra", "lem/mbedtls.lua"}}
}
