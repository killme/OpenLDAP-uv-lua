local x = require "openldapuv"

require "luvit.utils".DUMP_MAX_DEPTH = 10

p("Module", x)

local conf = dofile "ldap.conf"

local con = x.connect(conf.url)

p("connection", con)

con:bind(conf.dn, conf.password)

p(con:search("dc=example,dc=com", "LDAP_SCOPE_CHILDREN", nil, {"memberOf", "cn"}, false))
