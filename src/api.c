#include <ldap.h>
#include <lua.h>
#include <lauxlib.h>
#include <malloc.h>

#define LUA_EXPORT(type) static type
#define META_TABLE "openldap_uv_lua_handle"

typedef struct openldap_uv_lua_handle_s openldap_uv_lua_handle_t;

struct openldap_uv_lua_handle_s {
    openldap_uv_lua_handle_t *parent;
    char *url;
    LDAP *ldap;
    int refs;
};

static const char *openldap_uv_lua__string_or_null(lua_State *L, int idx)
{
    return lua_isnil(L, idx) ? NULL : luaL_checkstring(L, idx);
}

static void openldap_uv_lua__destory(openldap_uv_lua_handle_t *ldap)
{
    if(ldap->ldap)
    {
        ldap_destroy(ldap->ldap);
        ldap->ldap = 0;
    }
    if(ldap->url)
    {
        ldap_memfree(ldap->url);
        ldap->url = 0;
    }
}

static void openldap_uv_lua__check_error(lua_State *L, openldap_uv_lua_handle_t *ldap, int err)
{
    if(err != 0)
    {
        openldap_uv_lua__destory(ldap);
        luaL_error(L, "LDAP Error: %s", ldap_err2string(err));
    }
}

static void openldap_uv_lua__check_connection(lua_State *L, openldap_uv_lua_handle_t *ldap)
{
    if(!ldap->ldap)
    {
        luaL_error(L, "Not connected.");
    }
}

static int openldap_uv_lua__gc_handle(lua_State *L)
{
    openldap_uv_lua_handle_t *ldap = luaL_checkudata(L, 1, META_TABLE);

    openldap_uv_lua__destory(ldap);

    return 0;
}

LUA_EXPORT(int openldap_uv_lua_connect(lua_State* L))
{
    luaL_checkstring(L, 1);
    size_t length = 0;
    const char *url = lua_tolstring(L, 1, &length);

    int err;

    char *url_ = malloc(length+1);

    if(!url)
    {
        luaL_error(L, "Failed to allocate url buffer for %s.", url);
    }

    memcpy(url_, url, length);
    url_[length] = 0;

    openldap_uv_lua_handle_t *handle = lua_newuserdata(L, sizeof(*handle));
    memset(handle, 0, sizeof(*handle));

    handle->url = url_;

    luaL_getmetatable(L, META_TABLE);
    lua_setmetatable(L, -2);

    err = ldap_initialize(&handle->ldap, handle->url);

    openldap_uv_lua__check_error(L, handle, err);

    int version = 3;
    err = ldap_set_option(handle->ldap, LDAP_OPT_PROTOCOL_VERSION, &version);
    openldap_uv_lua__check_error(L, handle, err);

    return 1;
}

LUA_EXPORT(int openldap_uv_lua_bind(lua_State *L))
{
    openldap_uv_lua_handle_t *ldap = luaL_checkudata(L, 1, META_TABLE);

    if(!ldap->ldap)
    {
        luaL_error(L, "Handle is not connected");
    }

    const char *dn = luaL_checkstring(L, 2);

    struct berval credential = {};
    credential.bv_val = (void *)lua_tolstring(L, 3, &credential.bv_len);

    openldap_uv_lua__check_connection(L, ldap);

    struct berval *servercredentials;
    int err;

    err = ldap_sasl_bind_s(ldap->ldap, dn, 0, &credential, 0, 0, &servercredentials);

    if(err == 49)
    {
        lua_pushboolean(L, 0);
    }
    else
    {
        openldap_uv_lua__check_error(L, ldap, err);
        lua_pushboolean(L, 1);
    }

    return 1;
}

LUA_EXPORT(int openldap_uv_lua_search(lua_State *L))
{
    openldap_uv_lua_handle_t *ldap = luaL_checkudata(L, 1, META_TABLE);

    if(!ldap->ldap)
    {
        luaL_error(L, "Handle is not connected");
    }

    const char *dn = openldap_uv_lua__string_or_null(L, 2);
    const char *scope = luaL_checkstring(L, 3);

    int _scope;
    if(strcmp(scope, "LDAP_SCOPE_BASE") == 0 || strcmp(scope, "LDAP_SCOPE_BASEOBJECT") == 0) _scope = LDAP_SCOPE_BASEOBJECT;
    else if(strcmp(scope, "LDAP_SCOPE_ONE") == 0 || strcasecmp(scope, "LDAP_SCOPE_ONELEVEL") == 0) _scope = LDAP_SCOPE_ONELEVEL;
    else if(strcmp(scope, "LDAP_SCOPE_SUB") == 0 || strcasecmp(scope, "LDAP_SCOPE_SUBTREE") == 0) _scope = LDAP_SCOPE_SUBTREE;
    else if(strcmp(scope, "LDAP_SCOPE_CHILDREN") == 0 || strcasecmp(scope, "LDAP_SCOPE_SUBORDINATE") == 0) _scope = LDAP_SCOPE_CHILDREN;
    else luaL_error(L, "Unsupported scope %s", scope);

    const char *filter = openldap_uv_lua__string_or_null(L, 4);

    char **fieldSelector = NULL;

    if(!lua_isnil(L, 5))
    {
        luaL_checktype(L, 5, LUA_TTABLE);
        int size = lua_objlen(L, 5);

        fieldSelector = malloc(sizeof(*fieldSelector) * (size + 1));

        lua_pushnil(L);

        for(int i = 0; lua_next(L, 5); i++)
        {
            fieldSelector[i] = (char *)lua_tostring(L, -1);
            fieldSelector[i+1] = 0;
            lua_pop(L, 1);
        }
        lua_pop(L, 1);
    }

    int onlyFieldNames = lua_toboolean(L, 6) ? 1 : 0;

    LDAPMessage *message = 0;
    int err = ldap_search_ext_s(ldap->ldap, dn, _scope, filter, fieldSelector, onlyFieldNames, 0, 0, 0, LDAP_NO_LIMIT, &message);

    if(err != 0)
    {
        ldap_msgfree(message);
        openldap_uv_lua__check_error(L, ldap, err);
    }

    LDAPMessage *entry = ldap_first_entry(ldap->ldap, message);

    lua_newtable(L);

    while(entry)
    {
        char *dn = ldap_get_dn(ldap->ldap, entry);
        lua_pushstring(L, dn);
        free(dn);

        lua_newtable(L);

        BerElement *ber;
        char *attr = ldap_first_attribute(ldap->ldap, entry, &ber);

        int j = 0;
        while(attr)
        {
            struct berval **vals = ldap_get_values_len(ldap->ldap, entry, attr );

            if(vals)
            {
                for(int i = 0; vals[i]; i++)
                {
                    lua_pushnumber(L, ++j);

                    lua_newtable(L);

                    lua_pushnumber(L, 1);
                    lua_pushstring(L, attr);
                    lua_rawset(L, -3);

                    lua_pushnumber(L, 2);
                    lua_pushlstring(L, vals[i]->bv_val, vals[i]->bv_len);
                    lua_rawset(L, -3);

                    lua_rawset(L, -3);
                }

                ldap_value_free_len( vals );
            }

            ldap_memfree( attr );

            attr = ldap_next_attribute( ldap->ldap, entry, ber);
        }

        lua_rawset(L, -3);

        entry = ldap_next_entry(ldap->ldap, entry);
    }

    ldap_msgfree(message);

    return 1;
}

LUA_EXPORT(int openldap_uv_lua_destory(lua_State *L))
{
    openldap_uv_lua_handle_t *ldap = luaL_checkudata(L, 1, META_TABLE);
    openldap_uv_lua__destory(ldap);
    return 0;
}

static const luaL_reg metafunctions[] = {
    { "bind", openldap_uv_lua_bind },
    { "search", openldap_uv_lua_search },
    { "close", openldap_uv_lua_destory },
    { NULL, NULL }
};

static const luaL_reg functions[] = {
    { "connect", openldap_uv_lua_connect },
    { NULL, NULL }
};


int luaopen_openldapuv(lua_State* L)
{
    luaL_newmetatable(L, META_TABLE);

    lua_newtable(L);
    luaL_register(L, NULL, metafunctions);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, openldap_uv_lua__gc_handle);
    lua_setfield(L, -2, "__gc");
    lua_pop(L, 1);

    lua_newtable (L);

    luaL_register(L, NULL, functions);

    return 1;
}

#ifdef LIB_SHARED
LUALIB_API int luaopen_lua(lua_State *L)
{
    return luaopen_openldapuv(L);
}
#endif
