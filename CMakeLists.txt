cmake_minimum_required(VERSION 2.8)
project(openldap-uv-lua C)

if(NOT DEFINED LUAJIT_INCLUDE_DIRS)
    find_package(PkgConfig)
    message(STATUS "Detecting LuaJIT...")
    if(PKG_CONFIG_FOUND)
        message(STATUS "Using pkg-config to detect LuaJIT...")
        pkg_check_modules(LUAJIT luajit)
        if(LUAJIT_FOUND)
            message(STATUS "Found LuaJIT.")
            message(STATUS "include: ${LUAJIT_INCLUDE_DIRS}")
            include_directories(${LUAJIT_INCLUDE_DIRS})
            link_directories(${LUAJIT_LIBRARY_DIRS})
            set(EXTRA_LIBS ${LUAJIT_LIBRARIES})
        else()
            message(FATAL_ERROR "LuaJIT not found.")
        endif()
    else()
        message(STATUS "Using local LuaJIT.")
        set(LUAJIT_LIBRARIES luajit)
    endif()
endif()

set(OPENLDAPUVLUA_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${UV_INCLUDE_DIRS}
    ${LUAJIT_INCLUDE_DIRS}
    CACHE INTERNAL "OpenLDAP-uv-lua include directories")

set(OPENLDAPUVLUA_LIBRARY
    "openldapuv"
    CACHE INTERNAL "OpenLDAP-uv-lua library name")

set(OPENLDAPUVLUA_LIBRARIES
    ${OPENLDAPUVLUA_LIBRARY}
    ldap_r
    ${LUAJIT_LIBRARIES}
    CACHE INTERNAL "OpenLDAP-uv-lua libraries")

set(OPENLDAPUVLUA_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/api.c)

set(OPENLDAPUVLUA_MODE "SHARED")

if("${OPENLDAPUVLUA_MODE}" MATCHES "SHARED")
    add_definitions(-DLIB_SHARED=1)
endif()

include_directories(${OPENLDAPUVLUA_INCLUDE_DIRS})

add_library(${OPENLDAPUVLUA_LIBRARY} ${OPENLDAPUVLUA_MODE}
    ${OPENLDAPUVLUA_SOURCES})

target_link_libraries(${OPENLDAPUVLUA_LIBRARIES} ${OPENLDAPUVLUA_LIBRARIES})

if(INSTALL_LIBRARY_DIR)
    install(
        TARGETS ${OPENLDAPUVLUA_LIBRARY}
        ARCHIVE DESTINATION ${INSTALL_ARCHIVE_DIR}
        LIBRARY DESTINATION ${INSTALL_LIBRARY_DIR})
endif()

if(INSTALL_LUA_DIR)
    install(
        DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test
        DESTINATION ${INSTALL_LUA_DIR})
endif()
