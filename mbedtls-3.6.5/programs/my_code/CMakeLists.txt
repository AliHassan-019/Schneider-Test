set(executables_mbedtls
    my_test
)

add_dependencies(${programs_target} ${executables_mbedtls})

foreach(exe IN LISTS executables_mbedtls)
    add_executable(${exe} test.c)

    target_link_libraries(${exe}
        mbedtls
        mbedx509
        mbedcrypto
    )
endforeach()

install(TARGETS ${executables_mbedtls}
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                    GROUP_READ GROUP_EXECUTE
                    WORLD_READ WORLD_EXECUTE)
