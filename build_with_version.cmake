execute_process(COMMAND bash "-c" "git rev-parse HEAD | tr -d '\n'"
                OUTPUT_VARIABLE GIT_COMMIT
                ERROR_QUIET)

set(COMPILER ${CMAKE_ARGV3})
set(PROJECT_VERSION ${CMAKE_ARGV4})
set(OUTPUT_NAME ${CMAKE_ARGV5})
set(INJECT_PATH ${CMAKE_ARGV6})
set(TRIMPATH ${CMAKE_ARGV7})


if("${COMPILER}" STREQUAL "go")
    execute_process(
        COMMAND
        go build ${TRIMPATH}
        -o ${OUTPUT_NAME}
        -buildvcs=false
        -ldflags "-X '${INJECT_PATH}.Version=${PROJECT_VERSION}' -X '${INJECT_PATH}.GitCommit=${GIT_COMMIT}'"
    )
else()
    execute_process(
        COMMAND
        ertgo build ${TRIMPATH} -buildmode=c-archive -tags enclave
        -o ${OUTPUT_NAME}
        -buildvcs=false
        -ldflags "-X '${INJECT_PATH}.Version=${PROJECT_VERSION}' -X '${INJECT_PATH}.GitCommit=${GIT_COMMIT}'"
    )
endif()
