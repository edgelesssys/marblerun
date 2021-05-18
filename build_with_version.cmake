execute_process(COMMAND bash "-c" "git rev-parse HEAD | tr -d '\n'"
                OUTPUT_VARIABLE GIT_COMMIT
                ERROR_QUIET)

set(COMPILER ${CMAKE_ARGV3})
set(PROJECT_VERSION ${CMAKE_ARGV4})
set(OUTPUT_NAME ${CMAKE_ARGV5})
set(BUILD_SOURCE ${CMAKE_ARGV6})
set(INJECT_PATH ${CMAKE_ARGV7})
set(TRIMPATH ${CMAKE_ARGV8})


if("${COMPILER}" STREQUAL "go")
    execute_process(
        COMMAND
        go build ${TRIMPATH}
        -o ${OUTPUT_NAME}
        -ldflags "-X '${INJECT_PATH}.Version=${PROJECT_VERSION}' -X '${INJECT_PATH}.GitCommit=${GIT_COMMIT}'"
        ${BUILD_SOURCE}
    )
else()
    execute_process(
        COMMAND
        ertgo build ${TRIMPATH} -buildmode=c-archive -tags enclave
        -o ${OUTPUT_NAME}
        -ldflags "-X '${INJECT_PATH}.Version=${PROJECT_VERSION}' -X '${INJECT_PATH}.GitCommit=${GIT_COMMIT}'"
        ${BUILD_SOURCE})
endif()