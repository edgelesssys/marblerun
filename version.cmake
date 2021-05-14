execute_process(COMMAND bash "-c" "git rev-parse HEAD | tr -d '\n'"
                OUTPUT_VARIABLE GIT_REV
                ERROR_QUIET)

set(VERSION_INFO "package util

// Version is the CLI version
var Version = \"${CMAKE_ARGV3}\" // Don't touch! Automatically injected at build-time.

// GitCommit is the git commit hash
var GitCommit = \"${GIT_REV}\"
")

set(SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/..")

if(EXISTS ${SOURCE_DIR}/util/version.go)
    file(READ ${SOURCE_DIR}/util/version.go VERSION_INFO_)
else()
    set(VERSION_INFO_ "")
endif()

if (NOT "${VERSION_INFO}" STREQUAL "${VERSION_INFO_}")
    file(WRITE ${SOURCE_DIR}/util/version.go "${VERSION_INFO}")
endif()