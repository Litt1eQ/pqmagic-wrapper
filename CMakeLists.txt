cmake_minimum_required(VERSION 3.16)

project(PQMagicWrapper
    VERSION 1.0.0
    DESCRIPTION "PQMagic Wrapper Library with liboqs-style API"
    LANGUAGES C
)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

# Options
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(BUILD_TESTS "Build unit tests" ON)
option(BUILD_EXAMPLES "Build example programs" ON)

# Compiler flags
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic -Wstrict-prototypes -Wmissing-prototypes")
    set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
    set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
    set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG")
endif()

if(MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4")
    set(CMAKE_C_FLAGS_DEBUG "/Od /Zi")
    set(CMAKE_C_FLAGS_RELEASE "/O2 /DNDEBUG")
endif()

# Find PQMagic
if(NOT TARGET pqmagic_target)
    # Build PQMagic as external project
    message(STATUS "Building PQMagic...")
    
    # Create build directory for PQMagic
    set(PQMAGIC_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external/PQMagic)
    set(PQMAGIC_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/external/PQMagic)
    set(PQMAGIC_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/pqmagic_install)
    
    # Configure PQMagic build
    file(MAKE_DIRECTORY ${PQMAGIC_BUILD_DIR})
    
    execute_process(
        COMMAND ${CMAKE_COMMAND} 
            -S ${PQMAGIC_SOURCE_DIR}
            -B ${PQMAGIC_BUILD_DIR}
            -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
            -DCMAKE_INSTALL_PREFIX=${PQMAGIC_INSTALL_DIR}
            -DENABLE_TEST=OFF
            -DENABLE_BENCH=OFF
        RESULT_VARIABLE PQMAGIC_CONFIG_RESULT
        OUTPUT_VARIABLE PQMAGIC_CONFIG_OUTPUT
        ERROR_VARIABLE PQMAGIC_CONFIG_ERROR
    )
    
    if(NOT PQMAGIC_CONFIG_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to configure PQMagic: ${PQMAGIC_CONFIG_ERROR}")
    endif()
    
    # Build PQMagic
    execute_process(
        COMMAND ${CMAKE_COMMAND} --build ${PQMAGIC_BUILD_DIR} --parallel
        RESULT_VARIABLE PQMAGIC_BUILD_RESULT
        OUTPUT_VARIABLE PQMAGIC_BUILD_OUTPUT
        ERROR_VARIABLE PQMAGIC_BUILD_ERROR
    )
    
    if(NOT PQMAGIC_BUILD_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to build PQMagic: ${PQMAGIC_BUILD_ERROR}")
    endif()
    
    # Install PQMagic
    execute_process(
        COMMAND ${CMAKE_COMMAND} --install ${PQMAGIC_BUILD_DIR}
        RESULT_VARIABLE PQMAGIC_INSTALL_RESULT
        OUTPUT_VARIABLE PQMAGIC_INSTALL_OUTPUT
        ERROR_VARIABLE PQMAGIC_INSTALL_ERROR
    )
    
    if(NOT PQMAGIC_INSTALL_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to install PQMagic: ${PQMAGIC_INSTALL_ERROR}")
    endif()
    
    # Set up imported target
    add_library(pqmagic_target SHARED IMPORTED)
    if(WIN32)
        set_target_properties(pqmagic_target PROPERTIES
            IMPORTED_LOCATION ${PQMAGIC_INSTALL_DIR}/lib/libpqmagic_std.dll
            IMPORTED_IMPLIB ${PQMAGIC_INSTALL_DIR}/lib/libpqmagic_std_import.lib
        )
    elseif(APPLE)
        set_target_properties(pqmagic_target PROPERTIES
            IMPORTED_LOCATION ${PQMAGIC_INSTALL_DIR}/lib/libpqmagic_std.dylib
        )
    else()
        set_target_properties(pqmagic_target PROPERTIES
            IMPORTED_LOCATION ${PQMAGIC_INSTALL_DIR}/lib/libpqmagic_std.so
        )
    endif()
    
    # Set include directories
    set(PQMAGIC_INCLUDE_DIR ${PQMAGIC_INSTALL_DIR}/include)
    target_include_directories(pqmagic_target INTERFACE ${PQMAGIC_INCLUDE_DIR})
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
if(EXISTS ${PQMAGIC_INSTALL_DIR}/include)
    include_directories(${PQMAGIC_INSTALL_DIR}/include)
else()
    # Fallback to external PQMagic include directory
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/external/PQMagic/include)
endif()

# Source files
set(WRAPPER_SOURCES
    src/pqmagic_wrapper.c
    src/common.c
    
    # KEM algorithms
    src/kem/kem.c
    src/kem/ml_kem/kem_ml_kem_512.c
    src/kem/ml_kem/kem_ml_kem_768.c
    src/kem/ml_kem/kem_ml_kem_1024.c
    src/kem/kyber/kem_kyber_512.c
    src/kem/kyber/kem_kyber_768.c
    src/kem/kyber/kem_kyber_1024.c
    src/kem/aigis_enc/kem_aigis_enc_1.c
    src/kem/aigis_enc/kem_aigis_enc_2.c
    src/kem/aigis_enc/kem_aigis_enc_3.c
    src/kem/aigis_enc/kem_aigis_enc_4.c
    
    # Signature algorithms
    src/sig/sig.c
    src/sig/ml_dsa/sig_ml_dsa_44.c
    src/sig/ml_dsa/sig_ml_dsa_65.c
    src/sig/ml_dsa/sig_ml_dsa_87.c
    src/sig/dilithium/sig_dilithium_2.c
    src/sig/dilithium/sig_dilithium_3.c
    src/sig/dilithium/sig_dilithium_5.c
    src/sig/slh_dsa/sig_slh_dsa_sha2_128f.c
    src/sig/slh_dsa/sig_slh_dsa_sha2_128s.c
    src/sig/slh_dsa/sig_slh_dsa_sha2_192f.c
    src/sig/slh_dsa/sig_slh_dsa_sha2_192s.c
    src/sig/slh_dsa/sig_slh_dsa_sha2_256f.c
    src/sig/slh_dsa/sig_slh_dsa_sha2_256s.c
    src/sig/slh_dsa/sig_slh_dsa_shake_128f.c
    src/sig/slh_dsa/sig_slh_dsa_shake_128s.c
    src/sig/slh_dsa/sig_slh_dsa_shake_192f.c
    src/sig/slh_dsa/sig_slh_dsa_shake_192s.c
    src/sig/slh_dsa/sig_slh_dsa_shake_256f.c
    src/sig/slh_dsa/sig_slh_dsa_shake_256s.c
    src/sig/slh_dsa/sig_slh_dsa_sm3_128f.c
    src/sig/slh_dsa/sig_slh_dsa_sm3_128s.c
    src/sig/sphincs_alpha/sig_sphincs_a_sha2_128f.c
    src/sig/sphincs_alpha/sig_sphincs_a_sha2_128s.c
    src/sig/sphincs_alpha/sig_sphincs_a_sha2_192f.c
    src/sig/sphincs_alpha/sig_sphincs_a_sha2_192s.c
    src/sig/sphincs_alpha/sig_sphincs_a_sha2_256f.c
    src/sig/sphincs_alpha/sig_sphincs_a_sha2_256s.c
    src/sig/sphincs_alpha/sig_sphincs_a_shake_128f.c
    src/sig/sphincs_alpha/sig_sphincs_a_shake_128s.c
    src/sig/sphincs_alpha/sig_sphincs_a_shake_192f.c
    src/sig/sphincs_alpha/sig_sphincs_a_shake_192s.c
    src/sig/sphincs_alpha/sig_sphincs_a_shake_256f.c
    src/sig/sphincs_alpha/sig_sphincs_a_shake_256s.c
    src/sig/sphincs_alpha/sig_sphincs_a_sm3_128f.c
    src/sig/sphincs_alpha/sig_sphincs_a_sm3_128s.c
    src/sig/aigis_sig/sig_aigis_sig_1.c
    src/sig/aigis_sig/sig_aigis_sig_2.c
    src/sig/aigis_sig/sig_aigis_sig_3.c
)

# Create wrapper library
add_library(pqmagic_wrapper ${WRAPPER_SOURCES})

# Set library properties
set_target_properties(pqmagic_wrapper PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    PUBLIC_HEADER include/pqmagic_wrapper.h
)

# Link libraries
target_link_libraries(pqmagic_wrapper PRIVATE pqmagic_target)

# Include directories for target
target_include_directories(pqmagic_wrapper
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${PQMAGIC_INCLUDE_DIR}
)

# Compiler definitions
target_compile_definitions(pqmagic_wrapper PRIVATE PQMAGIC_WRAPPER_BUILD)

# Install library
install(TARGETS pqmagic_wrapper
    EXPORT PQMagicWrapperTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    PUBLIC_HEADER DESTINATION include
)

# Install headers
install(DIRECTORY include/
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)

# Export targets
install(EXPORT PQMagicWrapperTargets
    FILE PQMagicWrapperTargets.cmake
    NAMESPACE PQMagicWrapper::
    DESTINATION lib/cmake/PQMagicWrapper
)

# Create config file
include(CMakePackageConfigHelpers)
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/PQMagicWrapperConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/PQMagicWrapperConfig.cmake
    INSTALL_DESTINATION lib/cmake/PQMagicWrapper
)

# Create version file
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/PQMagicWrapperConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

# Install config files
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/PQMagicWrapperConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/PQMagicWrapperConfigVersion.cmake
    DESTINATION lib/cmake/PQMagicWrapper
)

# Unit tests
if(BUILD_TESTS)
    enable_testing()
    
    # Find or build a unit testing framework
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(CHECK check)
    endif()
    
    if(CHECK_FOUND)
        message(STATUS "Using system libcheck for unit tests")
        set(TEST_FRAMEWORK_LIBRARIES ${CHECK_LIBRARIES})
        set(TEST_FRAMEWORK_INCLUDE_DIRS ${CHECK_INCLUDE_DIRS})
    else()
        # Use built-in minimal test framework
        message(STATUS "Using built-in test framework")
        set(TEST_FRAMEWORK_LIBRARIES "")
        set(TEST_FRAMEWORK_INCLUDE_DIRS "")
        add_definitions(-DUSE_MINIMAL_TEST_FRAMEWORK)
    endif()
    
    # Test sources
    set(TEST_SOURCES
        tests/test_main.c
        tests/test_kem.c
        tests/test_sig.c
        tests/test_common.c
    )
    
    # Create test executable
    add_executable(test_pqmagic_wrapper ${TEST_SOURCES})
    target_link_libraries(test_pqmagic_wrapper 
        pqmagic_wrapper 
        ${TEST_FRAMEWORK_LIBRARIES}
    )
    target_include_directories(test_pqmagic_wrapper PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/tests
        ${TEST_FRAMEWORK_INCLUDE_DIRS}
    )
    
    # Add tests
    add_test(NAME test_pqmagic_wrapper COMMAND test_pqmagic_wrapper)
    
    # Copy test data if it exists
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/data)
        file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/tests/data
             DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/tests)
    endif()
endif()

# Examples
if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Print summary
message(STATUS "")
message(STATUS "PQMagic Wrapper Configuration Summary:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Build shared libs: ${BUILD_SHARED_LIBS}")
message(STATUS "  Build tests: ${BUILD_TESTS}")
message(STATUS "  Build examples: ${BUILD_EXAMPLES}")
message(STATUS "  C compiler: ${CMAKE_C_COMPILER}")
message(STATUS "  Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")