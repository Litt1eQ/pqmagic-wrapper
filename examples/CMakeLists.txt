cmake_minimum_required(VERSION 3.16)

# Example programs
set(EXAMPLE_SOURCES
    example_kem.c
    example_sig.c
)

foreach(example_src ${EXAMPLE_SOURCES})
    get_filename_component(example_name ${example_src} NAME_WE)
    add_executable(${example_name} ${example_src})
    target_link_libraries(${example_name} pqmagic_wrapper)
    target_include_directories(${example_name} PRIVATE
        ${CMAKE_SOURCE_DIR}/include
    )
endforeach()

# Copy example data if exists
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/data)
    file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/data
         DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
endif()