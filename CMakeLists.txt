# Copyright (C) 2017 Ben Smith
#
# This software may be modified and distributed under the terms
# of the MIT license.  See the LICENSE file for details.
cmake_minimum_required(VERSION 2.8)
project(lupica)

if (MSVC)
  add_definitions(-W3 -D_CRT_SECURE_NO_WARNINGS)
else ()
  add_definitions(
    -Wall -Wextra -Werror -Wpointer-arith -Wno-unused-parameter -g
    -Wno-unused-function
    -Wno-unused-variable
  )
endif ()

function (target_copy_to_bin name)
add_custom_target(${name}-copy-to-bin ALL
  COMMAND ${CMAKE_COMMAND} -E make_directory ${PROJECT_SOURCE_DIR}/bin
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${name}> ${PROJECT_SOURCE_DIR}/bin
  DEPENDS ${name}
)
endfunction ()

add_executable(lupica
  src/lupica.c
)

install(TARGETS lupica DESTINATION bin)
target_copy_to_bin(lupica)
