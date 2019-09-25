cmake_minimum_required(VERSION 2.8.9)
project(rina-sockets)
set(CMAKE_BUILD_TYPE Release)

if(NOT IRATI_INSTALL_PATH)
    set(IRATI_INSTALL_PATH "/usr/local/irati" CACHE STRING "" FORCE) 
endif() 
 
#Bring the IRATI headers into the project
include_directories(${IRATI_INSTALL_PATH}/include)
 
#However, the file(GLOB...) allows for wildcard additions:
file(GLOB SOURCES "src/*.c")

#Add third-party already built libraries
add_library(librina-api SHARED IMPORTED)
set_property(TARGET librina-api PROPERTY IMPORTED_LOCATION ${IRATI_INSTALL_PATH}/lib/librina-api.so)
 
#Generate the shared library from the sources
add_library(rina-sockets SHARED ${SOURCES})

target_link_libraries(rina-sockets librina-api)
 
#Set the location for library installation -- i.e., /usr/lib in this case
# not really necessary in this example. Use "sudo make install" to apply
install(TARGETS rina-sockets DESTINATION ${IRATI_INSTALL_PATH}/lib)
