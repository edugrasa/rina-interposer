cmake_minimum_required(VERSION 2.8.9)
project(rina-sockets)
set(CMAKE_BUILD_TYPE Release)
 
#Bring the headers, such as Student.h into the project
include_directories(/usr/local/irati/include)
 
#However, the file(GLOB...) allows for wildcard additions:
file(GLOB SOURCES "src/*.c")

#Add third-party already built libraries
add_library(librina-api SHARED IMPORTED)
set_property(TARGET librina-api PROPERTY IMPORTED_LOCATION /usr/local/irati/lib/librina-api.so)
 
#Generate the shared library from the sources
add_library(rina-sockets SHARED ${SOURCES})

target_link_libraries(rina-sockets librina-api)
 
#Set the location for library installation -- i.e., /usr/lib in this case
# not really necessary in this example. Use "sudo make install" to apply
install(TARGETS rina-sockets DESTINATION /usr/local/irati/lib)
