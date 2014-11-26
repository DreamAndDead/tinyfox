cmake_minimum_required(VERSION 3.0)

project (tinyfox)
add_subdirectory (src)

install (DIRECTORY packets/ DESTINATION /opt/tinyfox/packets)
install (FILES README.md LICENSE DESTINATION /opt/tinyfox)
