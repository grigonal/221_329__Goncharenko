cmake_minimum_required(VERSION 3.14)

project(lab1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core)

add_executable(lab1
  main.cpp
  res.qrc
)

include(GNUInstallDirs)
install(TARGETS lab1
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)


target_include_directories(
    lab1
    PRIVATE
    C:/Qt/Tools/OpenSSLv3/Win_x64/include)
target_link_libraries(
    lab1
    PRIVATE
    C:/Qt/Tools/OpenSSLv3/Win_x64/lib/libcrypto.lib
    Qt${QT_VERSION_MAJOR}::Core)

