cmake_minimum_required(VERSION 3.21)
project(nrr_qt_native_host LANGUAGES CXX)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# A shared Qt loads its QML plugins at run time; the CMake packages describing
# them matter only for a static link. Including them also drags in every module
# those plugins depend on, so one absent optional module fails the whole
# configure step — a default 6.11.1 install has no Qt TaskTree, which
# QmlAssetDownloader requires, and `find_package(Qt6 ... Qml)` dies on it.
# Overridable: a static build has to set this OFF.
if(NOT DEFINED QT_SKIP_AUTO_QML_PLUGIN_INCLUSION)
    set(QT_SKIP_AUTO_QML_PLUGIN_INCLUSION ON)
endif()

find_package(Qt6 REQUIRED COMPONENTS Core Gui Qml Quick QuickControls2 Widgets)

qt_standard_project_setup()

# Headers carrying a `Q_OBJECT` class are listed so AUTOMOC generates their
# meta-object code; moc reads a source's own text, never what it includes.
set(NRR_HOST_SOURCES
    src/main.cpp
    src/native_bridge.cpp
    src/native_bridge_channel.cpp
    src/native_bridge_files.cpp
    src/native_bridge_rpc.cpp
    src/native_bridge_rpc_diagnostics.cpp
    src/host_includes.h
    src/host_support.h
    src/native_bridge.h
    src/rpc_stdin_reader.h
    src/service_controller.h
)

# The PE resource script carries the executable's icon. It is a Windows
# concept — a `.rc` in the source list of a Linux build has no compiler to
# handle it — so it is generated and added only there. On Linux the icon comes
# from the desktop entry the packaging step installs.
if(WIN32)
    set(APP_ICON_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../../../../assets/icons/app/app.ico")
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/app.rc.in
        ${CMAKE_CURRENT_BINARY_DIR}/generated_app.rc
        @ONLY
    )
    list(APPEND NRR_HOST_SOURCES ${CMAKE_CURRENT_BINARY_DIR}/generated_app.rc)
endif()

# `WIN32` sets the subsystem so no console is allocated; on every other
# platform CMake ignores the keyword.
qt_add_executable(nrr_qt_native_host
    WIN32
    ${NRR_HOST_SOURCES}
)

# The host looks for its payload (QML, presets, icons, the launcher binaries)
# beside itself only. A dev build also reads it from the checkout and the cargo
# profile directory; those paths name the build machine, where on another
# machine anyone could create them, so they are baked only when build.rs asks.
option(NRR_DEV_LAYOUT "Resolve payload from the source checkout (dev builds only)" OFF)
set(NRR_DEV_BIN_DIR "" CACHE PATH "Cargo profile directory holding the launcher binaries")
if(NRR_DEV_LAYOUT)
    get_filename_component(NRR_DEV_REPO_ROOT_ABS "${CMAKE_CURRENT_SOURCE_DIR}/../../../.." ABSOLUTE)
    target_compile_definitions(nrr_qt_native_host PRIVATE
        NRR_DEV_REPO_ROOT="${NRR_DEV_REPO_ROOT_ABS}"
    )
    if(NRR_DEV_BIN_DIR)
        file(TO_CMAKE_PATH "${NRR_DEV_BIN_DIR}" NRR_DEV_BIN_DIR_CMAKE)
        target_compile_definitions(nrr_qt_native_host PRIVATE
            NRR_DEV_BIN_DIR="${NRR_DEV_BIN_DIR_CMAKE}"
        )
    endif()
endif()

target_link_libraries(nrr_qt_native_host PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Qml
    Qt6::Quick
    Qt6::QuickControls2
    Qt6::Widgets
)

# Runtime assets (startup-splash logo, window icon) are looked up beside the
# binary, the same place the package puts them; copy them there.
set(NRR_ASSETS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../../assets")
get_filename_component(NRR_ASSETS_DIR_ABS "${NRR_ASSETS_DIR}" ABSOLUTE)
add_custom_command(TARGET nrr_qt_native_host POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory
        "$<TARGET_FILE_DIR:nrr_qt_native_host>/assets/images/logo"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${NRR_ASSETS_DIR_ABS}/images/logo/logo-lockup-stacked.png"
        "$<TARGET_FILE_DIR:nrr_qt_native_host>/assets/images/logo/logo-lockup-stacked.png"
    COMMAND ${CMAKE_COMMAND} -E make_directory
        "$<TARGET_FILE_DIR:nrr_qt_native_host>/assets/icons/app"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${NRR_ASSETS_DIR_ABS}/icons/app/app.ico"
        "$<TARGET_FILE_DIR:nrr_qt_native_host>/assets/icons/app/app.ico"
    VERBATIM
)

if(WIN32)
    # DwmSetWindowAttribute (DWMWA_USE_IMMERSIVE_DARK_MODE) for dark title bar
    # on Windows 10 1809+ and Windows 11.
    target_link_libraries(nrr_qt_native_host PRIVATE dwmapi)
endif()
