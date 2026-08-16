cmake_minimum_required(VERSION 3.21)
project(nrr_qt_native_host LANGUAGES CXX)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 REQUIRED COMPONENTS Core Gui Qml Quick QuickControls2 Widgets)

qt_standard_project_setup()

set(NRR_HOST_SOURCES src/main.cpp)

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

# Bake absolute QML paths so the host can locate them regardless of where
# `target-dir` redirects build artefacts (e.g. fast local drive away from a
# synced source tree). `findUpwardFile` from the binary location is tried
# first; this is the deterministic dev-mode fallback.
set(NRR_QML_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../qml")
get_filename_component(NRR_QML_DIR_ABS "${NRR_QML_DIR}" ABSOLUTE)
# Same fallback story for `presets/` (country packs) and
# `configs/presets/` (builtin-demo). Walking upward fails when the
# build target-dir is on a different drive than the source tree.
set(NRR_PRESETS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../../presets")
get_filename_component(NRR_PRESETS_DIR_ABS "${NRR_PRESETS_DIR}" ABSOLUTE)
set(NRR_CONFIGS_PRESETS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../../configs/presets")
get_filename_component(NRR_CONFIGS_PRESETS_DIR_ABS "${NRR_CONFIGS_PRESETS_DIR}" ABSOLUTE)
target_compile_definitions(nrr_qt_native_host PRIVATE
    NRR_QML_MAIN_DEFAULT="${NRR_QML_DIR_ABS}/Main.qml"
    NRR_QML_TRAY_DEFAULT="${NRR_QML_DIR_ABS}/Tray.qml"
    NRR_PRESETS_ROOT_DEFAULT="${NRR_PRESETS_DIR_ABS}"
    NRR_CONFIGS_PRESETS_ROOT_DEFAULT="${NRR_CONFIGS_PRESETS_DIR_ABS}"
)

target_link_libraries(nrr_qt_native_host PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Qml
    Qt6::Quick
    Qt6::QuickControls2
    Qt6::Widgets
)

# Runtime assets (startup-splash logo, window icon) are resolved by walking
# upward from the binary, which fails when the build target-dir lives on a
# different drive than the source tree and equally in an installed layout.
# Copy them next to the binary so the depth-0 lookup always succeeds; this
# also mirrors how an installer lays assets out relative to the executables.
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
