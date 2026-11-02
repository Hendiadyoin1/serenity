find_package(SDL2 REQUIRED)

include_directories(${SDL2_INCLUDE_DIRS})
add_executable(LibGLTestSDL main.cpp ../../../../Userland/Applications/3DFileViewer/WavefrontOBJLoader.cpp ../../../../Userland/Applications/3DFileViewer/Mesh.cpp)

target_include_directories(LibGLTestSDL PRIVATE ${SDL2_INCLUDE_DIRS})
target_link_libraries(LibGLTestSDL PRIVATE LibMain LibCore LibGfx LibGL SDL2::SDL2)
