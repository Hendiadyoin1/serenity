/*
 * Copyright (c) 2026, Sönke Holz <soenke.holz@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibCore/ArgsParser.h>
#include <LibCore/ElapsedTimer.h>
#include <LibCore/EventLoop.h>
#include <LibCore/File.h>
#include <LibCore/MappedFile.h>
#include <LibGL/GLContext.h>
#include <LibMain/Main.h>
#include <SDL2/SDL.h>

ErrorOr<int> serenity_main(Main::Arguments)
{
    static constexpr size_t WIDTH = 1280;
    static constexpr size_t HEIGHT = 720;

    if (SDL_Init(SDL_INIT_VIDEO) != 0) {
        warnln("Failed to initialize SDL: {}", SDL_GetError());
        exit(-1);
    }

    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 1);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 5);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, 0);

    SDL_Window* window = SDL_CreateWindow("LibGL Test", SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED, WIDTH, HEIGHT, SDL_WINDOW_OPENGL);
    if (window == NULL) {
        SDL_Quit();
        warnln("Failed to create an SDL Window: {}", SDL_GetError());
        exit(-1);
    }

    SDL_Renderer* renderer = SDL_CreateRenderer(window, -1, 0);
    if (!renderer) {
        warnln("Failed to create SDL renderer: {}", SDL_GetError());
        exit(-1);
    }

    SDL_SetRenderDrawColor(renderer, 255, 0, 255, SDL_ALPHA_OPAQUE);

    SDL_Texture* texture = SDL_CreateTexture(renderer, SDL_PIXELFORMAT_ARGB8888, SDL_TEXTUREACCESS_STREAMING, WIDTH, HEIGHT);
    if (!texture) {
        warnln("Failed to create SDL texture: {}", SDL_GetError());
        exit(-1);
    }

    auto bitmap = TRY(Gfx::Bitmap::create(Gfx::BitmapFormat::BGRx8888, { WIDTH, HEIGHT }));
    bitmap->fill(Color::Cyan);
    auto context = TRY(GL::create_context(*bitmap));
    GL::make_context_current(context);

    warnln("Vendor:     {}", reinterpret_cast<char const*>(glGetString(GL_VENDOR)));
    warnln("Renderer:   {}", reinterpret_cast<char const*>(glGetString(GL_RENDERER)));
    warnln("Version:    {}", reinterpret_cast<char const*>(glGetString(GL_VERSION)));
    warnln("Entensions: {}", reinterpret_cast<char const*>(glGetString(GL_EXTENSIONS)));

    glFrontFace(GL_CCW);
    glEnable(GL_CULL_FACE);
    glEnable(GL_DEPTH_TEST);

    static constexpr u32 UPDATE_FRAMERATE_EVERY_FRAMES = 30;
    size_t frame_count = 0;
    auto framerate_timer = Core::ElapsedTimer::start_new();

    Core::EventLoop event_loop;
    for (;;) {
        SDL_Event event;
        if (SDL_PollEvent(&event)) {
            if (event.type == SDL_QUIT)
                break;
        }

        event_loop.pump(Core::EventLoop::WaitMode::PollForEvents);

        // x_offset = sin(MonotonicTime::now().milliseconds() / 1000.f);

        glClearColor(0.2f, 0.0f, 0.7f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

        glBegin(GL_TRIANGLES);

        // Front
        glColor3f(1, 0, 0);
        glVertex2f(-.5f, -.5f);
        glVertex2f(.5f, -.5f);
        glVertex2f(0.f, .5f);

        glEnd();

        VERIFY(glGetError() == 0);

        context->present();

        if ((frame_count % UPDATE_FRAMERATE_EVERY_FRAMES) == 0) {
            auto render_time = static_cast<double>(framerate_timer.elapsed_milliseconds()) / UPDATE_FRAMERATE_EVERY_FRAMES;
            auto frame_rate = render_time > 0 ? 1000 / render_time : 0;
            dbgln("{:.0f} fps, {:.1f} ms", frame_rate, render_time);
            framerate_timer = Core::ElapsedTimer::start_new();
        }

        u8* pixels = bitmap->scanline_u8(0);
        int result = SDL_UpdateTexture(texture, NULL, pixels, bitmap->pitch());
        if (result != 0) {
            warnln("Failed to update SDL texture: {}", SDL_GetError());
        }

        SDL_RenderClear(renderer);
        SDL_RenderCopy(renderer, texture, NULL, NULL);
        SDL_RenderPresent(renderer);

        frame_count++;
    }

    SDL_DestroyTexture(texture);
    SDL_DestroyRenderer(renderer);
    SDL_DestroyWindow(window);
    SDL_Quit();
    return 0;
}
