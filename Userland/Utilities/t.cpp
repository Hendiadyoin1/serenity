/*
 * Copyright (c) 2026, Sönke Holz <soenke.holz@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Random.h>
#include <LibCore/ElapsedTimer.h>
#include <LibGL/GLContext.h>
#include <LibGUI/Application.h>
#include <LibGUI/Painter.h>
#include <LibGUI/Window.h>
#include <LibMain/Main.h>

static float random_float()
{
    return get_random<u32>() / static_cast<float>(NumericLimits<u32>::max());
}

class Canvas final : public GUI::Widget {
    C_OBJECT(Canvas)
public:
    virtual ~Canvas() override = default;

    Canvas(GL::GLContext& context, NonnullRefPtr<Gfx::Bitmap> const& bitmap)
        : m_bitmap(bitmap)
        , m_context(context)
    {
        m_bitmap->fill(Color::Cyan);

        warnln("Vendor:     {}", reinterpret_cast<char const*>(glGetString(GL_VENDOR)));
        warnln("Renderer:   {}", reinterpret_cast<char const*>(glGetString(GL_RENDERER)));
        warnln("Version:    {}", reinterpret_cast<char const*>(glGetString(GL_VERSION)));
        warnln("Entensions: {}", reinterpret_cast<char const*>(glGetString(GL_EXTENSIONS)));

        start_timer(500);
    }

private:
    NonnullRefPtr<Gfx::Bitmap> m_bitmap;

    virtual void paint_event(GUI::PaintEvent& event) override
    {
        GUI::Painter painter(*this);
        painter.add_clip_rect(event.rect());
        painter.draw_scaled_bitmap(rect(), *m_bitmap, m_bitmap->rect());
    }

    virtual void timer_event(Core::TimerEvent&) override
    {
        glClearColor(random_float(), random_float(), random_float(), 1.0f);
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

        VERIFY(glGetError() == 0);

        m_context.present();

        update();
    }

    GL::GLContext& m_context;
};

ErrorOr<int> serenity_main(Main::Arguments arguments)
{
    auto app = TRY(GUI::Application::create(arguments));
    auto window = TRY(GUI::Window::try_create());

    auto bitmap = TRY(Gfx::Bitmap::create(Gfx::BitmapFormat::BGRx8888, { 640, 480 }));

    auto context = TRY(GL::create_context(*bitmap));
    GL::make_context_current(context);

    glFrontFace(GL_CCW);
    glEnable(GL_CULL_FACE);
    glEnable(GL_DEPTH_TEST);

    window->set_title("LibGL Test");
    window->set_resizable(false);
    window->resize(640, 480);
    (void)window->set_main_widget<Canvas>(*context, bitmap);
    window->show();

    return app->exec();
}
