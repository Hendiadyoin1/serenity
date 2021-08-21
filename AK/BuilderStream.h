/*
 * Copyright (c) 2021, Leon Albrecht <leon2002.la@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Noncopyable.h>
#include <AK/Stream.h>

namespace AK {

template<typename Builder>
class OutputBuilderStream : OutputStream {
    AK_MAKE_NONCOPYABLE(OutputBuilderStream);

public:
    virtual OutputBuilderStream(Builder& builder)
        : m_builder(builder)
    {
    }
    virtual size_t write(ReadonlyBytes data)
    {
        // FIXME: Make this not ignorant
        builder.append_bytes(data);
        return data.size();
    };
    virtual bool write_or_error(ReadonlyBytes data) { return write(data) == data.size() };
    virtual ~OutputBuilderStream() override { }

private:
    Builder& m_builder;
};

}

using AK::OutputBuilderStream;
