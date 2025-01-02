/*
 * Copyright (c) 2022, Oleg Kosenkov <oleg@kosenkov.ca>
 * Copyright (c) 2022, the SerenityOS developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Math.h>
#include <LibGfx/Filters/MatrixFilter.h>

// This filter is similar to LibGfx/Filters/HueRotateFilter.h, however it uses
// a different formula (matrix) for hue rotation. This filter provides brighter
// colors compared to the filter provided in LibGfx.
class HueFilter : public Gfx::MatrixFilter {
public:
    HueFilter(float angle_degrees)
        : Gfx::MatrixFilter(calculate_hue_rotate_matrix(angle_degrees))
    {
    }

    virtual bool amount_handled_in_filter() const override
    {
        return true;
    }

    virtual StringView class_name() const override { return "HueFilter"sv; }

private:
    static FloatMatrix3x3 calculate_hue_rotate_matrix(float angle_degrees)
    {
        float const angle_rads = AK::to_radians(angle_degrees);
        float const sqrt_3 = AK::sqrt(3.0f);
        auto [sin, cos] = AK::sincos(angle_rads);
        return FloatMatrix3x3 {
            1 + 2 * cos,
            1 - cos - sqrt_3 * sin,
            1 - cos + sqrt_3 * sin,

            1 - cos + sqrt_3 * sin,
            1 + 2 * cos,
            1 - cos - sqrt_3 * sin,

            1 - cos - sqrt_3 * sin,
            1 - cos + sqrt_3 * sin,
            1 + 2 * cos
        }
        / 3;
    }
};
