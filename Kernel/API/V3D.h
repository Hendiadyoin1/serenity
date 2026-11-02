/*
 * Copyright (c) 2025, Sönke Holz <soenke.holz@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Types.h>

struct V3DBuffer {
    // Set by userspace.
    u32 size;

    // Set by the kernel.
    u32 gpu_virtual_address;
};

struct V3DJob {
    u32 tile_state_data_array_address;
    u32 tile_allocation_memory_address;
    u32 tile_allocation_memory_size;

    u32 binning_control_list_address;
    u32 binning_control_list_size;

    u32 rendering_control_list_address;
    u32 rendering_control_list_size;
};

// XXX: For libgpu-linux-shim
#ifdef AK_OS_LINUX
#    define V3D_ALLOCATE_BUFFER 0xcccc0000
#    define V3D_FREE_BUFFER 0xcccc0001
#    define V3D_SUBMIT_JOB 0xcccc0002
#endif
