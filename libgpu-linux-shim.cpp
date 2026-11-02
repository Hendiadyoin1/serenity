/*
 * Copyright (c) 2026, Sönke Holz <soenke.holz@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Format.h>
#include <AK/HashMap.h>
#include <AK/Vector.h>
#include <Kernel/API/V3D.h>

#include <dlfcn.h>
#include <drm/v3d_drm.h>
#include <stdarg.h>
#include <sys/ioctl.h>

static constexpr auto SERENITY_DEVICE_PATH = "/dev/gpu/render0";
static constexpr auto LINUX_DEVICE_PATH = "/dev/dri/renderD128";

// Used to translate the Serenity kernel API to the Linux DRM API.
struct Buffer {
    int fd;
    u32 drm_buffer_object_handle;
    u32 gpu_virtual_address;
    u64 drm_mmap_offset;
};
static HashMap<int, HashMap<FlatPtr, Buffer>> s_buffers;

static Vector<u32> s_all_drm_buffer_object_handles;

static int (*original_ioctl)(int fd, unsigned long request, ...) = nullptr;
static void* (*original_mmap)(void* addr, size_t length, int prot, int flags, int fd, off_t offset) = nullptr;
static int (*original_openat)(int dirfd, char const* path, int flags, ...) = nullptr;

static Optional<u32> s_out_sync;

static int ioctl_v3d_submit_job(int fd, V3DJob const* job)
{
    if (!s_out_sync.has_value()) {
        struct drm_syncobj_create syncobj_create = {
            .handle = 0,
            .flags = DRM_SYNCOBJ_CREATE_SIGNALED,
        };
        int ret = ioctl(fd, DRM_IOCTL_SYNCOBJ_CREATE, &syncobj_create);
        VERIFY(ret == 0);

        s_out_sync = syncobj_create.handle;
    }

    u32 out_sync = s_out_sync.value();

    struct drm_v3d_submit_cl submit_cl = {
        // Binner command list (optional)
        .bcl_start = job->binning_control_list_address,
        .bcl_end = job->binning_control_list_address + job->binning_control_list_size,

        // Render command list
        .rcl_start = job->rendering_control_list_address,
        .rcl_end = job->rendering_control_list_address + job->rendering_control_list_size,

        // Optional sync objects
        .in_sync_bcl = 0,
        .in_sync_rcl = 0,
        .out_sync = out_sync,

        // Tile alloc memory offset
        .qma = job->tile_allocation_memory_address,
        // Tile alloc memory size
        .qms = job->tile_allocation_memory_size,

        // Offset of the tile state data array
        .qts = job->tile_state_data_array_address,

        // BOs referenced by this job
        .bo_handles = bit_cast<u64>(s_all_drm_buffer_object_handles.data()),
        .bo_handle_count = static_cast<u32>(s_all_drm_buffer_object_handles.size()),

        .flags = 0,

        .perfmon_id = 0,

        .pad = 0,

        .extensions = 0,
    };

    if (ioctl(fd, DRM_IOCTL_V3D_SUBMIT_CL, &submit_cl) != 0)
        return -1;

    struct drm_syncobj_wait syncobj_wait = {};
    syncobj_wait.handles = (uintptr_t)&out_sync;
    syncobj_wait.timeout_nsec = INT64_MAX;
    syncobj_wait.count_handles = 1;
    syncobj_wait.flags = DRM_SYNCOBJ_WAIT_FLAGS_WAIT_ALL;
    int ret = ioctl(fd, DRM_IOCTL_SYNCOBJ_WAIT, &syncobj_wait);
    VERIFY(ret == 0);

    return 0;
}

static int ioctl_v3d_allocate_buffer(int fd, V3DBuffer* buffer)
{
    struct drm_v3d_create_bo create_bo = {
        .size = buffer->size,
        .flags = 0,

        // Set by the kernel
        .handle = 0,
        .offset = 0,
    };

    if (ioctl(fd, DRM_IOCTL_V3D_CREATE_BO, &create_bo) != 0)
        return -1;

    buffer->gpu_virtual_address = create_bo.offset;

    s_all_drm_buffer_object_handles.append(create_bo.handle);

    struct drm_v3d_mmap_bo mmap_bo = {
        .handle = create_bo.handle,
        .flags = 0,

        // Set by the kernel
        .offset = 0,
    };

    if (ioctl(fd, DRM_IOCTL_V3D_MMAP_BO, &mmap_bo) != 0)
        return -1;

    s_buffers.ensure(fd).set(buffer->gpu_virtual_address, {
                                                              .fd = fd,
                                                              .drm_buffer_object_handle = create_bo.handle,
                                                              .gpu_virtual_address = buffer->gpu_virtual_address,
                                                              .drm_mmap_offset = mmap_bo.offset,
                                                          });

    return 0;
}

static Optional<Buffer const&> look_up_buffer(int fd, FlatPtr gpu_virtual_address)
{
    auto buffers = s_buffers.get(fd);
    if (!buffers.has_value())
        return {};

    return buffers->get(gpu_virtual_address);
}

static int ioctl_v3d_free_buffer(int fd, FlatPtr gpu_virtual_address)
{
    auto const& buffer = *look_up_buffer(fd, gpu_virtual_address);

    struct drm_gem_close close = {
        .handle = static_cast<u32>(buffer.drm_buffer_object_handle),
        .pad = 0,
    };

    s_all_drm_buffer_object_handles.remove_first_matching([&buffer](u32 handle) { return handle == buffer.drm_buffer_object_handle; });
    s_buffers.get(fd)->remove(gpu_virtual_address);

    if (ioctl(fd, DRM_IOCTL_GEM_CLOSE, &close) != 0)
        return -1;

    return 0;
}

extern "C" int ioctl(int fd, unsigned long request, ...)
{
    if (original_ioctl == nullptr) {
        original_ioctl = reinterpret_cast<decltype(original_ioctl)>(dlsym(RTLD_NEXT, "ioctl"));
        VERIFY(original_ioctl != nullptr);
    }

    va_list args;
    va_start(args, request);

    void* arg = va_arg(args, void*);

    int ret = -1;
    if (request == V3D_ALLOCATE_BUFFER)
        ret = ioctl_v3d_allocate_buffer(fd, reinterpret_cast<V3DBuffer*>(arg));
    else if (request == V3D_FREE_BUFFER)
        ret = ioctl_v3d_free_buffer(fd, bit_cast<u64>(arg));
    else if (request == V3D_SUBMIT_JOB)
        ret = ioctl_v3d_submit_job(fd, reinterpret_cast<V3DJob const*>(arg));
    else
        ret = original_ioctl(fd, request, arg);

    va_end(args);

    return ret;
}

extern "C" void* mmap64(void* addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    if (original_mmap == nullptr) {
        original_mmap = reinterpret_cast<decltype(original_mmap)>(dlsym(RTLD_NEXT, "mmap"));
        VERIFY(original_mmap != nullptr);
    }

    auto maybe_buffer = look_up_buffer(fd, offset);
    if (!maybe_buffer.has_value()) {
        return original_mmap(addr, length, prot, flags, fd, offset);
    }

    auto const& buffer = maybe_buffer.value();

    return original_mmap(addr, length, prot, flags, fd, buffer.drm_mmap_offset);
}

extern "C" int openat64(int dirfd, char const* path, int flags, ...)
{
    if (original_openat == nullptr) {
        original_openat = reinterpret_cast<decltype(original_openat)>(dlsym(RTLD_NEXT, "openat"));
        VERIFY(original_openat != nullptr);
    }

    va_list args;
    va_start(args, flags);

    mode_t mode = va_arg(args, mode_t);

    int ret = -1;
    if (strcmp(path, SERENITY_DEVICE_PATH) == 0) {
        ret = original_openat(dirfd, LINUX_DEVICE_PATH, flags, mode);
    } else {
        ret = original_openat(dirfd, path, flags, mode);
    }

    va_end(args);

    return ret;
}
