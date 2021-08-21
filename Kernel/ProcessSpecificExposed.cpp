/*
 * Copyright (c) 2021, Liav A. <liavalb@hotmail.co.il>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/BuilderStream.h>
#include <AK/JsonArraySerializer.h>
#include <AK/JsonObjectSerializer.h>
#include <AK/JsonValue.h>
#include <Kernel/API/ProcFSProtocol.h>
#include <Kernel/Arch/x86/InterruptDisabler.h>
#include <Kernel/FileSystem/Custody.h>
#include <Kernel/FileSystem/ProcFS.h>
#include <Kernel/KBufferBuilder.h>
#include <Kernel/Memory/AnonymousVMObject.h>
#include <Kernel/Memory/MemoryManager.h>
#include <Kernel/Process.h>
#include <Kernel/ProcessExposed.h>

namespace Kernel {

KResultOr<size_t> Process::procfs_get_thread_stack(ThreadID thread_id, KBufferBuilder& builder) const
{
    JsonArraySerializer array { builder };
    auto thread = Thread::from_tid(thread_id);
    if (!thread)
        return KResult(ESRCH);
    bool show_kernel_addresses = Process::current()->is_superuser();
    bool kernel_address_added = false;
    for (auto address : Processor::capture_stack_trace(*thread, 1024)) {
        if (!show_kernel_addresses && !Memory::is_user_address(VirtualAddress { address })) {
            if (kernel_address_added)
                continue;
            address = 0xdeadc0de;
            kernel_address_added = true;
        }
        array.add(address);
    }

    array.finish();
    return KSuccess;
}

KResult Process::traverse_stacks_directory(unsigned fsid, Function<bool(FileSystem::DirectoryEntryView const&)> callback) const
{
    callback({ ".", { fsid, SegmentedProcFSIndex::build_segmented_index_for_main_property(pid(), SegmentedProcFSIndex::ProcessSubDirectory::Stacks, SegmentedProcFSIndex::MainProcessProperty::Reserved) }, 0 });
    callback({ "..", { fsid, m_procfs_traits->component_index() }, 0 });

    for_each_thread([&](const Thread& thread) {
        int tid = thread.tid().value();
        InodeIdentifier identifier = { fsid, SegmentedProcFSIndex::build_segmented_index_for_thread_stack(pid(), thread.tid()) };
        callback({ String::number(tid), identifier, 0 });
    });
    return KSuccess;
}

KResultOr<NonnullRefPtr<Inode>> Process::lookup_stacks_directory(const ProcFS& procfs, StringView name) const
{
    KResultOr<NonnullRefPtr<ProcFSProcessPropertyInode>> thread_stack_inode { ENOENT };

    // FIXME: Try to exit the loop earlier
    for_each_thread([&](const Thread& thread) {
        int tid = thread.tid().value();
        VERIFY(!(tid < 0));
        if (name.to_int() == tid) {
            auto maybe_inode = ProcFSProcessPropertyInode::try_create_for_thread_stack(procfs, thread.tid(), pid());
            if (maybe_inode.is_error()) {
                thread_stack_inode = maybe_inode.error();
                return;
            }

            thread_stack_inode = maybe_inode.release_value();
        }
    });

    if (thread_stack_inode.is_error())
        return thread_stack_inode.error();
    return thread_stack_inode.release_value();
}

KResultOr<size_t> Process::procfs_get_file_description_link(unsigned fd, KBufferBuilder& builder) const
{
    auto file_description = m_fds.file_description(fd);
    if (!file_description)
        return EBADF;
    auto data = file_description->absolute_path();
    builder.append(data);
    return data.length();
}

KResult Process::traverse_file_descriptions_directory(unsigned fsid, Function<bool(FileSystem::DirectoryEntryView const&)> callback) const
{
    callback({ ".", { fsid, m_procfs_traits->component_index() }, 0 });
    callback({ "..", { fsid, m_procfs_traits->component_index() }, 0 });
    size_t count = 0;
    fds().enumerate([&](auto& file_description_metadata) {
        if (!file_description_metadata.is_valid()) {
            count++;
            return;
        }
        StringBuilder builder;
        builder.appendff("{}", count);
        callback({ builder.string_view(), { fsid, SegmentedProcFSIndex::build_segmented_index_for_file_description(pid(), count) }, 0 });
        count++;
    });
    return KSuccess;
}

KResultOr<NonnullRefPtr<Inode>> Process::lookup_file_descriptions_directory(const ProcFS& procfs, StringView name) const
{
    auto maybe_index = name.to_uint();
    if (!maybe_index.has_value())
        return ENOENT;

    if (!fds().get_if_valid(*maybe_index))
        return ENOENT;

    auto maybe_inode = ProcFSProcessPropertyInode::try_create_for_file_description_link(procfs, *maybe_index, pid());
    if (maybe_inode.is_error())
        return maybe_inode.error();
    return maybe_inode.release_value();
}

KResult Process::procfs_get_pledge_stats(KBufferBuilder& builder) const
{
    JsonObjectSerializer obj { builder };
#define __ENUMERATE_PLEDGE_PROMISE(x) \
    if (has_promised(Pledge::x)) {    \
        if (!builder.is_empty())      \
            builder.append(' ');      \
        builder.append(#x);           \
    }
    if (has_promises()) {
        StringBuilder builder;
        ENUMERATE_PLEDGE_PROMISES
        obj.add("promises", builder.build());
    }
#undef __ENUMERATE_PLEDGE_PROMISE
    obj.finish();
    return KSuccess;
}

KResult Process::procfs_get_unveil_stats(KBufferBuilder& builder) const
{
    JsonArraySerializer array { builder };
    for (auto& unveiled_path : unveiled_paths()) {
        if (!unveiled_path.was_explicitly_unveiled())
            continue;
        Unveil unveil {};
        unveil.path = unveiled_path.path();
        StringBuilder permissions_builder;
        if (unveiled_path.permissions() & UnveilAccess::Read)
            permissions_builder.append('r');
        if (unveiled_path.permissions() & UnveilAccess::Write)
            permissions_builder.append('w');
        if (unveiled_path.permissions() & UnveilAccess::Execute)
            permissions_builder.append('x');
        if (unveiled_path.permissions() & UnveilAccess::CreateOrRemove)
            permissions_builder.append('c');
        if (unveiled_path.permissions() & UnveilAccess::Browse)
            permissions_builder.append('b');
        unveil.permissions = permissions_builder.to_string();
        auto obj = array.add_object();
        unveil.write_to_json(obj);
    }
    array.finish();
    return KSuccess;
}

KResult Process::procfs_get_perf_events(KBufferBuilder& builder) const
{
    InterruptDisabler disabler;
    if (!const_cast<Process&>(*this).perf_events()) {
        dbgln("ProcFS: No perf events for {}", pid());
        return KResult(ENOBUFS);
    }
    return const_cast<Process&>(*this).perf_events()->to_json(builder) ? KSuccess : KResult(EINVAL);
}

KResult Process::procfs_get_fds_stats(KBufferBuilder& builder) const
{
    JsonArraySerializer array { builder };
    if (fds().open_count() == 0) {
        array.finish();
        return KSuccess;
    }

    size_t count = 0;
    fds().enumerate([&](auto& file_description_metadata) {
        if (!file_description_metadata.is_valid()) {
            count++;
            return;
        }
        Fd fd_entry {};

        bool cloexec = file_description_metadata.flags() & FD_CLOEXEC;
        RefPtr<FileDescription> description = file_description_metadata.description();
        fd_entry.fd = count;
        fd_entry.absolute_path = description->absolute_path();
        fd_entry.seekable = description->file().is_seekable();
        fd_entry.class_ = description->file().class_name();
        fd_entry.offset = description->offset();
        fd_entry.cloexec = cloexec;
        fd_entry.blocking = description->is_blocking();
        fd_entry.can_read = description->can_read();
        fd_entry.can_write = description->can_write();

        auto description_object = array.add_object();
        fd_entry.write_to_stream(description_object);

        count++;
    });

    array.finish();
    return KSuccess;
}

KResult Process::procfs_get_virtual_memory_stats(KBufferBuilder& builder) const
{
    JsonArraySerializer array { builder };
    {
        ScopedSpinLock lock(address_space().get_lock());
        for (auto& region : address_space().regions()) {
            if (!region->is_user() && !Process::current()->is_superuser())
                continue;
            Region region_entry {};
            region_entry.readable = region->is_readable();
            region_entry.writable = region->is_writable();
            region_entry.executable = region->is_executable();
            region_entry.stack = region->is_stack();
            region_entry.shared = region->is_shared();
            region_entry.syscall = region->is_syscall_region();
            region_entry.purgeable = region->vmobject().is_anonymous();
            if (region->vmobject().is_anonymous()) {
                region_entry.volatile_ = static_cast<Memory::AnonymousVMObject const&>(region->vmobject()).is_volatile();
            }
            region_entry.cacheable = region->is_cacheable();
            region_entry.address = region->vaddr().get();
            region_entry.size = region->size();
            region_entry.amount_resident = region->amount_resident();
            region_entry.amount_dirty = region->amount_dirty();
            region_entry.cow_pages = region->cow_pages();
            region_entry.name = region->name();
            region_entry.vmobject = region->vmobject().class_name();

            StringBuilder pagemap_builder;
            for (size_t i = 0; i < region->page_count(); ++i) {
                auto* page = region->physical_page(i);
                if (!page)
                    pagemap_builder.append('N');
                else if (page->is_shared_zero_page() || page->is_lazy_committed_page())
                    pagemap_builder.append('Z');
                else
                    pagemap_builder.append('P');
            }
            region_entry.pagemap = pagemap_builder.to_string();
            auto region_object = array.add_object();
            region_entry.write_to_json(region_object);
        }
    }
    array.finish();
    return KSuccess;
}

KResult Process::procfs_get_current_work_directory_link(KBufferBuilder& builder) const
{
    builder.append_bytes(const_cast<Process&>(*this).current_directory().absolute_path().bytes());
    return KSuccess;
}

mode_t Process::binary_link_required_mode() const
{
    if (!executable())
        return 0;
    return m_procfs_traits->required_mode();
}

KResult Process::procfs_get_binary_link(KBufferBuilder& builder) const
{
    auto* custody = executable();
    if (!custody)
        return KResult(ENOEXEC);
    builder.append(custody->absolute_path().bytes());
    return KSuccess;
}

}
