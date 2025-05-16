/*
 * Copyright (c) 2018-2022, Andreas Kling <kling@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/BitCast.h>
#include <AK/Concepts.h>
#include <AK/Forward.h>
#include <AK/HashFunctions.h>
#include <AK/StdLibExtraDetails.h>
#include <AK/StringHash.h>

namespace AK {

template<typename T>
struct DefaultTraits {
    using PeekType = T&;
    using ConstPeekType = T const&;
    static constexpr bool is_trivial() { return false; }
    static constexpr bool is_trivially_serializable() { return false; }
    static constexpr bool equals(T const& a, T const& b) { return a == b; }

    template<typename U>
    requires(!IsSame<T, U>)
    static unsigned hash(U&&) = delete;
    template<typename U>
    requires(!IsSame<T, T>)
    static unsigned equals(T const&, U const&) = delete;
};

template<typename T>
struct Traits : public DefaultTraits<T> {
};

template<typename T>
struct Traits<T const> : public Traits<T> {
    using PeekType = typename Traits<T>::ConstPeekType;
};

template<Integral T>
struct Traits<T> : public DefaultTraits<T> {
    static constexpr bool is_trivial() { return true; }
    static constexpr bool is_trivially_serializable() { return true; }
    static unsigned hash(T value)
    {
        if constexpr (sizeof(T) < 8)
            return int_hash(value);
        else
            return u64_hash(value);
    }
};

#ifndef KERNEL
template<FloatingPoint T>
struct Traits<T> : public DefaultTraits<T> {
    static constexpr bool is_trivial() { return true; }
    static constexpr bool is_trivially_serializable() { return true; }
    static unsigned hash(T value)
    {
        if constexpr (sizeof(T) < 8)
            return int_hash(bit_cast<u32>(value));
        else
            return u64_hash(bit_cast<u64>(value));
    }
};
#endif

template<typename T>
requires(IsPointer<T> && !Detail::IsPointerOfType<char, T>) struct Traits<T> : public DefaultTraits<T> {
    static unsigned hash(RemovePointer<T> const* p) { return ptr_hash(bit_cast<FlatPtr>(p)); }
    static constexpr bool is_trivial() { return true; }
};

template<Enum T>
struct Traits<T> : public DefaultTraits<T> {
    static unsigned hash(T value) { return Traits<UnderlyingType<T>>::hash(to_underlying(value)); }
    static constexpr bool is_trivial() { return Traits<UnderlyingType<T>>::is_trivial(); }
    static constexpr bool is_trivially_serializable() { return Traits<UnderlyingType<T>>::is_trivially_serializable(); }
};

template<typename T>
requires(Detail::IsPointerOfType<char, T>) struct Traits<T> : public DefaultTraits<T> {
    static unsigned hash(T const value) { return string_hash(value, strlen(value)); }
    static constexpr bool equals(T const a, T const b) { return strcmp(a, b); }
    static constexpr bool is_trivial() { return true; }
};

template<typename P>
struct DefaultPointerCompatibleTraits {
    using PeekType = P::ElementType*;
    using ConstPeekType = P::ElementType const*;

    static constexpr bool is_trivial() { return false; }
    static constexpr bool is_trivially_serializable() { return false; }

    static unsigned hash(P const& p) { return ptr_hash(p.ptr()); }
    static unsigned hash(P::ElementType const* p) { return ptr_hash(p); }

    static constexpr bool equals(P const& a, P const& b) { return a.ptr() == b.ptr(); }
    static constexpr bool equals(P const& a, P::ElementType const* b) { return a.ptr() == b; }
};

template<typename P, typename Nonnull>
struct DefaultNullablePointerCompatibleTraits : DefaultPointerCompatibleTraits<P> {
    using DefaultPointerCompatibleTraits<P>::hash;
    using DefaultPointerCompatibleTraits<P>::equals;

    static unsigned hash(Nonnull const& p) { return ptr_hash(p.ptr()); }
    static bool equals(P const& a, Nonnull const& b) { return a.ptr() == b.ptr(); }
};

// Note: First Argument is the type tried to be used for indexing,
//       as that is how it is filled in when used in a template
template<typename U, typename T, typename TraitsForT = Traits<T>>
concept HashCompatible = requires(T t, U u) {
    TraitsForT::hash(t);
    TraitsForT::hash(u);
    TraitsForT::equals(t, u);
};

}

#if USING_AK_GLOBALLY
using AK::DefaultTraits;
using AK::Traits;
#endif
