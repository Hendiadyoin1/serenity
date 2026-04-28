/*
 * Copyright (c) 2021, Ali Mohammad Pur <mpfard@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Array.h>
#include <AK/Assertions.h>
#include <AK/BitCast.h>
#include <AK/StdLibExtraDetails.h>
#include <AK/StdLibExtras.h>
#include <AK/StdShim.h>
#include <AK/TypeList.h>

namespace AK::Detail {

template<typename T, typename IndexType, typename... Ts>
consteval IndexType index_of()
{
    bool matches[] = { IsSame<T, Ts>... };
    for (size_t i = 0; i < sizeof...(Ts); ++i) {
        if (matches[i])
            return static_cast<IndexType>(i);
    }
    return static_cast<IndexType>(sizeof...(Ts));
}

template<typename IndexType, IndexType CurrentIndex, typename... Ts>
union VariantStorage;

template<typename IndexType, IndexType CurrentIndex, typename F, typename... Ts>
union VariantStorage<IndexType, CurrentIndex, F, Ts...> {
    using ElementType = F;
    using __STORAGE = F[1];

    constexpr VariantStorage() = default;
    constexpr VariantStorage()
    requires(!IsTriviallyConstructible<F> || (!IsTriviallyConstructible<Ts> || ...))
    {
    }

    constexpr VariantStorage(VariantStorage const&) = default;
    constexpr VariantStorage(VariantStorage const&)
    requires(!IsTriviallyCopyConstructible<F> || (!IsTriviallyCopyConstructible<Ts> || ...))
    {
    }

    constexpr VariantStorage(VariantStorage&&) = default;
    constexpr VariantStorage(VariantStorage&&)
    requires(!IsTriviallyMoveConstructible<F> || (!IsTriviallyMoveConstructible<Ts> || ...))
    {
    }
    constexpr VariantStorage& operator=(VariantStorage const&) = default;
    constexpr VariantStorage& operator=(VariantStorage const&)
    requires(!IsTriviallyCopyAssignable<F> || (!IsTriviallyCopyAssignable<Ts> || ...))
    {
    }

    constexpr VariantStorage& operator=(VariantStorage&&) = default;
    constexpr VariantStorage& operator=(VariantStorage&&)
    requires(!IsTriviallyMoveAssignable<F> || (!IsTriviallyMoveAssignable<Ts> || ...))
    {
    }

    constexpr ~VariantStorage() = default;
    constexpr ~VariantStorage()
    requires(!IsTriviallyDestructible<F> || (!IsTriviallyDestructible<Ts> || ...))
    {
    }

    template<IndexType I, typename U>
    constexpr void construct(U&& val)
    {
        if constexpr (I == CurrentIndex) {
            // FIXME: Begin the lifetime of the storage
            new (&value[0]) F(forward<U>(val));
        } else {
            if constexpr (sizeof...(Ts) == 0)
                VERIFY_NOT_REACHED();
            else
                rest.template construct<I>(forward<U>(val));
        }
    }

    constexpr void delete_(IndexType id)
    {
        if (id == CurrentIndex) {
            value[0].~F();
            // FIXME: Do we need to end the lifetime of the storage array here?
        } else {
            if constexpr (sizeof...(Ts) == 0)
                VERIFY_NOT_REACHED();
            else
                rest.delete_(id);
        }
    }

    template<IndexType I, typename Self>
    constexpr auto&& get(this Self&& self)
    {
        if constexpr (I == CurrentIndex) {
            return forward<Self>(self).value[0];
        } else {
            return forward<Self>(self).rest.template get<I>();
        }
    }

    constexpr void move_to(IndexType id, VariantStorage& to)
    {
        if (id == CurrentIndex) {
            // FIXME: Begin the lifetime of the storage
            new (&to.value[0]) F(move(value[0]));
        } else {
            rest.move_to(id, to.rest);
        }
    }

    constexpr void copy_to(IndexType id, VariantStorage& to) const
    {
        if (id == CurrentIndex) {
            // FIXME: Begin the lifetime of the storage
            new (&to.value[0]) F(value[0]);
        } else {
            rest.copy_to(id, to.rest);
        }
    }

    __STORAGE value;
    VariantStorage<IndexType, CurrentIndex + 1, Ts...> rest;
};

template<typename IndexType, IndexType CurrentIndex, typename F>
union VariantStorage<IndexType, CurrentIndex, F> {
    using ElementType = F;
    using __STORAGE = F[1];

    constexpr VariantStorage() = default;
    constexpr VariantStorage()
    requires(!IsTriviallyConstructible<F>)
    {
    }
    constexpr ~VariantStorage() = default;
    constexpr ~VariantStorage()
    requires(!IsTriviallyDestructible<F>)
    {
    }

    template<IndexType I, typename U>
    constexpr void construct(U&& val)
    {
        if constexpr (I == CurrentIndex) {
            // FIXME: Begin the lifetime of the storage
            new (&value[0]) F(forward<U>(val));
        } else {
            VERIFY_NOT_REACHED();
        }
    }

    constexpr void delete_(IndexType id)
    {
        if (id == CurrentIndex) {
            value[0].~F();
            // FIXME: Do we need to end the lifetime of the storage array here?
        } else {
            VERIFY_NOT_REACHED();
        }
    }

    template<IndexType I, typename Self>
    constexpr auto&& get(this Self&& self)
    {
        if constexpr (I == CurrentIndex) {
            return forward<Self>(self).value[0];
        } else {
            VERIFY_NOT_REACHED();
        }
    }

    constexpr void move_to(IndexType id, VariantStorage& to)
    {
        if (id == CurrentIndex) {
            // FIXME: Begin the lifetime of the storage
            new (&to.value[0]) F(move(value[0]));
        } else {
            VERIFY_NOT_REACHED();
        }
    }

    constexpr void copy_to(IndexType id, VariantStorage& to) const
    {
        if (id == CurrentIndex) {
            // FIXME: Begin the lifetime of the storage
            new (&to.value[0]) F(value[0]);
        } else {
            VERIFY_NOT_REACHED();
        }
    }

    __STORAGE value;
};

template<typename IndexType, typename... Ts>
struct VisitImpl {
    template<typename RT, typename T, size_t I, typename Fn>
    static constexpr bool has_explicitly_named_overload()
    {
        // If we're not allowed to make a member function pointer and call it directly (without explicitly resolving it),
        // we have a templated function on our hands (or a function overload set).
        // in such cases, we don't have an explicitly named overload, and we would have to select it.
        return requires { (declval<Fn>().*(&Fn::operator()))(declval<T>()); };
    }

    template<typename ReturnType, typename T, typename Visitor, auto... Is>
    static constexpr bool should_invoke_const_overload(IndexSequence<Is...>)
    {
        // Scan over all the different visitor functions, if none of them are suitable for calling with `T const&`, avoid calling that first.
        return ((has_explicitly_named_overload<ReturnType, T, Is, typename Visitor::Types::template Type<Is>>()) || ...);
    }

    template<typename Self, typename Visitor, IndexType CurrentIndex = 0>
    ALWAYS_INLINE static constexpr decltype(auto) visit(Self& self, Visitor&& visitor)
    requires(CurrentIndex < sizeof...(Ts))
    {
        using T = typename TypeList<Ts...>::template Type<CurrentIndex>;

        if (self.index() == CurrentIndex) {
            // Check if Visitor::operator() is an explicitly typed function (as opposed to a templated function)
            // if so, try to call that with `T const&` first before copying the Variant's const-ness.
            // This emulates normal C++ call semantics where templated functions are considered last, after all non-templated overloads
            // are checked and found to be unusable.
            using ReturnType = decltype(visitor(declval<T&>()));
            if constexpr (should_invoke_const_overload<ReturnType, T, Visitor>(MakeIndexSequence<Visitor::Types::size>()))
                return visitor(AddConstToReferencedType<Self&>(self).template get<T>());

            return visitor(self.template get<T>());
        }

        if constexpr ((CurrentIndex + 1) < sizeof...(Ts))
            return visit<Self, Visitor, CurrentIndex + 1>(self, forward<Visitor>(visitor));
        else
            VERIFY_NOT_REACHED();
    }
};

struct VariantNoClearTag {
    explicit VariantNoClearTag() = default;
};
struct VariantConstructTag {
    explicit VariantConstructTag() = default;
};

// Type list deduplication
// Since this is a big template mess, each template is commented with how and why it works.
struct ParameterPackTag {
};

// Pack<Ts...> is just a way to pass around the type parameter pack Ts
template<typename... Ts>
struct ParameterPack : ParameterPackTag {
};

// Blank<T> is a unique replacement for T, if T is a duplicate type.
template<typename T>
struct Blank {
    void operator()() const;
};

template<typename A, typename P>
inline constexpr bool IsTypeInPack = false;

// IsTypeInPack<T, Pack<Ts...>> will just return whether 'T' exists in 'Ts'.
template<typename T, typename... Ts>
inline constexpr bool IsTypeInPack<T, ParameterPack<Ts...>> = (IsSame<T, Ts> || ...);

// Replaces T with Blank<T> if it exists in Qs.
template<typename T, typename... Qs>
using BlankIfDuplicate = Conditional<(IsTypeInPack<T, Qs> || ...), Blank<T>, T>;

template<size_t I, typename...>
struct InheritFromUniqueEntries;

// InheritFromUniqueEntries will inherit from both Qs and Ts, but only scan entries going *forwards*
// that is to say, if it's scanning from index I in Qs, it won't scan for duplicates for entries before I
// as that has already been checked before.
// This makes sure that the search is linear in time (like the 'merge' step of merge sort).
template<size_t I, typename... Ts, size_t... Js, typename... Qs>
struct InheritFromUniqueEntries<I, ParameterPack<Ts...>, IndexSequence<Js...>, Qs...>
    : public BlankIfDuplicate<Ts, Conditional<Js <= I, ParameterPack<>, Qs>...>... {

    using BlankIfDuplicate<Ts, Conditional<Js <= I, ParameterPack<>, Qs>...>::BlankIfDuplicate...;
    using BlankIfDuplicate<Ts, Conditional<Js <= I, ParameterPack<>, Qs>...>::operator()...;
};

template<typename...>
struct InheritFromPacks;

// InheritFromPacks will attempt to 'merge' the pack 'Ps' with *itself*, but skip the duplicate entries
// (via InheritFromUniqueEntries).
template<size_t... Is, typename... Ps>
struct InheritFromPacks<IndexSequence<Is...>, Ps...>
    : public InheritFromUniqueEntries<Is, Ps, IndexSequence<Is...>, Ps...>... {

    using InheritFromUniqueEntries<Is, Ps, IndexSequence<Is...>, Ps...>::InheritFromUniqueEntries...;
    using InheritFromUniqueEntries<Is, Ps, IndexSequence<Is...>, Ps...>::operator()...;
};

// Just a nice wrapper around InheritFromPacks, which will wrap any parameter packs in ParameterPack (unless it already is one).
template<typename... Ps>
using MergeAndDeduplicatePacks = InheritFromPacks<MakeIndexSequence<sizeof...(Ps)>, Conditional<IsBaseOf<ParameterPackTag, Ps>, Ps, ParameterPack<Ps>>...>;

// NOTE: This always allows allows narrowing,
//       The stl version does not allow narrowing conversions
//       main points where we need it are instantiations with literal 0s,
//       which we could possibly check for with a some more template magic and is_constant_p.
template<typename T>
struct Overload {
    // This Overload for <T> can be chosen,
    // if the passed type <U>, in its fully qualified form*, can construct a <T>
    // The compiler will then choose the "ideal" overload, if it is unambiguous
    // *: This is the reason for the forwarding reference in the arguments
    template<typename U, typename = T>
    requires(IsConstructible<T, U>)
    auto operator()(T, U&&) const -> __IdentityType<T>;
};

template<typename... Bases>
struct AllOverloads : MergeAndDeduplicatePacks<ParameterPack<Bases>...> {
    void operator()() const;
    using MergeAndDeduplicatePacks<ParameterPack<Bases>...>::operator();
};

template<typename IndexSequence>
struct MakeOverloadsImpl;

template<size_t... Indices>
struct MakeOverloadsImpl<IndexSequence<Indices...>> {
    template<typename... Types>
    using Apply = AllOverloads<Overload<Types>...>;
};

template<typename... Types>
using MakeOverloads = typename MakeOverloadsImpl<MakeIndexSequence<sizeof...(Types)>>::template Apply<Types...>;
}

namespace AK {

template<typename T>
concept NotLvalueReference = !IsLvalueReference<T>;

template<NotLvalueReference...>
struct Variant;

template<NotLvalueReference... Ts>
struct Variant {
    // FIXME: Can we get this to return the index as well?
    using OverloadFinder = Detail::MakeOverloads<Ts...>;
    template<typename T>
    using BestMatch = InvokeResult<OverloadFinder, T, T>::Type;

public:
    using IndexType = Conditional<(sizeof...(Ts) < 255), u8, size_t>; // Note: size+1 reserved for internal value checks
private:
    static constexpr IndexType invalid_index = sizeof...(Ts);

    template<typename T>
    static constexpr IndexType index_of() { return Detail::index_of<T, IndexType, Ts...>(); }

public:
    template<typename T>
    static constexpr bool can_contain() { return IsOneOf<T, Ts...>; }

    template<typename... NewTs>
    Variant(Variant<NewTs...>&& old)
    requires((can_contain<NewTs>() && ...))
        : Variant(move(old).template downcast<Ts...>())
    {
    }

    template<typename... NewTs>
    Variant(Variant<NewTs...> const& old)
    requires((can_contain<NewTs>() && ...))
        : Variant(old.template downcast<Ts...>())
    {
    }

    // FIXME: Not sure why we need the `!IsSame` constraint here to avoid recursion,
    //        The variant should not be able to contain it self, so a constructibility check should
    //        be enough?
    template<typename T>
    requires(!IsSame<RemoveCVReference<T>, Variant>
        && (IsConstructible<Ts, T> || ...))
    Variant(T&& t)
    {
        using BestOverload = BestMatch<T>;
        // FIXME: Can we get the index directly from the resolution?
        constexpr IndexType BestOverloadIndex = index_of<BestOverload>();

        m_data.template construct<BestOverloadIndex>(forward<T>(t));
        m_index = BestOverloadIndex;
    }

    template<NotLvalueReference... NewTs>
    friend struct Variant;

    Variant()
    requires(!can_contain<Empty>())
    = delete;
    Variant()
    requires(can_contain<Empty>())
        : Variant(Empty())
    {
    }

    Variant(Variant const&)
    requires(!(IsCopyConstructible<Ts> && ...))
    = delete;
    Variant(Variant const&) = default;

    Variant(Variant&&)
    requires(!(IsMoveConstructible<Ts> && ...))
    = delete;
    Variant(Variant&&) = default;

    ~Variant()
    requires(!(IsDestructible<Ts> && ...))
    = delete;
    ~Variant() = default;

    Variant& operator=(Variant const&)
    requires(!(IsCopyConstructible<Ts> && ...) || !(IsDestructible<Ts> && ...))
    = delete;
    Variant& operator=(Variant const&) = default;

    Variant& operator=(Variant&&)
    requires(!(IsMoveConstructible<Ts> && ...) || !(IsDestructible<Ts> && ...))
    = delete;
    Variant& operator=(Variant&&) = default;

    ALWAYS_INLINE Variant(Variant const& old)
    requires(!(IsTriviallyCopyConstructible<Ts> && ...))
        : m_data {}
        , m_index(old.m_index)
    {
        old.m_data.copy_to(old.m_index, m_data);
    }

    // Note: A moved-from variant emulates the state of the object it contains
    //       so if a variant containing an int is moved from, it will still contain that int
    //       and if a variant with a nontrivial move ctor is moved from, it may or may not be valid
    //       but it will still contain the "moved-from" state of the object it previously contained.
    ALWAYS_INLINE Variant(Variant&& old)
    requires(!(IsTriviallyMoveConstructible<Ts> && ...))
        : m_index(old.m_index)
    {
        old.m_data.move_to(old.m_index, m_data);
    }

    ALWAYS_INLINE ~Variant()
    requires(!(IsTriviallyDestructible<Ts> && ...))
    {
        m_data.delete_(m_index);
    }

    ALWAYS_INLINE Variant& operator=(Variant const& other)
    requires(!(IsTriviallyCopyConstructible<Ts> && ...) || !(IsTriviallyDestructible<Ts> && ...))
    {
        if (this != &other) {
            if constexpr (!(IsTriviallyDestructible<Ts> && ...)) {
                m_data.delete_(m_index);
            }
            m_index = other.m_index;
            other.m_data.copy_to(other.m_index, m_data);
        }
        return *this;
    }

    ALWAYS_INLINE Variant& operator=(Variant&& other)
    requires(!(IsTriviallyMoveConstructible<Ts> && ...) || !(IsTriviallyDestructible<Ts> && ...))
    {
        if (this != &other) {
            if constexpr (!(IsTriviallyDestructible<Ts> && ...)) {
                m_data.delete_(m_index);
            }
            m_index = other.m_index;
            other.m_data.move_to(other.m_index, m_data);
        }
        return *this;
    }

    template<typename T, typename StrippedT = RemoveCVReference<T>>
    void set(T&& t)
    requires(can_contain<StrippedT>() && requires { StrippedT(forward<T>(t)); })
    {
        constexpr auto new_index = index_of<StrippedT>();
        m_data.delete_(m_index);
        m_data.template construct<new_index>(forward<T>(t));
        m_index = new_index;
    }

    template<typename T, typename StrippedT = RemoveCVReference<T>>
    void set(T&& t, Detail::VariantNoClearTag)
    requires(can_contain<StrippedT>() && requires { StrippedT(forward<T>(t)); })
    {
        constexpr auto new_index = index_of<StrippedT>();
        m_data.template construct<new_index>(forward<T>(t));
        m_index = new_index;
    }

    template<typename T>
    T* get_pointer()
    requires(can_contain<T>())
    {
        constexpr IndexType I = index_of<T>();
        if (I == m_index)
            return &m_data.template get<I>();
        return nullptr;
    }

    template<typename T>
    T& get()
    requires(can_contain<T>())
    {
        VERIFY(has<T>());
        constexpr IndexType I = index_of<T>();
        return m_data.template get<I>();
    }

    template<typename T>
    T const* get_pointer() const
    requires(can_contain<T>())
    {
        constexpr IndexType I = index_of<T>();
        if (I == m_index)
            return &m_data.template get<I>();
        return nullptr;
    }

    template<typename T>
    T const& get() const
    requires(can_contain<T>())
    {
        VERIFY(has<T>());
        constexpr IndexType I = index_of<T>();
        return m_data.template get<I>();
    }

    template<typename T>
    [[nodiscard]] bool has() const
    requires(can_contain<T>())
    {
        return index_of<T>() == m_index;
    }

    bool operator==(Variant const& other) const
    {
        return this->visit([&]<typename T>(T const& self) {
            if (auto const* p = other.get_pointer<T>())
                return static_cast<T const&>(self) == static_cast<T const&>(*p);
            return false;
        });
    }

    template<typename... Fs>
    ALWAYS_INLINE decltype(auto) visit(Fs&&... functions)
    {
        Visitor<Fs...> visitor { forward<Fs>(functions)... };
        return VisitHelper::visit(*this, move(visitor));
    }

    template<typename... Fs>
    ALWAYS_INLINE decltype(auto) visit(Fs&&... functions) const
    {
        Visitor<Fs...> visitor { forward<Fs>(functions)... };
        return VisitHelper::visit(*this, move(visitor));
    }

    template<typename... NewTs>
    decltype(auto) downcast() &&
    {
        if constexpr (sizeof...(NewTs) == 1 && (IsSpecializationOf<NewTs, Variant> && ...)) {
            return move(*this).template downcast_variant<NewTs...>();
        } else {
            Variant<NewTs...> instance { Variant<NewTs...>::invalid_index, Detail::VariantConstructTag {} };
            visit([&](auto& value) {
                if constexpr (Variant<NewTs...>::template can_contain<RemoveCVReference<decltype(value)>>())
                    instance.set(move(value), Detail::VariantNoClearTag {});
            });
            VERIFY(instance.m_index != instance.invalid_index);
            return instance;
        }
    }

    template<typename... NewTs>
    decltype(auto) downcast() const&
    {
        if constexpr (sizeof...(NewTs) == 1 && (IsSpecializationOf<NewTs, Variant> && ...)) {
            return (*this).downcast_variant(TypeWrapper<NewTs...> {});
        } else {
            Variant<NewTs...> instance { Variant<NewTs...>::invalid_index, Detail::VariantConstructTag {} };
            visit([&](auto const& value) {
                if constexpr (Variant<NewTs...>::template can_contain<RemoveCVReference<decltype(value)>>())
                    instance.set(value, Detail::VariantNoClearTag {});
            });
            VERIFY(instance.m_index != instance.invalid_index);
            return instance;
        }
    }

    auto index() const { return m_index; }

private:
    template<typename... NewTs>
    Variant<NewTs...> downcast_variant(TypeWrapper<Variant<NewTs...>>) &&
    {
        return move(*this).template downcast<NewTs...>();
    }

    template<typename... NewTs>
    Variant<NewTs...> downcast_variant(TypeWrapper<Variant<NewTs...>>) const&
    {
        return (*this).template downcast<NewTs...>();
    }

    static constexpr auto data_size = Detail::integer_sequence_generate_array<size_t>(0, IntegerSequence<size_t, sizeof(Ts)...>()).max();
    static constexpr auto data_alignment = Detail::integer_sequence_generate_array<size_t>(0, IntegerSequence<size_t, alignof(Ts)...>()).max();
    using VisitHelper = Detail::VisitImpl<IndexType, Ts...>;

    explicit Variant(IndexType index, Detail::VariantConstructTag)
        : m_index(index)
    {
    }

    ALWAYS_INLINE void clear_without_destruction()
    {
        __builtin_memset(m_data, 0, data_size);
        m_index = invalid_index;
    }

    template<typename... Fs>
    struct Visitor : Fs... {
        using Types = TypeList<Fs...>;

        Visitor(Fs&&... args)
            : Fs(forward<Fs>(args))...
        {
        }

        using Fs::operator()...;
    };

    Detail::VariantStorage<IndexType, 0, Ts...> m_data;
    IndexType m_index;
};

template<typename... Ts>
struct TypeList<Variant<Ts...>> : TypeList<Ts...> {};

}

#if USING_AK_GLOBALLY
using AK::Variant;
#endif
