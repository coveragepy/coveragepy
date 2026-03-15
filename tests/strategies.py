# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Hypothesis strategies for use in tests."""

from __future__ import annotations

from collections.abc import Sequence

from hypothesis import strategies as st

# Type aliases:
# S: a Hypothesis strategy, generic.
# P: primitive leaf data types.
# D: nested data.

S = st.SearchStrategy
P = None | bool | int | float | str | bytes
D = P | list["D"] | tuple["D", ...] | set["D"] | dict[str, "D"]

# Leaf types, all hashable. Some are limited to the kinds of values coverage
# deals with, to focus Hypothesis.
primitives: Sequence[S[P]] = [
    st.none(),
    st.booleans(),
    st.integers(min_value=-1000, max_value=100_000),
    st.floats(min_value=-100, max_value=100, allow_nan=False, allow_infinity=False).map(
        # Avoid -0.0.
        lambda x: 0.0 if x == 0.0 else x
    ),
    st.text(max_size=10),
    st.binary(max_size=10),
]


def homogenous_tuples_of(elements: S[D]) -> S[tuple[D, ...]]:
    """Make a strategy for homogenous tuples.

    The elements are all the same type, one of the strategies from `elements`.
    The tuples will be varying lengths.
    """
    return st.lists(elements, max_size=3).map(tuple)


def true_tuple_strategies(element_strategies: Sequence[S[D]]) -> S[S[tuple[D, ...]]]:
    """Make a strategy that produces tuple-generating strategies.

    The elements will be types drawn from `element_strategies`.
    The tuples drawn from the returned strategy will have heterogenous types,
    but every tuple will have the same types in the same positions, and all the
    tuples will be the same length.
    """
    # Note the way we use this, we won't ever get nested tuples: (int, (str, int))
    return st.lists(st.sampled_from(element_strategies), max_size=3).map(
        lambda strats: st.tuples(*strats)
    )


# A strategy for producing strategies that produce hashable values.
hashable_strategies: S[S[D]] = st.one_of(
    st.sampled_from(primitives),
    true_tuple_strategies(primitives),
)


def dicts_of(leaves: S[D]) -> S[dict[str, D]]:
    """Make a strategy for dicts with string keys and values from `leaves`."""
    return st.dictionaries(st.text(max_size=10), leaves, max_size=3)


def nested_dicts_of(leaves: S[D]) -> S[dict[str, D]]:
    """Make a strategy for recursive dicts with leaves from another strategy."""
    return dicts_of(st.recursive(leaves, dicts_of, max_leaves=5))


# A strategy that generates strategies for nested data.
nested_data_strategies: S[S[D]] = st.recursive(
    hashable_strategies,
    lambda children: st.one_of(
        children.map(lambda s: st.lists(s, max_size=5)),
        children.map(homogenous_tuples_of),
        hashable_strategies.map(lambda s: st.sets(s, max_size=5)),
        children.map(nested_dicts_of),
    ),
    max_leaves=3,
)

if __name__ == "__main__":
    for _ in range(100):
        print(repr(nested_data_strategies.example().example()))
