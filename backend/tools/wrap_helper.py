"""Shared helpers for tool wrappers (small utilities)."""


def dedup_list(items):
    return list(dict.fromkeys(items))


def dup(items):
    return dedup_list(items)
