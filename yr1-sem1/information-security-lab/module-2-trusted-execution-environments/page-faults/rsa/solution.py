import sys
from itertools import groupby

# Usage: python3 solution.py traces/<key>.out
#
# This exercise gives you TWO traces per key:
#   <key>.out       execution trace - one page address per line (page faults
#                   in the binary's executable segment, in execution order)
#   <key>.out_mem   memory trace    - one lookup_table page address per line,
#                   in access order
#
# The executed code is the same no matter which window value is used, so the
# execution trace alone will not reveal the exponent. The memory trace tells
# you which page-sized lookup_table entry was touched.
#
# Your script must be generic: it gets ONE trace pair and must recover the key
# from it alone. ASLR was enabled, so absolute addresses differ between traces,
# but offsets within the binary do not. Do NOT recompile the binary.
#
# Keep recover_key() with exactly this name and signature - that is what the
# grading script imports. 


def recover_key(exec_pages, mem_pages):
    """Recover the exponent from one trace pair.

    exec_pages: the execution trace as a list of ints, one page address per
                entry, in execution order.
    mem_pages:  the memory trace as a list of ints, one page address per
                entry, in access order.
    returns:    the recovered key, as an int.
    """
    key = 1

    page_set = sorted(set(exec_pages))

    base = page_set[0] - 0x1000
    lookup_table = base + 0xa000

    groups = [(p, len(list(g))) for p, g in groupby(mem_pages)]
    grouped_pages = [p for p, _ in groupby(mem_pages)]

    i = 1
    while grouped_pages[i] != grouped_pages[0]:
        i += 1

    num = i
    i = 4 * num - 2

    end = len(groups) - num
    unit = min(count for _, count in groups[i:end])

    key = 0
    while i < end:
        page, count = groups[i]
        idx = (page - lookup_table) >> 12
        reps = max(1, round(count / unit))
        for _ in range(reps):
            key = (key << 4) | idx
        i += 1

    return key


def main():
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} <trace.out>   (expects <trace.out>_mem too)")
    with open(sys.argv[1]) as fh:
        exec_pages = [int(line, 16) for line in fh if line.strip()]
    with open(sys.argv[1] + "_mem") as fh:
        mem_pages = [int(line, 16) for line in fh if line.strip()]
    print(hex(recover_key(exec_pages, mem_pages)))


if __name__ == "__main__":
    main()
