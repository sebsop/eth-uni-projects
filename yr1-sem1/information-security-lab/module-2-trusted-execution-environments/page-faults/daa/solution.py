import sys
from itertools import groupby

# Usage: python3 solution.py traces/<key>.out
#
# The trace holds one page address per line, in execution order - each line is
# a page fault, i.e. the moment execution entered a new page of the binary.
#
# Your script must be generic: it gets ONE trace and must recover the key from
# it alone. ASLR was enabled, so absolute addresses differ between traces, but
# offsets within the binary do not. Do NOT recompile the binary - that can
# change the layout the traces were recorded against.
#
# Keep recover_key() with exactly this name and signature - that is what the
# grading script imports.

def recover_key(pages):
    """Recover the private scalar from one execution trace.

    pages: the trace as a list of ints, one page address per entry, in
           execution order.
    returns: the recovered key, as an int.
    """
    key = 1

    page_set = sorted(set(pages))

    base = page_set[0] - 0x1000
    double_page = base + 0xa000
    addition_page = base + 0xc000
    loop_page = base + 0xe000

    filtered_pages = [p for p in pages if p in (double_page, addition_page, loop_page)]
    grouped_pages = [p for p, _ in groupby(filtered_pages)]
    
    for page in grouped_pages:
        if page == double_page:
            key <<= 1
        elif page == addition_page:
            key |= 1

    return key

def main():
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} <trace.out>")
    with open(sys.argv[1]) as fh:
        pages = [int(line, 16) for line in fh if line.strip()]
    print(hex(recover_key(pages)))

if __name__ == "__main__":
    main()