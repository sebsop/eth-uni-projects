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
    negative_part = 0

    page_set = sorted(set(pages))

    base = page_set[0] - 0x1000
    double_page = base + 0x7000
    addition_page = base + 0x8000
    neg_addition_page = addition_page + 0x2000
    loop_page = base + 0x9000
    loop_page_tail = loop_page + 0x2000

    filtered_pages = [p for p in pages if p in (double_page, addition_page, neg_addition_page, loop_page, loop_page_tail)]
    grouped_pages = [p for p, _ in groupby(filtered_pages)]
    
    for page in grouped_pages:
        if page == double_page:
            key <<= 1
            is_negative = False
        elif page == addition_page:
            if is_negative:
                key -= 1
            else:
                key |= 1
        elif page == neg_addition_page:
            is_negative = True
            
    return key

def main():
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} <trace.out>")
    with open(sys.argv[1]) as fh:
        pages = [int(line, 16) for line in fh if line.strip()]
    print(hex(recover_key(pages)))

if __name__ == "__main__":
    main()