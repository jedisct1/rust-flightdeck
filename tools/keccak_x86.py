#!/usr/bin/env python3
"""Write the assembly files of src/simd: twelve rounds of Keccak-p[1600] on several states, for x86-64.

    uv run tools/keccak_x86.py

Why assembly? The compiler has the same instructions.
But on the CPUs measured, speed depends on things it decides for other reasons:

- The order of the instructions.
  Rotations only run on half of the vector units, so the rest has to be laid out around them.
- Which input `vpternlogq` overwrites.
  It should be the one computed last, or AMD CPUs wait for it.
- Where the code is, and how much of it there is.
  In 128-bit and 256-bit registers the rounds are so fast that the CPU struggles to fetch the instructions.
  Twelve rounds written out leave no room in the cache of decoded instructions for another routine taking turns with them.
  So the rounds for up to eight states run in a loop, one file serves one, two and four states, and every file starts on a 64-byte boundary.

With AVX-512 a state fits in registers, 25 of the 32, for eight, four or two states at once.
The rounds are a list of operations on named values, and registers are picked afterwards.
Eight states can also take a ninth one along on general registers.
The two kinds of instructions are mixed in one file.

With AVX2 there are 16 registers, so four states live in memory, and the rounds are written directly.
"""

import pathlib

# For each row of the output: where its five lanes come from, and how far they are rotated.
ROWS = [
    [(0, 0), (6, 44), (12, 43), (18, 21), (24, 14)],
    [(3, 28), (9, 20), (10, 3), (16, 45), (22, 61)],
    [(1, 1), (7, 6), (13, 25), (19, 8), (20, 18)],
    [(4, 27), (5, 36), (11, 10), (17, 15), (23, 56)],
    [(2, 62), (8, 55), (14, 39), (15, 41), (21, 2)],
]

# The order of the operations of a round for eight states, as positions in `plain_round()`.
# A search found it on a Ryzen 7 7700: it moved one operation at a time and kept what ran faster.
# It's worth about 2% there. `range(91)` is the plain order, and gives the same result.
ORDER_X8 = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 30, 31, 28, 29, 32, 33, 34, 35, 17, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
    48, 51, 49, 50, 52, 53, 54, 55, 56, 57, 58, 59, 60, 65, 61, 63, 64, 66, 67, 68, 69, 70, 71,
    72, 62, 73, 74, 79, 75, 76, 77, 78, 80, 81, 82, 84, 85, 86, 87, 83, 88, 89, 90,
]

# From the same search: the input that a few `vpternlogq` overwrite, 0, 1 or 2.
# The others overwrite the input computed last.
OVERWRITE_X8 = {28: 2, 29: 1, 55: 2, 62: 0, 63: 1, 67: 1, 75: 1, 81: 0}

XOR3 = lambda a, b, c: a ^ b ^ c
CHI = lambda a, b, c: a ^ ((1 - b) & c)

# An operation is (kind, result, inputs, argument).
# `a<r>_<i>` is lane `i` before round `r`, and `c<r>_<x>` the parity of column `x`.


def chi_row(r, y):
    """Chi on a row, and iota on the first lane."""
    ops = []
    for x in range(5):
        inputs = [f"b{r}_{5 * y + (x + i) % 5}" for i in range(3)]
        if y == 0 and x == 0:
            ops.append(("tern", f"e{r}", inputs, CHI))
            ops.append(("iota", f"a{r + 1}_0", [f"e{r}"], r))
        else:
            ops.append(("tern", f"a{r + 1}_{5 * y + x}", inputs, CHI))
    return ops


def rho(r, y, x):
    """The rotation that makes a lane of the output.

    The first lane is the only one that isn't rotated.
    """
    source, bits = ROWS[y][x]
    return ("rol" if bits else "same", f"b{r}_{5 * y + x}", [f"x{r}_{source}"], bits)


def parities(r):
    ops = []
    for x in range(5):
        ops.append(("tern", f"p{r}_{x}", [f"a{r}_{x}", f"a{r}_{x + 5}", f"a{r}_{x + 10}"], XOR3))
    for x in range(5):
        ops.append(("tern", f"c{r}_{x}", [f"p{r}_{x}", f"a{r}_{x + 15}", f"a{r}_{x + 20}"], XOR3))
    return ops


def plain_round(r):
    """Round `r` with the fewest operations: theta is one three-way XOR per lane, a column at a time."""
    ops = []
    for x in range(5):
        ops.append(("rol", f"t{r}_{x}", [f"c{r}_{(x + 1) % 5}"], 1))
        for y in range(5):
            lane = 5 * y + x
            ops.append(("tern", f"x{r}_{lane}", [f"a{r}_{lane}", f"c{r}_{(x + 4) % 5}", f"t{r}_{x}"], XOR3))
    ops += [rho(r, y, x) for y in range(5) for x in range(5)]
    for y in range(5):
        ops += chi_row(r, y)
    return ops + parities(r + 1)


def round_by_rows(r):
    """Round `r` with the fewest instructions: theta is two-input XORs, so nothing has to be copied.

    That's for where the number of instructions is the limit:
    narrower registers, and eight states next to a ninth one.
    The lanes are made one row at a time, and chi on a row comes after the rotations of the next one.
    """
    ops = []
    for x in (0, 4, 3, 1, 2):
        ops.append(("rol", f"t{r}_{x}", [f"c{r}_{(x + 1) % 5}"], 1))
        ops.append(("xor", f"d{r}_{x}", [f"c{r}_{(x + 4) % 5}", f"t{r}_{x}"], None))
    for y in range(5):
        for x in range(5):
            source = ROWS[y][x][0]
            ops.append(("xor", f"x{r}_{source}", [f"a{r}_{source}", f"d{r}_{source % 5}"], None))
            ops.append(rho(r, y, x))
        if y > 0:
            ops += chi_row(r, y - 1)
    ops += chi_row(r, 4)
    return ops + parities(r + 1)


def program(round_fn, lanes, order=None, overwrite={}, rounds=12):
    """`rounds` rounds, without what the wanted `lanes` of the result don't need.

    Each operation gets a fifth field: the input its `vpternlogq` overwrites, if `overwrite` says so.
    A mark follows each round.
    """
    ops = [op + (None,) for op in parities(0)]
    for r in range(rounds):
        plain = round_fn(r)
        ops += [plain[i] + (overwrite.get(i),) for i in order or range(len(plain))]
        ops.append(("mark", None, [], None, None))

    # Go backwards and keep what leads to a wanted lane.
    wanted = {f"a{rounds}_{lane}" for lane in lanes}
    kept = []
    for op in reversed(ops):
        if op[1] in wanted or op[0] == "mark":
            wanted.update(op[2])
            kept.append(op)
    return kept[::-1]


def ternlog_immediate(function, operands):
    """What makes `vpternlogq` compute `function(a, b, c)` when its operands hold `operands`, like "cab"."""
    immediate = 0
    for k in range(8):
        bits = {operands[0]: k >> 2 & 1, operands[1]: k >> 1 & 1, operands[2]: k & 1}
        immediate |= function(bits["a"], bits["b"], bits["c"]) << k
    return immediate


def assemble(ops, lanes, constants="rax", first_round=0):
    """Pick registers and return the instructions, for eight states.

    The lanes come in zmm0 to zmm24, and the wanted `lanes` of the result leave in the same registers.
    The round constants are read at `constants`, starting with the one of round `first_round`.
    A mark comes out as a line of its own, "mark".
    """
    uses = {}
    for _, _, inputs, _, _ in ops:
        for value in inputs:
            uses[value] = uses.get(value, 0) + 1
    rounds = sum(op[0] == "mark" for op in ops)
    leaving = {f"a{rounds}_{lane}": lane for lane in lanes}
    for value in leaving:
        uses[value] = uses.get(value, 0) + 1

    register = {f"a0_{lane}": lane for lane in range(25)}
    free = list(range(25, 32))
    made = {value: -1 for value in register}
    same = {}
    lines = []

    for index, (kind, result, inputs, argument, overwrite) in enumerate(ops):
        if kind == "mark":
            lines.append("mark")
            continue
        inputs = [same.get(value, value) for value in inputs]
        made[result] = index
        if kind == "same":
            same[result] = inputs[0]
            uses[inputs[0]] += uses[result] - 1
            continue

        dying = [value for value in inputs if uses[value] == 1]
        if kind == "tern":
            by_age = sorted(inputs, key=lambda value: made[value])
            first = by_age[2] if overwrite is None else inputs[overwrite]
            if first not in dying and not free:
                # No register to copy it into: overwrite an input that isn't needed after this.
                first = dying[0]
            if first in dying:
                dying = [first]
                out = register[first]
            else:
                dying = []
                out = free.pop(0)
                lines.append(f"vmovdqa64 zmm{out}, zmm{register[first]}")
            others = [value for value in by_age if value != first]
            operands = "".join("abc"[inputs.index(value)] for value in [first] + others)
            immediate = ternlog_immediate(argument, operands)
            lines.append(f"vpternlogq zmm{out}, zmm{register[others[0]]}, zmm{register[others[1]]}, 0x{immediate:02x}")
        else:
            out = register[dying[0]] if dying else free.pop(0)
            if kind == "rol":
                lines.append(f"vprolq zmm{out}, zmm{register[inputs[0]]}, {argument}")
            elif kind == "xor":
                lines.append(f"vpxorq zmm{out}, zmm{register[inputs[0]]}, zmm{register[inputs[1]]}")
            else:
                lines.append(f"vpxorq zmm{out}, zmm{register[inputs[0]]}, qword ptr [{constants} + {8 * (first_round + argument)}]{{{{1to8}}}}")

        reused = dying[0] if dying else None
        for value in inputs:
            uses[value] -= 1
            if value == reused:
                del register[value]
            elif uses[value] == 0:
                free.append(register.pop(value))
        register[result] = out

    # Put the lanes back where they came from.
    moves = {register[same.get(value, value)]: target for value, target in leaving.items()}
    moves = {source: target for source, target in moves.items() if source != target}
    while moves:
        ready = [source for source, target in moves.items() if target not in moves]
        if ready:
            lines.append(f"vmovdqa64 zmm{moves.pop(ready[0])}, zmm{ready[0]}")
            continue
        # Only cycles are left: break one with a register nobody needs.
        busy = set(moves) | set(moves.values()) | set(leaving.values())
        spare = next(r for r in range(32) if r not in busy)
        source = next(iter(moves))
        lines.append(f"vmovdqa64 zmm{spare}, zmm{source}")
        moves[spare] = moves.pop(source)
    return lines


# The registers of the ninth state: the row being made, what theta adds to each column, and scratch.
ROW = ["rcx", "rdx", "r8", "r9", "r10"]
THETA = ["r11", "r12", "r13", "r14", "r15"]
SCRATCH = "rbx"


def scalar_round(r, here, there, rows):
    """One round on one state, on general registers: the lanes are read at `here` and written to `there`.

    `ROW` holds the parities of the columns first, then each row in turn.
    Only the given rows of the result are computed.
    """
    lines = []
    for x in range(5):
        lines.append(f"mov {ROW[x]}, [{here} + {8 * x}]")
        lines += [f"xor {ROW[x]}, [{here} + {8 * (5 * y + x)}]" for y in range(1, 5)]
    for x in range(5):
        lines.append(f"rorx {THETA[x]}, {ROW[(x + 1) % 5]}, 63")
        lines.append(f"xor {THETA[x]}, {ROW[(x + 4) % 5]}")
    for y in rows:
        for x in range(5):
            source, bits = ROWS[y][x]
            lines.append(f"mov {ROW[x]}, [{here} + {8 * source}]")
            lines.append(f"xor {ROW[x]}, {THETA[source % 5]}")
            if bits:
                lines.append(f"rol {ROW[x]}, {bits}")
        for x in range(5):
            lines.append(f"andn {SCRATCH}, {ROW[(x + 1) % 5]}, {ROW[(x + 2) % 5]}")
            lines.append(f"xor {SCRATCH}, {ROW[x]}")
            if y == 0 and x == 0:
                lines.append(f"xor {SCRATCH}, [rax + {8 * r}]")
            lines.append(f"mov [{there} + {8 * (5 * y + x)}], {SCRATCH}")
    return lines


def weave(a, b):
    """Two lists of instructions, spread evenly through each other."""
    out, taken = [], 0
    for i, line in enumerate(a):
        out.append(line)
        upto = (i + 1) * len(b) // len(a)
        out += b[taken:upto]
        taken = upto
    return out


def nine(lanes):
    """Twelve rounds on eight states in vectors and one on general registers, for the wanted `lanes` of the results."""
    vector = assemble(program(round_by_rows, lanes), lanes)
    last_rows = sorted({lane // 5 for lane in lanes})
    lines = ["push rbx"]
    for r in range(12):
        end = vector.index("mark")
        here, there = ("rdi", "rsi") if r % 2 == 0 else ("rsi", "rdi")
        lines += weave(vector[:end], scalar_round(r, here, there, last_rows if r == 11 else range(5)))
        vector = vector[end + 1:]
    return lines + vector + ["pop rbx"]


# Rounds per pass in the loops.
# Two and three measured the same, four and six were slower.
PER_PASS = 2


def looped(round_fn, lanes, order=None, overwrite={}):
    """Twelve rounds, `PER_PASS` at a time in a loop counted by rcx, and the last ones written out for the wanted `lanes` only."""
    last = 12 - PER_PASS
    body = assemble(program(round_fn, range(25), order, overwrite, PER_PASS), range(25), constants="rax + rcx * 8")
    tail = assemble(program(round_fn, lanes, order, overwrite, PER_PASS), lanes, first_round=last)
    lines = ["xor ecx, ecx", "2:"] + body + [f"add ecx, {PER_PASS}", f"cmp ecx, {last}", "jb 2b"] + tail
    return [line for line in lines if line != "mark"]


def avx2():
    """Twelve rounds on four states with AVX2.

    The lanes live in memory, so the registers have fixed roles:
    ymm0 to ymm4 are the parities of the columns, ymm5 to ymm9 what theta adds to each column,
    ymm10 to ymm14 the row being made, and ymm15 is scratch.
    A row is made right after its five lanes were read, and stored right away.
    The parities for the next round are added up as the lanes are stored: reading them back costs more.

    The last round makes its rows from the last one, and stops once it has as many as ecx says.
    """
    lines = []
    for r in range(12):
        here, there = ("rdi", "rsi") if r % 2 == 0 else ("rsi", "rdi")
        if r == 0:
            for x in range(5):
                lines.append(f"vmovdqa ymm{x}, [{here} + {32 * x}]")
                lines += [f"vpxor ymm{x}, ymm{x}, [{here} + {32 * (5 * y + x)}]" for y in range(1, 5)]
        # There's no rotation instruction: rotating by one bit is an addition and a shift.
        for x in range(5):
            previous, following, d = (x + 4) % 5, (x + 1) % 5, 5 + x
            lines += [
                f"vpaddq ymm15, ymm{following}, ymm{following}",
                f"vpsrlq ymm{d}, ymm{following}, 63",
                f"vpor ymm{d}, ymm{d}, ymm15",
                f"vpxor ymm{d}, ymm{d}, ymm{previous}",
            ]
        for y in range(5) if r < 11 else (4, 3, 0, 1, 2):
            for x in range(5):
                source, bits = ROWS[y][x]
                b = 10 + x
                lines.append(f"vpxor ymm{b}, ymm{5 + source % 5}, [{here} + {32 * source}]")
                if bits in (8, 56):
                    lines.append(f"vpshufb ymm{b}, ymm{b}, [rax + {0 if bits == 8 else 32}]")
                elif bits:
                    lines += [
                        f"vpsllq ymm15, ymm{b}, {bits}",
                        f"vpsrlq ymm{b}, ymm{b}, {64 - bits}",
                        f"vpor ymm{b}, ymm{b}, ymm15",
                    ]
            for x in range(5):
                lines.append(f"vpandn ymm15, ymm{10 + (x + 1) % 5}, ymm{10 + (x + 2) % 5}")
                lines.append(f"vpxor ymm15, ymm15, ymm{10 + x}")
                if y == 0 and x == 0:
                    lines.append(f"vpxor ymm15, ymm15, [rax + {64 + 32 * r}]")
                lines.append(f"vmovdqa [{there} + {32 * (5 * y + x)}], ymm15")
                if r < 11:
                    lines.append(f"vmovdqa ymm{x}, ymm15" if y == 0 else f"vpxor ymm{x}, ymm{x}, ymm15")
            if r == 11 and y in (4, 3):
                lines += [f"cmp ecx, {5 - y}", "je 2f"]
    return lines + ["2:"]


VECTORS = """\
// Twelve rounds of Keccak-p[1600] on {states}, for AVX-512.
//
// Lane i of every state is in {reg}<i>, on the way in and on the way out.
// {reg}25 to {reg}31, rcx and the flags are overwritten, and rax points to the twelve round constants.
"""

SKIP = """\
//
// Only lanes {skip} to 24 of the result are computed.
// The other registers come out with garbage.
"""

NINE = """\
// Twelve rounds of Keccak-p[1600] on nine states: eight with AVX-512, and one on general registers, with BMI.
// The two kinds of instructions don't use the same parts of the CPU, so they are mixed and run at the same time.
//
// Lane i of the eight states is in zmm<i>, on the way in and on the way out.
// zmm25 to zmm31 are overwritten.
// The 25 lanes of the ninth state are at rdi, 8 bytes each, and there's room for 25 more at rsi:
// each round reads them in one place and writes them to the other, and the result ends up at rdi.
// rax points to the twelve round constants.
// rcx, rdx, r8 to r15 and the flags are overwritten.
//
// Only lanes 0 to 3 and 20 to 24 of the results are computed: what's read after a block of 20 lanes.
// The rest comes out with garbage.
"""

AVX2 = """\
// Twelve rounds of Keccak-p[1600] on four states, for AVX2.
//
// The 25 lanes are at rdi, 32 bytes each and aligned, and there's room for 25 more at rsi:
// each round reads the lanes in one place and writes them to the other, and the result ends up at rdi.
// rax points to two shuffle masks, to rotate by 8 and by 56 bits,
// then to the twelve round constants, four times each.
// ecx is how many rows of the result are wanted, counted from the last one: 1, 2 or 5.
// The other rows come out with garbage.
// ymm0 to ymm15 and the flags are overwritten.
"""

FOOTER = """\
//
// This file is generated by tools/keccak_x86.py. Don't edit it.
.p2align 6
"""

SIMD = pathlib.Path(__file__).resolve().parent.parent / "src" / "simd"


def write(name, header, lines):
    (SIMD / name).write_text(header + FOOTER + "\n".join(lines) + "\n")
    print(f"{name}: {len(lines)} instructions")


def main():
    write("keccak_avx512_x9_block20.s", NINE, nine([0, 1, 2, 3, 20, 21, 22, 23, 24]))

    # Eight states also have files without the first 16 or 20 lanes, for callers that overwrite them anyway.
    for skip in (0, 16, 20):
        lines = looped(plain_round, range(skip, 25), ORDER_X8, OVERWRITE_X8)
        header = VECTORS.format(states="eight states", reg="zmm") + (SKIP.format(skip=skip) if skip else "")
        write(f"keccak_avx512_x8_skip{skip}.s" if skip else "keccak_avx512_x8.s", header, lines)

    # Four states get the rounds with the fewest instructions, which is what counts there.
    # One and two states go through the same code, in the low part of the registers:
    # a ymm instruction costs what an xmm one does, and a second copy of the rounds would take turns with this one.
    lines = looped(round_by_rows, range(25))
    narrow = [line.replace("zmm", "ymm").replace("1to8", "1to4") for line in lines]
    write("keccak_avx512_x4.s", VECTORS.format(states="four states", reg="ymm"), narrow)

    write("keccak_avx2_x4.s", AVX2, avx2())


if __name__ == "__main__":
    main()
