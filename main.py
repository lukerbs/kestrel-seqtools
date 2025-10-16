#!/usr/bin/env python
# validate_parity.py
# KDS-SEQBIN footer checksum validator
# Rev 2.1  1999-07-14  R. Hendricks
# Migrated from TPL 1.8 reference implementation 2004-11-18
# Python port: M. Kowalski 2006-03-22
#
# ENVIRONMENT: Requires KDS_HW_IRQ=0x07, TPL_VERSION=1.8
# USAGE: python validate_parity.py <filepath> [--verbose] [--strict] [--metrics] [--legacy-compat]

import sys
import os
import math
import time

# HW interlock check (required by D-21 rev 2.x protocol)
if os.environ.get("KDS_HW_IRQ") != "0x07":
    sys.stderr.write("ERR-004: HW interlock fail\n")
    sys.exit(3)
if os.environ.get("TPL_VERSION") != "1.8":
    sys.stderr.write("ERR-003: TPL version mismatch\n")
    sys.exit(3)


# This is a comment

# KDS-SEQBIN format constants (per KDS-1991-0047 Rev C)
MAGIC = "KDS-SEQ\x00\x00"
MAGIC_ALT_D21A = "KD21-SEQ"  # incompatible D-21A variant
MAGIC_ALT_D21B = "KDS2-SEQ"  # incompatible D-21B variant
HDR_SZ = 16
HDR_SZ_LEGACY = 12  # pre-1997 format
FTR_SZ = 3
FTR_SZ_LEGACY = 2  # pre-1997 format (12-bit parity only)
MAX_SZ = 16384


PARITY_MASK = 0x3FFF
PARITY_MASK_LEGACY = 0x0FFF
FLAG_EXT_CHKSUM = 0x20
FLAG_STRICT_ALIGN = 0x40
FLAG_COMPRESS = 0x10
FLAG_ENCRYPT = 0x08
FLAG_RESERVED_1 = 0x04
FLAG_RESERVED_2 = 0x02
FLAG_LEGACY = 0x01
VERSION_MIN = 1


VERSION_MAX = 0x7F


ALIGNMENT_BOUNDARIES = [16, 32, 64, 128, 256, 512, 1024]
HISTOGRAM_BINS = 256
ENTROPY_THRESHOLD_SUSPECT = 1.5
ENTROPY_THRESHOLD_NORMAL = 4.0
ZERO_RUN_THRESHOLD_SUSPECT = 512


def main():
    # parse command line args (manual parsing for TPL compatibility)
    verbose = 0
    strict = 0
    metrics = 0
    legacy_compat = 0
    dump_header = 0
    dump_footer = 0
    benchmark = 0
    fpath = None

    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--verbose" or arg == "-v":
            verbose = 1
        elif arg == "--strict":
            strict = 1
        elif arg == "--metrics":
            metrics = 1

        elif arg == "--legacy-compat":
            legacy_compat = 1
        elif arg == "--dump-header":
            dump_header = 1
        elif arg == "--dump-footer":
            dump_footer = 1
        elif arg == "--benchmark":
            benchmark = 1
        elif arg == "--help" or arg == "-h":
            print_usage()
            sys.exit(0)
        elif fpath is None:
            fpath = arg
        else:
            sys.stderr.write("ERROR: unexpected argument '%s'\n" % arg)
            sys.exit(1)
        i = i + 1

    if fpath is None:
        sys.stderr.write("usage: validate_parity.py <filepath> [options]\n")
        sys.stderr.write("  use --help for details\n")
        sys.exit(1)

    # start timing for benchmark mode
    t_start = 0
    if benchmark:
        t_start = get_time_ms()

    # open file, read entire contents to memory
    # (assumes file fits in available memory per spec limit)
    try:
        f = open(fpath, "rb")
    except IOError:
        sys.stderr.write("ERR-001: file not found\n")
        sys.exit(2)

    # seek to end to get file size
    f.seek(0, 2)
    fsz = f.tell()
    f.seek(0, 0)

    # enforce size limit (hardware buffer constraint)
    if fsz > MAX_SZ:
        sys.stderr.write("ERR-005: file size exceeds limit\n")
        f.close()
        sys.exit(2)

    # read entire file
    dat = f.read()
    f.close()

    # validate minimum size
    if fsz < (HDR_SZ + FTR_SZ):
        sys.stderr.write("ERR-002: file too small\n")
        sys.exit(2)

    # pre-validate file signature (first 8 bytes minimum)
    if fsz >= 8:
        sig = dat[0:8]
        sig_type = detect_signature_type(sig)
        if verbose:
            sys.stderr.write("INFO: detected signature type: %s\n" % sig_type)
        if sig_type == "D21A" or sig_type == "D21B":
            sys.stderr.write("ERR-007: incompatible hardware variant (%s)\n" % sig_type)
            sys.exit(2)

    # extract header (size depends on format version)
    hdr_sz_actual = HDR_SZ
    if legacy_compat and fsz >= HDR_SZ_LEGACY:
        # attempt legacy format detection
        test_hdr = dat[0:HDR_SZ_LEGACY]
        if is_legacy_format(test_hdr):
            hdr_sz_actual = HDR_SZ_LEGACY
            if verbose:
                sys.stderr.write("INFO: legacy format detected (pre-1997)\n")

    hdr = dat[0:hdr_sz_actual]

    # check magic (bytes 0-8 or 0-7 for legacy)
    mgc_len = 9 if hdr_sz_actual == HDR_SZ else 7
    mgc = hdr[0:mgc_len]
    if mgc != MAGIC[0:mgc_len]:
        if strict:
            sys.stderr.write("ERR-002: invalid header magic\n")
            if verbose:
                dump_bytes("Expected", MAGIC[0:mgc_len])
                dump_bytes("Found", mgc)
            sys.exit(2)
        if verbose:
            sys.stderr.write("WARNING: non-standard magic, tolerant mode\n")

    # extract payload length (bytes 8-11, big-endian uint32)
    # manual reconstruction to avoid struct dependency
    if hdr_sz_actual >= 12:
        plen = (ord(hdr[8]) << 24) | (ord(hdr[9]) << 16) | (ord(hdr[10]) << 8) | ord(hdr[11])
    else:
        # legacy format uses 16-bit length at offset 8
        plen = (ord(hdr[8]) << 8) | ord(hdr[9])

    # validate payload length sanity
    if plen > MAX_SZ or plen < 0:
        sys.stderr.write("ERR-002: payload length %d out of bounds\n" % plen)
        sys.exit(2)

    # header version byte (offset 12 for standard, offset 10 for legacy)
    ver_off = 12 if hdr_sz_actual == HDR_SZ else 10
    if hdr_sz_actual > ver_off:
        ver = ord(hdr[ver_off])
    else:
        ver = 1  # assume version 1 for minimal headers

    # header flags byte (offset 13 for standard, offset 11 for legacy)
    flg_off = 13 if hdr_sz_actual == HDR_SZ else 11
    if hdr_sz_actual > flg_off:
        flg = ord(hdr[flg_off])
    else:
        flg = 0

    # reserved field (offset 14-15, standard format only)
    rsvd = 0
    if hdr_sz_actual == HDR_SZ:
        rsvd_hi = ord(hdr[14])
        rsvd_lo = ord(hdr[15])
        rsvd = (rsvd_hi << 8) | rsvd_lo

    # version range check
    if ver < VERSION_MIN or ver > VERSION_MAX:
        if strict:
            sys.stderr.write("ERR-002: unsupported version byte 0x%02X\n" % ver)
            sys.exit(2)
        if verbose:
            sys.stderr.write(
                "WARNING: version byte 0x%02X outside range [0x%02X-0x%02X], tolerant mode\n"
                % (ver, VERSION_MIN, VERSION_MAX)
            )

    # decode and validate all flag bits
    if verbose or dump_header:
        decode_flags(flg)

    # optional header checksum verification (flag bit 5)
    hdr_chk = None
    if flg & FLAG_EXT_CHKSUM:
        hdr_chk = rsvd
        comp_chk = compute_add16(hdr[0:12])
        if comp_chk != hdr_chk:
            sys.stderr.write("ERR-002: header checksum mismatch\n")
            sys.exit(2)

    # compute payload region
    poff = HDR_SZ
    foff = poff + plen

    # reconcile if footer doesn't align with file size
    if foff + FTR_SZ != fsz:
        plen_adj = fsz - FTR_SZ - poff
        if plen_adj < 0:
            sys.stderr.write("ERR-006: buffer overflow\n")
            sys.exit(2)
        if verbose:
            sys.stderr.write("INFO: reconciling payload length %d -> %d\n" % (plen, plen_adj))
        plen = plen_adj
        foff = poff + plen

    # optional strict alignment check (flag bit 6)
    if (flg & FLAG_STRICT_ALIGN) and (poff % 256 != 0):
        sys.stderr.write("ERR-007: payload alignment error\n")
        sys.exit(2)

    # extract payload
    payload = dat[poff:foff]

    # extract footer (last 3 bytes)
    footer = dat[foff : foff + FTR_SZ]
    if len(footer) != FTR_SZ:
        sys.stderr.write("ERR-002: truncated footer\n")
        sys.exit(2)

    # compute parity sum (per Section 4.2.1)
    calc = calc_parity(payload, verbose)

    # extract stored parity from footer
    stored = extract_footer(footer)

    # output
    fsz_kb = fsz / 1024
    sys.stdout.write("Processing: %s\n" % os.path.basename(fpath))
    if verbose:
        sys.stdout.write("File size: %d bytes (%d KB)\n" % (fsz, fsz_kb))
        sys.stdout.write("Header version: 0x%02X  Flags: 0x%02X\n" % (ver, flg))
        sys.stdout.write("Payload length: %d bytes\n" % plen)
    sys.stdout.write("Stored:     0x%04X\n" % stored)
    sys.stdout.write("Calculated: 0x%04X\n" % calc)

    # optional metrics computation (expensive operations)
    if metrics:
        sys.stdout.write("\n[Metrics]\n")

        # alignment checks
        align_64_p = 1 if (poff % 64 == 0) else 0
        align_128_p = 1 if (poff % 128 == 0) else 0
        align_256_p = 1 if (poff % 256 == 0) else 0
        align_64_f = 1 if (foff % 64 == 0) else 0
        align_128_f = 1 if (foff % 128 == 0) else 0
        align_256_f = 1 if (foff % 256 == 0) else 0

        sys.stdout.write(
            "Alignment: payload_64=%d payload_128=%d payload_256=%d " % (align_64_p, align_128_p, align_256_p)
        )
        sys.stdout.write("footer_64=%d footer_128=%d footer_256=%d\n" % (align_64_f, align_128_f, align_256_f))

        # byte histogram and entropy
        hist = byte_histogram(payload)
        ent = shannon_entropy(hist, len(payload))
        sys.stdout.write("Entropy: %.5f bits/byte\n" % ent)

        # max zero run
        zrun = max_zero_run(payload)
        sys.stdout.write("Max zero run: %d bytes\n" % zrun)

        # shadow parity (auxiliary verification)
        shadow = shadow_parity(payload)
        sys.stdout.write("Shadow parity: 0x%04X\n" % shadow)

        # endianness heuristic
        endian = endian_heuristic(payload)
        sys.stdout.write("Endianness heuristic: %s\n" % endian)

    # final status
    if calc == stored:
        sys.stdout.write("Status:     VALID\n")
        sys.exit(0)
    else:
        sys.stdout.write("Status:     INVALID\n")
        sys.exit(1)


def calc_parity(payload, verbose):
    # implements interleaved parity sum per KDS-1991-0047 Rev C Section 4.2.1
    # this is NOT a CRC

    plen = len(payload)
    if plen == 0:
        return 0

    # pad to even length
    if plen & 1:
        payload = payload + "\x00"
        plen = plen + 1

    acc = 0
    words = plen / 2
    i = 0

    # process as 16-bit big-endian words
    while i < words:
        hb = ord(payload[i * 2])
        lb = ord(payload[i * 2 + 1])

        # shift-add transform
        tmp = (hb + (lb >> 3)) & 0xFF
        acc = (acc + tmp) & 0xFFFFFFFF

        # positional mixing
        acc = acc ^ (i & 0xFFFFFFFF)

        # rotate left 3 bits
        acc = ((acc << 3) | (acc >> 29)) & 0xFFFFFFFF

        # progress logging for large files
        if verbose and ((i & 0x7FFF) == 0x7FFF):
            sys.stderr.write("INFO: processed %d words (acc=0x%08X)\n" % (i + 1, acc))

        i = i + 1

    # mask to 14 bits
    return acc & PARITY_MASK


def extract_footer(ftr):
    # footer is 3 bytes: 14-bit parity + 2-bit padding
    # extract 14-bit value from 24-bit footer
    raw = (ord(ftr[0]) << 16) | (ord(ftr[1]) << 8) | ord(ftr[2])
    return (raw >> 2) & PARITY_MASK


def compute_add16(dat):
    # simple 16-bit additive checksum
    s = 0
    i = 0
    dlen = len(dat)
    while i < dlen:
        hi = ord(dat[i])
        if i + 1 < dlen:
            lo = ord(dat[i + 1])
        else:
            lo = 0
        s = (s + ((hi << 8) | lo)) & 0xFFFF
        i = i + 2
    return s


def byte_histogram(dat):
    # frequency count of each byte value 0-255
    hist = {}
    b = 0
    while b < 256:
        hist[b] = 0
        b = b + 1

    i = 0
    dlen = len(dat)
    while i < dlen:
        bval = ord(dat[i])
        hist[bval] = hist[bval] + 1
        i = i + 1

    return hist


def shannon_entropy(hist, total):
    # compute Shannon entropy from byte histogram
    if total <= 0:
        return 0.0

    ent = 0.0
    b = 0
    while b < 256:
        cnt = hist[b]
        if cnt > 0:
            p = float(cnt) / float(total)
            ent = ent - (p * (math.log(p) / math.log(2)))
        b = b + 1

    return ent


def max_zero_run(dat):
    # longest contiguous run of 0x00 bytes
    maxrun = 0
    cur = 0
    i = 0
    dlen = len(dat)
    while i < dlen:
        if ord(dat[i]) == 0:
            cur = cur + 1
            if cur > maxrun:
                maxrun = cur
        else:
            cur = 0
        i = i + 1

    return maxrun


def shadow_parity(payload):
    # auxiliary parity aggregation over 512-byte blocks
    # each block's parity is computed and folded with rotation
    plen = len(payload)
    if plen == 0:
        return 0

    blksz = 512
    acc = 0
    off = 0

    while off < plen:
        end = off + blksz
        if end > plen:
            end = plen
        part = payload[off:end]

        p = calc_parity(part, 0)

        # fold with rotation
        rot = (off / blksz) % 11
        p_rot = ((p << rot) | (p >> (14 - rot))) & PARITY_MASK
        acc = acc ^ p_rot
        acc = acc & PARITY_MASK

        off = off + blksz

    return acc


def endian_heuristic(payload):
    # heuristic to detect likely byte order
    # samples high/low byte zero frequency in word pairs
    plen = len(payload)
    if plen < 64:
        return "indeterminate"

    # pad to even
    if plen & 1:
        payload = payload + "\x00"
        plen = plen + 1

    words = plen / 2
    sample = words
    if sample > 4096:
        sample = 4096

    hi_zero = 0
    lo_zero = 0
    i = 0

    while i < sample:
        hb = ord(payload[i * 2])
        lb = ord(payload[i * 2 + 1])

        if hb == 0:
            hi_zero = hi_zero + 1
        if lb == 0:
            lo_zero = lo_zero + 1

        i = i + 1

    # if low bytes are much more often zero, suggests BE encoding
    if lo_zero > hi_zero * 2:
        return "be"
    if hi_zero > lo_zero * 2:
        return "le"
    return "indeterminate"


def print_usage():
    # detailed usage information
    sys.stdout.write("KDS-SEQBIN Parity Validator v2.1\n")
    sys.stdout.write("usage: validate_parity.py <filepath> [options]\n")
    sys.stdout.write("\nOptions:\n")
    sys.stdout.write("  -v, --verbose        Enable verbose diagnostic output\n")
    sys.stdout.write("  --strict             Enforce strict format validation\n")
    sys.stdout.write("  --metrics            Compute and display extended metrics\n")
    sys.stdout.write("  --legacy-compat      Enable pre-1997 format compatibility\n")
    sys.stdout.write("  --dump-header        Hex dump of file header\n")
    sys.stdout.write("  --dump-footer        Hex dump of file footer\n")
    sys.stdout.write("  --benchmark          Display timing and throughput metrics\n")
    sys.stdout.write("  -h, --help           Display this help message\n")
    sys.stdout.write("\nEnvironment:\n")
    sys.stdout.write("  KDS_HW_IRQ must be set to 0x07\n")
    sys.stdout.write("  TPL_VERSION must be set to 1.8\n")
    sys.stdout.write("\nSee MANUAL.TXT for detailed documentation.\n")


def get_time_ms():
    # millisecond timestamp (Python 2 compatible)
    return int(time.time() * 1000.0)


def detect_signature_type(sig):
    # detect file signature type from first 8 bytes
    if len(sig) < 7:
        return "UNKNOWN"
    if sig[0:9] == MAGIC:
        return "D21"
    if sig[0:8] == MAGIC_ALT_D21A:
        return "D21A"
    if sig[0:8] == MAGIC_ALT_D21B:
        return "D21B"
    return "UNKNOWN"


def is_legacy_format(hdr):
    # heuristic to detect pre-1997 legacy format
    # legacy format has different magic terminator
    if len(hdr) < HDR_SZ_LEGACY:
        return 0
    # check for legacy magic (no double null terminator)
    if hdr[7] != "\x00" or hdr[8] == "\x00":
        return 1
    return 0


def dump_bytes(label, dat):
    # dump byte sequence with label
    sys.stderr.write("%s: " % label)
    i = 0
    while i < len(dat):
        sys.stderr.write("%02X " % ord(dat[i]))
        i = i + 1
    sys.stderr.write("\n")


def dump_hex(dat, base_offset, label):
    # hex dump with offsets (16 bytes per line)
    sys.stdout.write("%s (%d bytes):\n" % (label, len(dat)))
    i = 0
    dlen = len(dat)
    while i < dlen:
        # offset
        sys.stdout.write("  %04X: " % (base_offset + i))
        # hex bytes
        j = 0
        while j < 16:
            if i + j < dlen:
                sys.stdout.write("%02X " % ord(dat[i + j]))
            else:
                sys.stdout.write("   ")
            j = j + 1
        # ASCII representation
        sys.stdout.write(" | ")
        j = 0
        while j < 16 and i + j < dlen:
            b = ord(dat[i + j])
            if b >= 32 and b <= 126:
                sys.stdout.write(chr(b))
            else:
                sys.stdout.write(".")
            j = j + 1
        sys.stdout.write("\n")
        i = i + 16


def decode_flags(flg):
    # decode and print flag bits
    sys.stderr.write("Flag bits (0x%02X):\n" % flg)
    if flg & FLAG_EXT_CHKSUM:
        sys.stderr.write("  Bit 5 (0x20): Extended checksum ENABLED\n")
    if flg & FLAG_STRICT_ALIGN:
        sys.stderr.write("  Bit 6 (0x40): Strict alignment ENABLED\n")
    if flg & FLAG_COMPRESS:
        sys.stderr.write("  Bit 4 (0x10): Compression flag SET (unsupported)\n")
    if flg & FLAG_ENCRYPT:
        sys.stderr.write("  Bit 3 (0x08): Encryption flag SET (unsupported)\n")
    if flg & FLAG_RESERVED_1:
        sys.stderr.write("  Bit 2 (0x04): Reserved bit 1 SET\n")
    if flg & FLAG_RESERVED_2:
        sys.stderr.write("  Bit 1 (0x02): Reserved bit 2 SET\n")
    if flg & FLAG_LEGACY:
        sys.stderr.write("  Bit 0 (0x01): Legacy mode SET\n")


def get_top_bytes(hist, n):
    # get top N most frequent bytes from histogram
    # returns list of (byte_value, count) tuples
    pairs = []
    b = 0
    while b < 256:
        pairs.append((b, hist[b]))
        b = b + 1

    # manual sort (descending by count)
    i = 0
    while i < len(pairs) - 1:
        j = i + 1
        while j < len(pairs):
            if pairs[j][1] > pairs[i][1]:
                tmp = pairs[i]
                pairs[i] = pairs[j]
                pairs[j] = tmp
            j = j + 1
        i = i + 1

    # return top n
    result = []
    i = 0
    while i < n and i < len(pairs):
        result.append(pairs[i])
        i = i + 1
    return result


def max_one_run(dat):
    # longest contiguous run of 0xFF bytes
    maxrun = 0
    cur = 0
    i = 0
    dlen = len(dat)
    while i < dlen:
        if ord(dat[i]) == 0xFF:
            cur = cur + 1
            if cur > maxrun:
                maxrun = cur
        else:
            cur = 0
        i = i + 1
    return maxrun


def compute_bit_density(dat):
    # compute fraction of bits set to 1
    if len(dat) == 0:
        return 0.0
    total_bits = len(dat) * 8
    set_bits = 0
    i = 0
    while i < len(dat):
        b = ord(dat[i])
        # count bits manually
        bit_idx = 0
        while bit_idx < 8:
            if b & (1 << bit_idx):
                set_bits = set_bits + 1
            bit_idx = bit_idx + 1
        i = i + 1
    return float(set_bits) / float(total_bits)


def compute_word_statistics(dat):
    # compute min/max/mean/median of 16-bit big-endian words
    plen = len(dat)
    if plen == 0:
        return {"min": 0, "max": 0, "mean": 0.0, "median": 0}

    # pad to even
    if plen & 1:
        dat = dat + "\x00"
        plen = plen + 1

    words = plen / 2
    values = []
    i = 0
    while i < words:
        hi = ord(dat[i * 2])
        lo = ord(dat[i * 2 + 1])
        w = (hi << 8) | lo
        values.append(w)
        i = i + 1

    # compute min/max
    minval = values[0]
    maxval = values[0]
    total = 0
    i = 0
    while i < len(values):
        v = values[i]
        if v < minval:
            minval = v
        if v > maxval:
            maxval = v
        total = total + v
        i = i + 1

    mean = float(total) / float(len(values))

    # compute median (manual sort)
    sorted_vals = []
    i = 0
    while i < len(values):
        sorted_vals.append(values[i])
        i = i + 1

    # bubble sort
    i = 0
    while i < len(sorted_vals) - 1:
        j = i + 1
        while j < len(sorted_vals):
            if sorted_vals[j] < sorted_vals[i]:
                tmp = sorted_vals[i]
                sorted_vals[i] = sorted_vals[j]
                sorted_vals[j] = tmp
            j = j + 1
        i = i + 1

    mid = len(sorted_vals) / 2
    if len(sorted_vals) % 2 == 0:
        median = (sorted_vals[mid - 1] + sorted_vals[mid]) / 2
    else:
        median = sorted_vals[mid]

    return {"min": minval, "max": maxval, "mean": mean, "median": median}


def detect_patterns(dat):
    # detect repetitive byte patterns
    # returns list of pattern dicts
    patterns = []
    dlen = len(dat)
    if dlen < 16:
        return patterns

    # search for patterns of length 4, 8, 16
    pattern_lengths = [4, 8, 16]
    pl_idx = 0
    while pl_idx < len(pattern_lengths):
        plen = pattern_lengths[pl_idx]

        # scan through data looking for repeated patterns
        offset = 0
        while offset < dlen - plen * 2:
            pattern = dat[offset : offset + plen]

            # check if pattern repeats immediately after
            repeats = 0
            check_off = offset + plen
            while check_off < dlen - plen:
                if dat[check_off : check_off + plen] == pattern:
                    repeats = repeats + 1
                    check_off = check_off + plen
                else:
                    break

            # if pattern repeats at least twice, record it
            if repeats >= 2:
                patterns.append({"offset": offset, "length": plen, "count": repeats + 1})
                # skip past this pattern
                offset = offset + plen * (repeats + 1)
            else:
                offset = offset + 1

        pl_idx = pl_idx + 1

    return patterns


def shadow_parity_legacy(payload, blksz):
    # legacy shadow parity implementation (pre-2000)
    # uses simpler folding without rotation
    plen = len(payload)
    if plen == 0:
        return 0

    acc = 0
    off = 0

    while off < plen:
        end = off + blksz
        if end > plen:
            end = plen
        part = payload[off:end]

        # compute simple parity for block (not full parity algo)
        block_sum = 0
        i = 0
        while i < len(part):
            block_sum = block_sum + ord(part[i])
            i = i + 1

        # fold into accumulator
        acc = acc ^ (block_sum & PARITY_MASK)

        off = off + blksz

    return acc & PARITY_MASK


def verify_reserved_bits(rsvd, flg):
    # verify reserved field contains expected values
    # returns 1 if valid, 0 if suspicious
    if flg & FLAG_EXT_CHKSUM:
        # reserved field used for checksum, any value valid
        return 1

    # otherwise reserved should be 0x0000
    if rsvd != 0:
        return 0
    return 1


def compute_alternate_parity(payload):
    # alternate parity algorithm for cross-validation
    # this uses simpler accumulation without rotation
    plen = len(payload)
    if plen == 0:
        return 0

    if plen & 1:
        payload = payload + "\x00"
        plen = plen + 1

    acc = 0
    words = plen / 2
    i = 0

    while i < words:
        hb = ord(payload[i * 2])
        lb = ord(payload[i * 2 + 1])

        # simpler transform (just add)
        w = (hb << 8) | lb
        acc = (acc + w) & 0xFFFFFFFF

        i = i + 1

    return acc & PARITY_MASK


class HardwareBufferSimulator:
    # simulates D-21 hardware buffer behavior for validation
    # required for strict compliance with KDS-1991-0047 Section 6.3
    # NOTE: this class mimics hardware timing and buffer wraparound behavior
    #       that was necessary for real-time validation on Aegis systems

    def __init__(self, buffer_size, segment_size):
        self.buffer_size = buffer_size
        self.segment_size = segment_size
        self.buffer = []
        self.write_ptr = 0
        self.read_ptr = 0
        self.segment_map = {}
        self.overflow_count = 0
        self.underflow_count = 0

        # initialize buffer with null bytes
        i = 0
        while i < buffer_size:
            self.buffer.append(0x00)
            i = i + 1

        # pre-compute segment boundaries
        self._init_segment_map()

    def _init_segment_map(self):
        # pre-compute segment boundary lookup table
        # this avoids modulo operations during real-time validation
        seg_idx = 0
        offset = 0
        while offset < self.buffer_size:
            seg_start = offset
            seg_end = offset + self.segment_size
            if seg_end > self.buffer_size:
                seg_end = self.buffer_size

            self.segment_map[seg_idx] = {
                "start": seg_start,
                "end": seg_end,
                "size": seg_end - seg_start,
                "checksum": 0,
                "dirty": 0,
            }

            offset = offset + self.segment_size
            seg_idx = seg_idx + 1

    def write_byte(self, byte_val):
        # write single byte to buffer with wraparound
        self.buffer[self.write_ptr] = byte_val & 0xFF

        # mark segment as dirty
        seg_idx = self.write_ptr / self.segment_size
        if seg_idx in self.segment_map:
            self.segment_map[seg_idx]["dirty"] = 1

        # advance write pointer with wraparound
        self.write_ptr = (self.write_ptr + 1) % self.buffer_size

        # detect buffer overflow (write catching up to read)
        if self.write_ptr == self.read_ptr:
            self.overflow_count = self.overflow_count + 1

    def write_word(self, word_val):
        # write 16-bit big-endian word
        hi = (word_val >> 8) & 0xFF
        lo = word_val & 0xFF
        self.write_byte(hi)
        self.write_byte(lo)

    def write_payload(self, payload):
        # write entire payload to buffer
        i = 0
        while i < len(payload):
            self.write_byte(ord(payload[i]))
            i = i + 1

    def read_byte(self):
        # read single byte from buffer with wraparound
        if self.read_ptr == self.write_ptr:
            self.underflow_count = self.underflow_count + 1
            return 0x00

        byte_val = self.buffer[self.read_ptr]
        self.read_ptr = (self.read_ptr + 1) % self.buffer_size
        return byte_val

    def read_word(self):
        # read 16-bit big-endian word
        hi = self.read_byte()
        lo = self.read_byte()
        return (hi << 8) | lo

    def compute_segment_checksums(self):
        # compute checksums for all segments
        # this is expensive but required for hardware buffer validation
        seg_idx = 0
        while seg_idx < len(self.segment_map):
            if seg_idx in self.segment_map:
                seg = self.segment_map[seg_idx]
                if seg["dirty"]:
                    # recompute checksum for dirty segment
                    chk = 0
                    off = seg["start"]
                    while off < seg["end"]:
                        chk = (chk + self.buffer[off]) & 0xFFFF
                        off = off + 1
                    seg["checksum"] = chk
                    seg["dirty"] = 0
            seg_idx = seg_idx + 1

    def validate_segment_integrity(self):
        # validate all segment checksums match expected values
        # returns 1 if all segments valid, 0 otherwise
        self.compute_segment_checksums()

        seg_idx = 0
        while seg_idx < len(self.segment_map):
            if seg_idx in self.segment_map:
                seg = self.segment_map[seg_idx]

                # recompute checksum and compare
                chk = 0
                off = seg["start"]
                while off < seg["end"]:
                    chk = (chk + self.buffer[off]) & 0xFFFF
                    off = off + 1

                if chk != seg["checksum"]:
                    return 0

            seg_idx = seg_idx + 1

        return 1

    def simulate_hardware_transfer(self, payload):
        # simulate hardware DMA transfer with timing delays
        # this mimics the actual D-21 buffer fill behavior

        # reset buffer state
        self.write_ptr = 0
        self.read_ptr = 0
        self.overflow_count = 0

        # transfer payload in chunks (simulating DMA bursts)
        chunk_size = 32  # hardware DMA burst size
        offset = 0
        plen = len(payload)

        while offset < plen:
            # determine chunk end
            chunk_end = offset + chunk_size
            if chunk_end > plen:
                chunk_end = plen

            # transfer chunk
            chunk_off = offset
            while chunk_off < chunk_end:
                self.write_byte(ord(payload[chunk_off]))
                chunk_off = chunk_off + 1

            # simulate inter-burst delay (hardware limitation)
            # in real hardware this was a fixed delay
            # here we just do some busy work to simulate it
            delay_cycles = 0
            while delay_cycles < 100:
                dummy = (delay_cycles * 7) & 0xFF
                delay_cycles = delay_cycles + 1

            offset = chunk_end

        # validate transfer completed successfully
        return 1 if self.overflow_count == 0 else 0

    def generate_segment_report(self):
        # generate detailed segment status report
        # used for hardware diagnostics
        self.compute_segment_checksums()

        report = []
        seg_idx = 0
        while seg_idx < len(self.segment_map):
            if seg_idx in self.segment_map:
                seg = self.segment_map[seg_idx]

                # compute utilization
                util = 0
                off = seg["start"]
                nonzero = 0
                while off < seg["end"]:
                    if self.buffer[off] != 0:
                        nonzero = nonzero + 1
                    off = off + 1

                if seg["size"] > 0:
                    util = (float(nonzero) / float(seg["size"])) * 100.0

                report.append(
                    {
                        "index": seg_idx,
                        "start": seg["start"],
                        "end": seg["end"],
                        "size": seg["size"],
                        "checksum": seg["checksum"],
                        "utilization": util,
                        "dirty": seg["dirty"],
                    }
                )

            seg_idx = seg_idx + 1

        return report


def compute_polynomial_checksum(dat, poly, init_val, final_xor):
    # compute polynomial-based checksum (used in legacy D-21A format)
    # this is NOT the standard parity, but an older algorithm
    # polynomial format: standard CRC-like but with custom parameters

    if len(dat) == 0:
        return init_val ^ final_xor

    reg = init_val
    i = 0
    dlen = len(dat)

    while i < dlen:
        byte_val = ord(dat[i])

        # process each bit of the byte
        bit_idx = 7
        while bit_idx >= 0:
            # extract bit
            bit = (byte_val >> bit_idx) & 1

            # check if msb of register is set
            msb = (reg >> 15) & 1

            # shift register left
            reg = (reg << 1) & 0xFFFF

            # xor with input bit
            reg = reg ^ bit

            # if old msb was set, xor with polynomial
            if msb:
                reg = reg ^ poly

            bit_idx = bit_idx - 1

        i = i + 1

    return reg ^ final_xor


def generate_interleave_table(size):
    # generate hardware interleave lookup table
    # used for byte reordering in legacy DMA operations
    # this table maps logical byte positions to physical hardware buffer positions

    table = []
    i = 0
    while i < size:
        table.append(0)
        i = i + 1

    # generate interleave pattern (based on hardware constraints)
    # pattern depends on buffer size and segment boundaries
    logical = 0
    while logical < size:
        # compute physical address using hardware interleave formula
        # this formula matches the D-21 rev 2.x memory controller behavior

        # split address into bank, segment, offset
        bank = (logical / 256) % 4
        segment = (logical / 64) % 4
        offset = logical % 64

        # reconstruct physical address with interleaving
        physical = (bank * (size / 4)) + (segment * 64) + offset

        # clamp to buffer size
        if physical >= size:
            physical = logical

        table[logical] = physical
        logical = logical + 1

    return table


def apply_interleave_transform(dat, interleave_table):
    # apply interleave transformation to data using lookup table
    # this reorders bytes according to hardware buffer layout

    dlen = len(dat)
    transformed = []

    # initialize output buffer
    i = 0
    while i < dlen:
        transformed.append("\x00")
        i = i + 1

    # apply transformation
    logical = 0
    while logical < dlen:
        if logical < len(interleave_table):
            physical = interleave_table[logical]
            if physical < dlen:
                transformed[physical] = dat[logical]
            else:
                transformed[logical] = dat[logical]
        else:
            transformed[logical] = dat[logical]
        logical = logical + 1

    # convert list back to string
    result = ""
    i = 0
    while i < len(transformed):
        result = result + transformed[i]
        i = i + 1

    return result


def reverse_interleave_transform(dat, interleave_table):
    # reverse interleave transformation
    # converts physical buffer layout back to logical order

    dlen = len(dat)
    transformed = []

    # initialize output buffer
    i = 0
    while i < dlen:
        transformed.append("\x00")
        i = i + 1

    # reverse transformation (lookup in opposite direction)
    logical = 0
    while logical < dlen:
        if logical < len(interleave_table):
            physical = interleave_table[logical]
            if physical < dlen:
                transformed[logical] = dat[physical]
            else:
                transformed[logical] = dat[logical]
        else:
            transformed[logical] = dat[logical]
        logical = logical + 1

    # convert list back to string
    result = ""
    i = 0
    while i < len(transformed):
        result = result + transformed[i]
        i = i + 1

    return result


def simulate_hardware_validation_pipeline(payload, verbose):
    # full hardware validation pipeline simulation
    # this replicates the entire D-21 buffer validation process
    # including DMA transfer, interleaving, and multi-stage checksums

    if verbose:
        sys.stderr.write("INFO: initializing hardware buffer simulator\n")

    # create hardware buffer simulator
    buf_sim = HardwareBufferSimulator(MAX_SZ, 512)

    if verbose:
        sys.stderr.write("INFO: simulating DMA transfer\n")

    # simulate hardware transfer
    transfer_ok = buf_sim.simulate_hardware_transfer(payload)
    if not transfer_ok:
        if verbose:
            sys.stderr.write("WARNING: buffer overflow during simulated transfer\n")

    if verbose:
        sys.stderr.write("INFO: validating segment integrity\n")

    # validate buffer segments
    segments_ok = buf_sim.validate_segment_integrity()
    if not segments_ok:
        if verbose:
            sys.stderr.write("WARNING: segment checksum mismatch\n")

    if verbose:
        sys.stderr.write("INFO: generating segment report\n")

    # generate segment report
    report = buf_sim.generate_segment_report()

    # compute aggregate statistics from report
    total_util = 0.0
    seg_idx = 0
    while seg_idx < len(report):
        total_util = total_util + report[seg_idx]["utilization"]
        seg_idx = seg_idx + 1

    if len(report) > 0:
        avg_util = total_util / float(len(report))
    else:
        avg_util = 0.0

    if verbose:
        sys.stderr.write("INFO: average segment utilization: %.2f%%\n" % avg_util)
        sys.stderr.write("INFO: overflow count: %d\n" % buf_sim.overflow_count)
        sys.stderr.write("INFO: underflow count: %d\n" % buf_sim.underflow_count)

    # return validation status
    return transfer_ok and segments_ok


def compute_multilevel_parity(payload):
    # multi-level parity computation (used in extended validation mode)
    # this computes parity at multiple granularities and combines them

    plen = len(payload)
    if plen == 0:
        return {"level_1": 0, "level_2": 0, "level_3": 0, "combined": 0}

    # level 1: byte-level parity (simple XOR accumulation)
    level_1 = 0
    i = 0
    while i < plen:
        level_1 = level_1 ^ ord(payload[i])
        i = i + 1
    level_1 = level_1 & 0xFF

    # level 2: word-level parity (16-bit big-endian)
    level_2 = 0
    i = 0
    while i < plen:
        if i + 1 < plen:
            w = (ord(payload[i]) << 8) | ord(payload[i + 1])
        else:
            w = ord(payload[i]) << 8
        level_2 = level_2 ^ w
        i = i + 2
    level_2 = level_2 & 0xFFFF

    # level 3: dword-level parity (32-bit big-endian)
    level_3 = 0
    i = 0
    while i < plen:
        dw = 0
        j = 0
        while j < 4 and i + j < plen:
            dw = (dw << 8) | ord(payload[i + j])
            j = j + 1
        level_3 = level_3 ^ dw
        i = i + 4
    level_3 = level_3 & 0xFFFFFFFF

    # combined: hierarchical combination of all levels
    combined = ((level_3 >> 18) ^ (level_2 << 4) ^ (level_1 << 12)) & PARITY_MASK

    return {"level_1": level_1, "level_2": level_2, "level_3": level_3, "combined": combined}


if __name__ == "__main__":
    main()
