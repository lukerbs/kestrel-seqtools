## kestrel d-21 parity sum validator

footer checksum verification for KDS-SEQBIN sequence map files (`.SMAP` extension).

validates the 14-bit interleaved parity sum in the footer against the data payload per Section 4.2.1 of specification KDS-1991-0047 Rev C.

    originally part of internal Sequence Tools bundle (v2.3.1) 
    migrated from CVS 2004-11-18
    last modified 2006-03-22

---

## ENVIRONMENT

- TPL v1.8 interpreter required (other versions unsupported)
- `KDS_HW_IRQ` environment variable must equal `0x07`
- validated on Aegis OS 4.4 (build 1127)

other configurations may produce incorrect results or silent failures.

---

## USAGE

    tpl validate_parity.tpl <filepath>

output format: VALID/INVALID with stored vs. calculated checksum values

see Appendix E of KDS-1991-0047 for SMAP header structure.

### sample output

    Processing: SEQ_MAP_04A.SMAP
    Stored:     0x2E81
    Calculated: 0x2E81
    Status:     VALID

---

## LIMITATIONS

- max file size: 16,384 bytes (hardware buffer constraint)
- big-endian byte order required in source file
- files generated on LE host systems will fail validation
- assumes D-21 rev 2.x sequencer output format
- payload alignment checking disabled (see internal issue KDS-419)

files produced by D-21A or D-21B hardware variants are not compatible.

---

## ALGORITHM NOTES

processes payload as 16-bit big-endian words.  
for each word at index i:
  - right-shift low byte by 3
  - add to high byte (masked to 8 bits)
  - XOR accumulator with word index
  - rotate accumulator left by 3 bits

final accumulator is masked to 14 bits and compared to footer value (bytes at file_size - 3, 2 padding bits discarded).

this is NOT a CRC. this is the interleaved sum specified by the hardware vendor documentation.

---

## INSTALLATION

no build required. no external dependencies.

if migrating from Sequence Tools v2.2.x or earlier, consult migration document KDS-MIG-0039 regarding IRQ configuration changes.

---

## KNOWN ISSUES

- buffer overflow in TPL runtime for files >16KB (vendor issue, not fixed)
- tool will hang if header payload_length field is corrupt
- no graceful handling of truncated files
- endianness mismatch produces incorrect validation without warning

---

## STATUS

archived. no further development planned.

this tool fulfilled its original purpose (internal QA workflow, 1998-2006).  
retention is for historical reference per document retention policy DRP-91.

do not submit issues or pull requests. this repository is read-only by policy.

---

## LICENSE

proprietary software. copyright 1998-2006 Kestrel Systems Corp.

released for reference purposes only under internal documentation release policy DRP-91 (revised 2004-08-12).

users may view and execute the software for validation purposes consistent with original intended use. modification, redistribution, or derivative works require written authorization from Kestrel Systems legal department.

Kestrel Systems Corp. was acquired by Hexagon Industrial Technologies in 2008. current IP ownership and support contacts unknown. use at own risk.

no warranty express or implied. provided AS-IS per maintenance agreement appendix G.

---

## CONTACT

for questions regarding KDS hardware or SMAP format specification, contact your local Kestrel Systems field representative or consult the appropriate hardware maintenance agreement documentation.

software support was discontinued 2007-09-30.
