CC := gcc
OBJCOPY := objcopy
OBJDUMP := objdump
READELF := readelf

# Using -gstrict-dwarf to disable GNU extensions.
GFLAGS := -g -gstrict-dwarf

TESTS := frame-asm-directives test1 frame

.SECONDARY:

.PHONY: all
all: $(addsuffix .ref.txt,$(TESTS))

%.ref.txt: %.x
	$(READELF) -W -h -l -S -s -r -d -V -n $< > $@
	$(OBJDUMP) --dwarf $< | tail -n+4 >> $@
	$(OBJDUMP) --dwarf=frames-interp,decodedline $< | tail -n+4 >> $@

%.x: %.s
	$(CC) -nostartfiles $(GFLAGS) -o $@ $<

%.x: %.S
	$(CC) -nostartfiles $(GFLAGS) -o $@ $<

# Strip GNU property which is not supported by parse_elf.py
%.x: %.c
	$(CC) -O0 $(GFLAGS) -o $@ $<
	$(OBJCOPY) -R.note.gnu.property $@

.PHONY: clean
clean:
	rm -rf *.o *.x *.ref.txt
