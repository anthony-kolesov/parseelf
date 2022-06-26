CC := gcc
OBJDUMP := objdump
READELF := readelf

TESTS := eh_frame

.SECONDARY:

.PHONY: all
all: $(addsuffix .ref.txt,$(TESTS))

%.ref.txt: %.x
	$(READELF) -W -h -l -S -s -r -d -V -n $< > $@
	$(OBJDUMP) --dwarf $< | tail -n+3 >> $@
	$(OBJDUMP) --dwarf=frames-interp,decodedline $< | tail -n+3 >> $@

%.x: %.s
	$(CC) -nostartfiles -o $@ $<

.PHONY: clean
clean:
	rm -rf *.o *.x *.ref.txt
