This is a project that implements parsing of ELF files similar to what readelf
and objdump utilities do. It is intended mostly for my own amusement and
education and is not an attempt to develop a production-level alternative to
binutils. In particular the code may not handle various edge cases and there is
no user-friendly handling of malformed files - in case of invalid inputs the
code could throw some unhandled exception, fire an assert, or just continue
forward without a warning - there is no systemic approach to error handling.

Sources of specifications:
* https://refspecs.linuxfoundation.org/lsb.shtml
* http://www.sco.com/developers/gabi/latest/contents.html
* https://man7.org/linux/man-pages/man5/elf.5.html

Current implementation is tested with bintuils 2.34 and GCC 9.4. This, among
other means there are no tests for DWARF 5. The testing is done by diffing
output with a reference from objdump and readelf using some simple (or not so
simple) applications. There are no unit tests that test individual requirements
of ELF and DWARF standards. I am not writing individual unit tests mostly
because I'm interested in understanding high level concepts, rather then exactly
implementing standard to the letter.
