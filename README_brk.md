The first syscall is from libc calling brk().
That returns a pointer whose upper nibbles are like: 0xaaaaa

Where is this behavior determined?
* kernel dynanmic configuration?
* compiled into kernel?
* part of ELF header describing where to put the brk/

See `PR_SET_MM_START_BRK`
from [prctl(2)](https://man7.org/linux/man-pages/man2/prctl.2.html).

The kernel mm attribute `start_brk` is involved.
`start_brk` is exposed through
`/proc/PID/stat`, typically field 26, perhaps 27 or 28.
although 'man proc stat' says `start_brk` is field 47.
