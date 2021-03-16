#ifndef SHARED_H
# define SHARED_H

#include "allocstat.h"

#define IOCTL_UNKNOWN_BASE      FILE_DEVICE_UNKNOWN

#define BASE_IOCTL	0x800

/* test ioctl
 * Input buffer -  none
 * Output buffer - res (which DSA signature matched with called process
 */
#define IOCTL_TEST			CTL_CODE(IOCTL_UNKNOWN_BASE, BASE_IOCTL + 1, METHOD_BUFFERED, FILE_READ_DATA)
/* get alloc_stat for ecdsa allocations
 * Input buffer -  none
 * Output buffer - struct alloc_stat
 */
#define IOCTL_GET_ECDSA_ALLOCSTAT	CTL_CODE(IOCTL_UNKNOWN_BASE, BASE_IOCTL + 2, METHOD_BUFFERED, FILE_READ_DATA)

#endif /* SHARED_H */