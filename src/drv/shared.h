#ifndef SHARED_H
# define SHARED_H

#define IOCTL_UNKNOWN_BASE      FILE_DEVICE_UNKNOWN

#define IOCTL_TEST_IOCTL	CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0801, METHOD_BUFFERED, FILE_READ_DATA)

#endif /* SHARED_H */