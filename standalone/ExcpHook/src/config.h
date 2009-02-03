#pragma once
/* $Rev: 17 $ $LastChangedDate: 2009-02-03 09:57:31 +0100 (Wt, 03.02.2009) $
 */

#define EXCPHOOK_VERSION "0.0.5-rc2"

/*******************************************************************
 * Driver Status
 *******************************************************************/
#define DRV_STATUS_OK                            0x80000000
#define DRV_STATUS_ERROR                         0x40000000
#define DRV_STATUS_OK_NO_EXCP                    DRV_STATUS_OK | 0 
#define DRV_STATUS_OK_EXCP_PENDING               DRV_STATUS_OK | 1
#define DRV_STATUS_OK_EXCP_PENDING_BUFF_FULL     DRV_STATUS_OK | 2
#define DRV_STATUS_ERROR_HOOK_FIRST_SIGHT_FAILED DRV_STATUS_ERROR | 0
#define DRV_STATUS_ERROR_HOOK_FIRST_SIGHT_OK     DRV_STATUS_ERROR | 1
#define DRV_STATUS_ERROR_HOOK_FIRST_PATCH_FAILED DRV_STATUS_ERROR | 2

/*******************************************************************
 * IOCTL Packets
 *******************************************************************/

/* IOCTL_DRV_QUERY_VERSION
 * Asks the driver for a version string.
 * IN : Nothing
 * OUT: A buffer to write the version string, 128 bytes long.
 */
#define IOCTL_DRV_QUERY_VERSION   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA)

/* IOCTL_DRV_QUERY_STATUS
 * Asks the driver for status.
 * IN : Nothing
 * OUT: A pointer to a DWORD to store the status.
 *
 * Possible status (See Driver Status):
 * 0 - Driver OK, no exception pending
 * 1 - Driver OK, exception pending
 * 2 - Driver OK, exception pending, buffer full
 * 3 - Driver Error, could not set hook (KiDispatchException not found, first sight failed)
 * 4 - Driver Error, could not set hook (KiDispatchException not found, first sight OK)
 * 5 - Driver Error, could not set hook (patch could not be applied)
 */
#define IOCTL_DRV_QUERY_STATUS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_DATA)

/* IOCTL_DRV_READ_EXCEPTIONS
 * Asks the driver to send the exceptions.
 * IN : Nothing
 * OUT: A pointer to the buffer to receive the exceptions.
 * Check lpBytesReturned to see how many exceptions were received.
 */
#define IOCTL_DRV_READ_EXCEPTIONS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_READ_DATA)


/*******************************************************************
 * Exception info structure
 *******************************************************************/
#define EIP_BUFFER_SIZE 256
#define ESP_BUFFER_SIZE 64
#define IMAGE_NAME_SIZE 16

// TODO The following macro should depend on the Windows kernel version
// The below value is for XP SP3
#define OFFSET_IMAGE_NAME 0x174 // XP SP3
struct ExceptionInfo
{
  EXCEPTION_RECORD ExcpRecord;
  CONTEXT          Context;
  BYTE             ImageName[IMAGE_NAME_SIZE]; // Copied from EPROCESS
  BYTE             DataAtEip[EIP_BUFFER_SIZE];
  BYTE             DataAtEsp[ESP_BUFFER_SIZE];
};

