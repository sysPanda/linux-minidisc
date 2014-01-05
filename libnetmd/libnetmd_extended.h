/*
 * include this header file to get access to additional libnetmd members
 */

#include "libnetmd.h"
#include "utils.h"
/*
 * additional members from secure.c
 */

void netmd_send_secure_msg(netmd_dev_handle *dev, unsigned char cmd, unsigned char *data, size_t data_size);
netmd_error netmd_recv_secure_msg(netmd_dev_handle *dev, unsigned char cmd, netmd_response *response,
                                  unsigned char expected_response_code);
netmd_error netmd_secure_real_recv_track(netmd_dev_handle *dev, uint32_t length, FILE *file, size_t chunksize);
void netmd_write_aea_header(char *name, uint32_t frames, unsigned char channel, FILE* f);
void netmd_write_wav_header(unsigned char format, uint32_t bytes, FILE *f);
size_t netmd_get_frame_size(netmd_wireformat wireformat);


