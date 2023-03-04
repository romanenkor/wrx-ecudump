#include <fcntl.h>
#include <stdlib.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 0)
#error "This code requires Linux kernel > 2.6!"
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "picocom.c"

void print_line(unsigned char *buffer, int num_bytes, int offset,
                int line_length) {
  printf("\33[2K\r");
  printf("%6X |", offset);

  for (int i = 0; i < line_length; i++) {
    if (i > 0 && i % 4 == 0) {
      printf(" ");
    }
    if (i < num_bytes) {
      printf(" %02X", buffer[i]);
    } else {
      printf("   ");
    }
  }

  printf(" | ");

  for (int i = 0; i < num_bytes; i++) {
    if (buffer[i] > 31 && buffer[i] < 127) {
      printf("%c", buffer[i]);
    } else {
      printf(".");
    }
  }

  printf("\n");
  printf("\33[2K\r");
}

int main(int argc, char *argv[]) {
  int tty_fd, n, fh;

  fh = open("ecu.bin", O_RDONLY | O_WRONLY | O_TRUNC);

  if (argc != 3) {
    printf("%s device speed\n\nSet speed for a serial device.\nFor instance:\n "
           "   %s /dev/ttyUSB0 4800\n",
           argv[0], argv[0]);
    return -1;
  }

  opts.port = argv[1];
  opts.baud = atoi(argv[2]);
  opts.parity = P_EVEN;
  opts.databits = 8;
  opts.stopbits = 1;
  opts.flow = FC_NONE;
  opts.lecho = 0;
  opts.imap = M_SPCHEX | M_TABHEX | M_CRHEX | M_LFHEX | M_NRMHEX | M_8BITHEX;
  opts.exit_after = 50;

  tty_init();

  printf("Test start\n");
  // sleep(1);

  int start = 0x0000;
  int end = 0xFFFF;

  char eeprom_buf[18];
  char stop_cmd[1] = {0x12};
  for (int address = start; address <= end; address += 16) {
    char cmd[4] = {0x78, (char)(address >> 8), (char)(address & 0xFF), 15};
    if (tty_q_push((char *)cmd, sizeof(cmd)) != sizeof(cmd))
      fd_printf(STO, "first *** output buffer full ***\r\n");

    tty_loop(eeprom_buf, sizeof(eeprom_buf));
    while (cmd[1] != eeprom_buf[0] || cmd[2] != eeprom_buf[1]) {
      if (tty_q_push((char *)stop_cmd, sizeof(stop_cmd)) != sizeof(stop_cmd))
        fd_printf(STO, "second *** output buffer full ***\r\n");
      tty_loop(NULL, 0);
      if (tty_q_push((char *)cmd, sizeof(cmd)) != sizeof(cmd))
        fd_printf(STO, "third *** output buffer full ***\r\n");
      tty_loop(eeprom_buf, sizeof(eeprom_buf));
    }
    print_line(&eeprom_buf[2], 16, address, 16);
    write(fh, &eeprom_buf[2], 16);
  }

  close(fh);

  tty_exit();

  return 0;
}
