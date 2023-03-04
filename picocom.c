/* vi: set sw=4 ts=4:
 *
 * picocom.c
 *
 * simple dumb-terminal program. Helps you manually configure and test
 * stuff like modems, devices w. serial ports, etc.
 *
 * by Nick Patavalis (npat@efault.net)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef USE_FLOCK
#include <sys/file.h>
#endif

#define _GNU_SOURCE
#include <getopt.h>

/* vi: set sw=4 ts=4:
 *
 * fdio.h
 *
 * Functions for doing I/O on file descriptors.
 *
 * by Nick Patavalis (npat@efault.net)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */

#ifndef FDIO_H

ssize_t writen_ni(int fd, const void *buff, size_t n);

int fd_vprintf(int fd, const char *format, va_list ap);

int fd_printf(int fd, const char *format, ...);

#ifndef LINENOISE

int fd_readline(int fdi, int fdo, char *b, int bsz);

#endif

#endif /* of FDIO_H */

/**********************************************************************/

/*
 * Local Variables:
 * mode:c
 * tab-width: 4
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

/* vi: set sw=4 ts=4:
 *
 * fdio.c
 *
 * Functions for doing I/O on file descriptors.
 *
 * by Nick Patavalis (npat@efault.net)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/**********************************************************************/

ssize_t writen_ni(int fd, const void *buff, size_t n) {
  size_t nl;
  ssize_t nw;
  const char *p;

  p = buff;
  nl = n;
  while (nl > 0) {
    do {
      nw = write(fd, p, nl);
    } while (nw < 0 && errno == EINTR);
    if (nw <= 0)
      break;
    nl -= nw;
    p += nw;
  }

  return n - nl;
}

int fd_vprintf(int fd, const char *format, va_list ap) {
  char buf[256];
  int len;

  len = vsnprintf(buf, sizeof(buf), format, ap);
  buf[sizeof(buf) - 1] = '\0';

  return writen_ni(fd, buf, len);
}

int fd_printf(int fd, const char *format, ...) {
  va_list args;
  int len;

  va_start(args, format);
  len = fd_vprintf(fd, format, args);
  va_end(args);

  return len;
}

/**********************************************************************/

#ifndef LINENOISE

static int cput(int fd, char c) { return write(fd, &c, 1); }

static int cdel(int fd) {
  const char del[] = "\b \b";
  return write(fd, del, sizeof(del) - 1);
}

static int xput(int fd, unsigned char c) {
  const char hex[] = "0123456789abcdef";
  char b[4];

  b[0] = '\\';
  b[1] = 'x';
  b[2] = hex[c >> 4];
  b[3] = hex[c & 0x0f];
  return write(fd, b, sizeof(b));
}

static int xdel(int fd) {
  const char del[] = "\b\b\b\b    \b\b\b\b";
  return write(fd, del, sizeof(del) - 1);
}

int fd_readline(int fdi, int fdo, char *b, int bsz) {
  int r;
  unsigned char c;
  unsigned char *bp, *bpe;

  bp = (unsigned char *)b;
  bpe = (unsigned char *)b + bsz - 1;

  while (1) {
    r = read(fdi, &c, 1);
    if (r <= 0) {
      r = -1;
      goto out;
    }

    switch (c) {
    case '\b':
    case '\x7f':
      if (bp > (unsigned char *)b) {
        bp--;
        if (isprint(*bp))
          cdel(fdo);
        else
          xdel(fdo);
      } else {
        cput(fdo, '\x07');
      }
      break;
    case '\x03': /* CTRL-c */
      r = -1;
      errno = EINTR;
      goto out;
    case '\r':
      *bp = '\0';
      r = bp - (unsigned char *)b;
      goto out;
    default:
      if (bp < bpe) {
        *bp++ = c;
        if (isprint(c))
          cput(fdo, c);
        else
          xput(fdo, c);
      } else {
        cput(fdo, '\x07');
      }
      break;
    }
  }

out:
  return r;
}

#endif /* of LINENOISE */

/**********************************************************************/

/*
 * Local Variables:
 * mode:c
 * tab-width: 4
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

/* vi: set sw=4 ts=4:
 *
 * split.h
 *
 * Function that splits a string intro arguments with quoting.
 *
 * by Nick Patavalis (npat@efault.net)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */

#ifndef SPLIT_H
#define SPLIT_H

/* Maximum single-argument length that can be dealt-with by function
 * split_quoted(). Longer arguments are truncated. See below.
 */
#define MAX_ARG_LEN 512

/* Warning flags, set by split_quoted() to its return value.  */
#define SPLIT_DROP (1 << 0)  /* argument had to be dropped */
#define SPLIT_TRUNC (1 << 1) /* argument had to be truncated */

/* F split_quoted
 *
 * Splits string "s" into arguments and places them in "argv". Every
 * argument is a heap-allocated null-terminated string that must be
 * freed with free(3) when no longer needed. The first argument is
 * placed in "argv[*argc]", the following at subsequent "argv" slots,
 * and "*argc" is incremented accordingly. As a result, this function
 * can be called multiple times to add arguments to the same argument
 * vector. The argument "argv_sz" is the allocated size (in number of
 * slots) of the supplied argument vector ("argv"). The function takes
 * care not to overrun it. If more arguments are present in the
 * input string "s", they are dropped.
 *
 * When spliting the input string intro arguments, quoting rules
 * very similar to the ones used by the Unix shell are used.
 *
 * The following caracters are considered special: ' ' (space), '\t'
 * (tab), '\n' (newline), '\' (backslash), ''' (single quote), and '"'
 * (double quote). All other caracters are considered normal and can
 * become part of an argument without escaping.
 *
 * Arguments are separated by runs of the characters: ' ' (space),
 * '\t', and '\n', which are considered delimiters.
 *
 * All characters beetween single quotes (')---without
 * exceptions---are considered normal and become part of the current
 * argument (but not the single quotes themselves).
 *
 * All characters between double quotes (") are considered normal and
 * become part of the current argument (but not the double quotes
 * themselves). Exception to this is the backslash character, when
 * followed by one of the characters '"', '\', '$', and '`'. In this
 * case, the backslash is removed, and the next caracter is considered
 * normal and becomes part of the current argument. When the backslash
 * is followed by newline, both the backslash and the newline are
 * removed. In all other cases a backslash, within double quotes, is
 * considered a normal character (and becomes part of the current
 * argument). We treat the sequences '\$' and '\`' specially (while
 * there is no real reason), for better unix-shell compatibility.
 *
 * Outside of single or double quotes, every backslash caracter is
 * removed, and the following character (with the exception of
 * <newline>, see below) is considered normal and becomes part of the
 * current argument. If, outside of quotes, a backslash precedes a
 * <newline>, then both the backslash and the newline are removed.
 *
 * Examples:
 *
 *      a b c d        --> [a] [b] [c] [d]
 *      'a  b' c   d   --> [a b] [c] [d]
 *      'a "b"' c d    --> [a "b"] [c] [d]
 *      "a 'b'" c d    --> [a 'b'] [c] [d]
 *      a"b c"  d      --> [ab c] [d]
 *      a\ b c d       --> [a b] [c] [d]
 *      \a\b c d       --> [ab] [c] [d]
 *      \a\\b \\ c d   --> [a\b] [\] [c] [d]
 *      "a\$\b" c d    --> [a$\b] [c] [d]
 *      "\a\`\"\b" c d --> [\a`"\b] [c] [d]
 *
 * Limitation: This function cannot deal with individual arguments
 * longer than MAX_ARG_LEN. If such an argument is encountered, it is
 * truncated accordingly.
 *
 * This function returns a non-negative on success, and a negative on
 * failure. The only causes for failure is a malformed command string
 * (e.g. un-balanced quotes), or the inability to allocate an argument
 * string. On success the value returned can be checked against the
 * warning flags SPLIT_DROP, and SPLIT_TRUNC. If SPLIT_DROP is set,
 * then a least one argument was dropped as there was no available
 * slot in "argv" to store it in. If SPLIT_TRUNC is set, then at least
 * one argument was truncated (see limitation, above).
 */
int split_quoted(const char *s, int *argc, char *argv[], int argv_sz);

#endif /* of SPLIT_H */

/**********************************************************************/

/*
 * Local Variables:
 * mode:c
 * tab-width: 4
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

/* vi: set sw=4 ts=4:
 *
 * split.c
 *
 * Function that splits a string intro arguments with quoting.
 *
 * by Nick Patavalis (npat@efault.net)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* Lexer error end-codes */
enum err_codes {
  ERR_OK = 0,         /* no error, string lexed ok */
  ERR_BS_AT_EOS,      /* backslash at the end of string */
  ERR_SQ_OPEN_AT_EOS, /* single-quote left open */
  ERR_DQ_OPEN_AT_EOS  /* double-quote left open */
};

/* Lexer states */
enum states { ST_DELIM, ST_QUOTE, ST_ARG, ST_END };

/* Special characters */
#define BS '\\'
#define SQ '\''
#define DQ '\"'
#define NL '\n'
#define EOS '\0'

#define is_delim(c) ((c) == ' ' || (c) == '\t' || (c) == '\n')

#define is_dq_escapable(c)                                                     \
  ((c) == '\\' || (c) == '\"' || (c) == '`' || (c) == '$')

/* Short-hands used in split_quoted() */
#define push()                                                                 \
  do {                                                                         \
    char *arg;                                                                 \
    if (*argc < argv_sz) {                                                     \
      *ap = '\0';                                                              \
      arg = strdup(arg_buff);                                                  \
      /* !! out of mem !! */                                                   \
      if (!arg)                                                                \
        return -1;                                                             \
      argv[*argc] = arg;                                                       \
      (*argc)++;                                                               \
    } else {                                                                   \
      flags |= SPLIT_DROP;                                                     \
    }                                                                          \
    ap = &arg_buff[0];                                                         \
  } while (0)

#define save()                                                                 \
  do {                                                                         \
    if (ap != ae) {                                                            \
      *ap++ = *c;                                                              \
    } else {                                                                   \
      flags |= SPLIT_TRUNC;                                                    \
    }                                                                          \
  } while (0)

int split_quoted(const char *s, int *argc, char *argv[], int argv_sz) {
  char arg_buff[MAX_ARG_LEN]; /* current argument buffer */
  char *ap, *ae;              /* arg_buff current ptr & end-guard */
  const char *c;              /* current input charcter ptr */
  char qc;                    /* current quote character */
  enum states state;          /* current state */
  enum err_codes err;         /* error end-code */
  int flags;                  /* warning flags */

  ap = &arg_buff[0];
  ae = &arg_buff[MAX_ARG_LEN - 1];
  c = &s[0];
  state = ST_DELIM;
  err = ERR_OK;
  flags = 0;
  qc = SQ; /* silence compiler waring */

  while (state != ST_END) {
    switch (state) {
    case ST_DELIM:
      while (is_delim(*c))
        c++;
      if (*c == SQ || *c == DQ) {
        qc = *c;
        c++;
        state = ST_QUOTE;
        break;
      }
      if (*c == EOS) {
        state = ST_END;
        break;
      }
      if (*c == BS) {
        c++;
        if (*c == NL) {
          c++;
          break;
        }
        if (*c == EOS) {
          state = ST_END;
          err = ERR_BS_AT_EOS;
          break;
        }
      }
      /* All other cases incl. character after BS */
      save();
      c++;
      state = ST_ARG;
      break;
    case ST_QUOTE:
      while (*c != qc && (*c != BS || qc == SQ) && *c != EOS) {
        save();
        c++;
      }
      if (*c == qc) {
        c++;
        state = ST_ARG;
        break;
      }
      if (*c == BS) {
        assert(qc == DQ);
        c++;
        if (*c == NL) {
          c++;
          break;
        }
        if (*c == EOS) {
          state = ST_END;
          err = ERR_BS_AT_EOS;
          break;
        }
        if (!is_dq_escapable(*c)) {
          c--;
          save();
          c++;
        }
        save();
        c++;
        break;
      }
      if (*c == EOS) {
        state = ST_END;
        err = ERR_SQ_OPEN_AT_EOS;
        break;
      }
      assert(0);
    case ST_ARG:
      if (*c == SQ || *c == DQ) {
        qc = *c;
        c++;
        state = ST_QUOTE;
        break;
      }
      if (is_delim(*c) || *c == EOS) {
        push();
        state = (*c == EOS) ? ST_END : ST_DELIM;
        c++;
        break;
      }
      if (*c == BS) {
        c++;
        if (*c == NL) {
          c++;
          break;
        }
        if (*c == EOS) {
          state = ST_END;
          err = ERR_BS_AT_EOS;
          break;
        }
      }
      /* All other cases, incl. character after BS */
      save();
      c++;
      break;
    default:
      assert(0);
    }
  }

  return (err != ERR_OK) ? -1 : flags;
}

/**********************************************************************/

#if 0

int
main (int argc, char *argv[])
{
    char *my_argv[12];
    int my_argc, i, r;

    if ( argc != 2 ) {
        printf("Usage is: %s: <string to split>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    printf("String to split is: [%s]\n", argv[1]);
    r = split_quoted(argv[1], &my_argc, my_argv, 12);
    if ( r < 0 ) {
        printf("Spliting failed!\n");
        exit(EXIT_FAILURE);
    }
    printf("Split ok. SPLIT_DROP is %s, SPLIT_TRUNC is %s\n",
           (r & SPLIT_DROP) ? "ON" : "off",
           (r & SPLIT_TRUNC) ? "ON" : "off");

    for (i = 0; i < my_argc; i++)
        printf("%02d : [%s]\n", i, my_argv[i]);

    return EXIT_SUCCESS;
}

#endif

/**********************************************************************/

/*
 * Local Variables:
 * mode:c
 * tab-width: 4
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

/* vi: set sw=4 ts=4:
 *
 * term.h
 *
 * Simple terminal management library. Wraps termios(3), and
 * simplifies the logistics required for the reliable management and
 * control of terminals.
 *
 * Principles of operation:
 *
 * After the library is initialized, one or more file-descriptors can
 * be added to (and latter removed from) the list managed by the
 * it. These file descriptors must be opened on terminal devices. For
 * every fd, the original settings of the associated terminal device
 * are saved by the library. These settings are restored when the fd
 * is removed from the framework, or at program termination [by means
 * of an atexit(3) handler installed by the library], or at user
 * request. The library maintains three structures for every fd in the
 * framework: The original settings structure ("origtermios"), keeping
 * the settings of the terminal device when the respective filedes was
 * added to the framework. The current settings structure
 * ("currtermios"), keeping the current settings of the associated
 * terminal device; and the next settings structure ("nexttermios")
 * which keeps settings to be applied to the associated terminal
 * device at a latter time, upon user request.  The "term_set_*"
 * functions can be used to modify the device settings stored in the
 * nexttermios structure. Using functions provided by the library the
 * user can: Apply the nexttermios settings to the device. Revert all
 * changes made on nexttermios by copying the currtermios structure to
 * nexttermios. Reset the device, by configuring it to the original
 * settings, and copying origtermios to currtermios and
 * nexttermios. Refresh the device by rereading the current settings
 * from it and updating currtermios (to catch up with changes made to
 * the device by means outside of this framework).
 *
 * Interface summary:
 *
 * F term_lib_init  - library initialization
 * F term_add - add a filedes to the framework
 * F term_remove - remove a filedes from the framework
 * F term_erase - remove a filedes from the framework without reset
 * F term_replace - replace a fd w/o affecting the settings stuctures
 * F term_reset - revert a device to the settings in "origtermios"
 * F term_apply - configure a device to the settings in "nexttermios"
 * F term_revert - discard "nexttermios" by copying-over "currtermios"
 * F term_refresh - update "currtermios" from the device
 * F term_set_raw - set "nexttermios" to raw mode
 * F term_set_baudrate - set the baudrate in "nexttermios"
 * F term_set_parity - set the parity mode in "nexttermios"
 * F term_set_databits - set the databits in "nexttermios"
 * F term_set_stopbits - set the stopbits in "nexttermios"
 * F term_set_flowcntrl - set the flowcntl mode in "nexttermios"
 * F term_set_hupcl - enable or disable hupcl in "nexttermios"
 * F term_set_local - set "nexttermios" to local or non-local mode
 * F term_set - set all params of "nexttermios" in a single stroke
 * F term_get_baudrate - return the baudrate set in "currtermios"
 * F term_get_parity - return the parity setting in "currtermios"
 * F term_get_databits - return the data-bits setting in "currtermios"
 * F term_get_flowcntrl - return the flow-control setting in "currtermios"
 * F term_pulse_dtr - pulse the DTR line a device
 * F term_lower_dtr - lower the DTR line of a device
 * F term_raise_dtr - raise the DTR line of a device
 * F term_lower_rts - lower the RTS line of a device
 * F term_raise_rts - raise the RTS line of a device
 * F term_get_mctl - Get modem control signals status
 * F term_drain - drain the output from the terminal buffer
 * F term_flush - discard terminal input and output queue contents
 * F term_fake_flush - discard terminal input and output queue contents
 * F term_break - generate a break condition on a device
 * F term_baud_up - return next higher baudrate
 * F term_baud_down - return next lower baudrate
 * F term_baud_ok - check if baudrate is valid
 * F term_baud_std - check if baudrate is on of our listed standard baudrates
 * F term_strerror - return a string describing current error condition
 * F term_perror - print a string describing the current error condition
 * G term_errno - current error condition of the library
 * E term_errno_e - error condition codes
 * E parity_t - library supported parity types
 * E flocntrl_t - library supported folw-control modes
 * M MAX_TERM - maximum number of fds that can be managed
 *
 * by Nick Patavalis (npat@efault.net)
 *
 * originaly by Pantelis Antoniou (https://github.com/pantoniou),
 *              Nick Patavalis
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 * $Id: term.h,v 1.1 2003/05/07 18:00:05 npat Exp $
 */

#ifndef TERM_H
#define TERM_H

/* M MAX_TERMS
 *
 * Maximum nuber of terminals that can be managed by the library. Keep
 * relatively low, since linear searches are used. Reasonable values
 * would be: 16, 32, 64, etc.
 */
#define MAX_TERMS 16

/*
 * E term_errno_e
 *
 * Library error-condition codes. These marked with "see errno"
 * correspond to system errors, so it makes sense to also check the
 * system's error-condition code (errno) in order to fully determine
 * what went wrong.
 *
 * See the error strings in "term.c" for a description of each.
 */
enum term_errno_e {
  TERM_EOK = 0,
  TERM_ENOINIT,
  TERM_EFULL,
  TERM_ENOTFOUND,
  TERM_EEXISTS,
  TERM_EATEXIT,
  TERM_EISATTY,
  TERM_EFLUSH,   /* see errno */
  TERM_EGETATTR, /* see errno */
  TERM_ESETATTR, /* see errno */
  TERM_EBAUD,
  TERM_ESETOSPEED,
  TERM_ESETISPEED,
  TERM_EGETSPEED,
  TERM_EPARITY,
  TERM_EDATABITS,
  TERM_ESTOPBITS,
  TERM_EFLOW,
  TERM_EDTRDOWN,
  TERM_EDTRUP,
  TERM_EMCTL,
  TERM_EDRAIN, /* see errno */
  TERM_EBREAK,
  TERM_ERTSDOWN,
  TERM_ERTSUP
};

/* E parity_e
 *
 * Parity modes supported by the library:
 *
 * P_NONE  - no patiry
 * P_EVEN  - even parity
 * P_ODD   - odd parity
 * P_MARK  - mark parity (parity bit always 1)
 * P_SPACE - space parity (parity bit always 0)
 * P_ERROR - marker to indicate error for functions returning parity_e
 */
enum parity_e { P_NONE = 0, P_EVEN, P_ODD, P_MARK, P_SPACE, P_ERROR };

/*
 * E flowcntrl_e
 *
 * Flow control modes, supported by the library.
 *
 * FC_NONE - no flow control
 * FC_RTSCTS - RTS/CTS handshaking, also known as hardware
 *     flow-control.
 * FC_XONXOFF  - xon/xoff flow control.
 * FC_ERROR - marker to indicate error for functions returning flowcntrl_e
 */
enum flowcntrl_e { FC_NONE = 0, FC_RTSCTS, FC_XONXOFF, FC_OTHER, FC_ERROR };

/*
 * C MCTL_xxx
 *
 * Modem control line bits. Used against the return value of
 * term_get_mctl().
 */
#define MCTL_DTR (1 << 1)     /* O: Data Terminal Ready */
#define MCTL_DSR (1 << 2)     /* I: Data Set Ready */
#define MCTL_DCD (1 << 3)     /* I: Data Carrier Detect */
#define MCTL_RTS (1 << 4)     /* O: Request To Send */
#define MCTL_CTS (1 << 5)     /* I: Clear To Send */
#define MCTL_RI (1 << 6)      /* I: Ring Indicator */
#define MCTL_UNAVAIL (1 << 0) /* MCTL lines (status) not available */

/***************************************************************************/

/*
 * G term_errno
 *
 * Keeps the current library error-condtion code
 */
extern int term_errno;

/***************************************************************************/

/*
 * F term_strerror
 *
 * Return a string descibing the current library error condition.  If
 * the error condition reflects a system error, then the respective
 * system-error description is appended at the end of the returned
 * string. The returned string points to a statically allocated buffer
 * that is overwritten with every call to term_strerror()
 *
 * Returns a string describing the current library (and possibly
 * system) error condition.
 */
const char *term_strerror(int terrnum, int errnum);

/*
 * F term_perror
 *
 * Emit a description of the current library (and possibly system)
 * error condition to the standard-error stream. The description is
 * prefixed by a user-supplied string. What is actually emmited is:
 *
 *     <prefix><space><description>\n
 *
 * The description emitted is the string returned by term_strerror().
 *
 * Returns the number of characters emmited to the standard-error
 * stream or a neagative on failure.
 */
int term_perror(const char *prefix);

/* F term_lib_init
 *
 * Initialize the library
 *
 * Initialize the library. This function must be called before any
 * attemt to use the library. If this function is called and the
 * library is already initialized, all terminals associated with the
 * file-descriptors in the framework will be reset to their original
 * settings, and the file-descriptors will be removed from the
 * framework. An atexit(3) handler is installed by the library which
 * resets and removes all managed terminals.
 *
 * Returns negative on failure, non-negative on success. This function
 * will only fail if the atexit(3) handler cannot be
 * installed. Failure to reset a terminal to the original settings is
 * not considered an error.
 */
int term_lib_init(void);

/* F term_add
 *
 * Add the filedes "fd" to the framework. The filedes must be opened
 * on a terminal device or else the addition will fail. The settings
 * of the terminal device associated with the filedes are read and
 * stored in the origtermios structure.
 *
 * Returns negative on failure, non-negative on success.
 */
int term_add(int fd);

/* F term_remove
 *
 * Remove the filedes "fd" from the framework. The device associated
 * with the filedes is reset to its original settings (those it had
 * when it was added to the framework)
 *
 * Return negative on failure, non-negative on success. The filedes is
 * always removed form the framework even if this function returns
 * failure, indicating that the device reset failed.
 */
int term_remove(int fd);

/* F term_erase
 *
 * Remove the filedes "fd" from the framework. The device associated
 * with the filedes is *not* reset to its original settings.
 *
 * Return negative on failure, non-negative on success. The only
 * reason for failure is the filedes not to be found.
 */
int term_erase(int fd);

/* F term_replace
 *
 * Replace a managed filedes without affecting the associated settings
 * structures. The "newfd" takes the place of "oldfd". "oldfd" is
 * removed from the framework without the associated device beign
 * reset (it is most-likely no longer connected to a device anyway,
 * and reset would fail). The device associated with "newfd" is
 * configured with "oldfd"s current settings (stored in the
 * "currtermios" structure). After applying the settings to "newfd",
 * the "currtermios" structure is re-read from the device, so that it
 * corresponds to the actual device settings.
 *
 * Returns negative on failure, non-negative on success. In case of
 * failure "oldfd" is not removed from the framework, and no
 * replacement takes place.
 *
 * The usual reason to replace the filedes of a managed terminal is
 * because the device was closed and re-opened. This function gives
 * you a way to do transparent "open"s and "close"s: Before you close
 * a device, it has certain settings managed by the library. When you
 * close it and then re-open it many of these settings are lost, since
 * the device reverts to system-default settings. By calling
 * term_replace, you conceptually _maintain_ the old (pre-close)
 * settings to the new (post-open) filedes.
 */
int term_replace(int oldfd, int newfd);

/*
 * F term_apply
 *
 * Applies the settings stored in the "nexttermios" structure
 * associated with the managed filedes "fd", to the respective
 * terminal device.  It then re-reads the settings form the device and
 * stores them in "nexttermios". Finally it copies "nexttermios" to
 * "currtermios". If "now" is not zero, settings are applied
 * immediatelly, otherwise setting are applied after the output
 * buffers are drained and the input buffers are discarder. In this
 * sense, term_apply(fd, 0) is equivalent to: term_drain(fd);
 * term_flush(fd); term_apply(fd, 1);
 *
 * Returns negative on failure, non negative on success. In case of
 * failure the "nexttermios" and "currtermios" structures are not
 * affected.
 */
int term_apply(int fd, int now);

/*
 * F term_revert
 *
 * Discards all the changes made to the nexttermios structure
 * associated with the managed filedes "fd" that have not been applied
 * to the device. It does this by copying currtermios to nexttermios.
 *
 * Returns negative on failure, non negative on success. Returns
 * failure only to indicate invalid arguments, so the return value can
 * be safely ignored.
 */
int term_revert(int fd);

/* F term_reset
 *
 * Reset the terminal device associated with the managed filedes "fd"
 * to its "original" settings. This function applies the settings in
 * the "origtermios" structure to the actual device. It then reads the
 * settings from the device and stores them in both the "currtermios"
 * and "nexttermios" stuctures.
 *
 * Returns negative on failure, non-negative of success. On failure
 * the the "origtermios", "currtermios", and "nexttermios" stuctures
 * associated with the filedes remain unaffected.
 */
int term_reset(int fd);

/*
 * F term_refresh
 *
 * Updates the contents of the currtermios structure associated with
 * the managed filedes "fd", by reading the settings from the
 * respective terminal device.
 *
 * Returns negative on failure, non negative on success. On failure
 * the currtermios structure remains unaffected.
 */
int term_refresh(int fd);

/* F term_set_raw
 *
 * Sets the "nexttermios" structure associated with the managed
 * filedes "fd" to raw mode. The effective settings of the device are
 * not affected by this function.
 *
 * Returns negative on failure, non-negative on success. Returns
 * failure only to indicate invalid arguments, so the return value can
 * be safely ignored.
 *
 * When in raw mode, no characters are processed by the terminal
 * driver and there is no line-discipline or buffering. More
 * technically setting to raw mode means, affecting the following
 * terminal settings as indicated:
 *
 *   -ignbrk -brkint -parmrk -istrip -inlcr -igncr -icrnl -ixon
 *   -opost -echo -echonl -icannon -isig -iexten -csize -parenb
 *   cs8 min=1 time=0
 */
int term_set_raw(int fd);

/* F term_set_baudrate
 *
 * Sets the baudrate in the "nexttermios" structure associated with
 * the managed filedes "fd" to "baudrate". The effective settings of
 * the device are not affected by this function.
 *
 * Supported baudrates: 0, 50, 75, 110, 134, 150, 200, 300, 600, 1200,
 *   1800, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400
 *
 * Returns negative on failure, non negative on success. Returns
 * failure only to indicate invalid arguments, so the return value can
 * be safely ignored.
 */
int term_set_baudrate(int fd, int baudrate);

/* F term_set_parity
 *
 * Sets the parity mode in the "nexttermios" structure associated with
 * the managed filedes "fd" to "parity". The effective settings of the
 * device are not affected by this function.
 *
 * Supported parity modes are: p_even, p_odd, p_none.
 *
 * Returns negative on failure, non negative on success. Returns
 * failure only to indicate invalid arguments, so the return value can
 * be safely ignored.
 */
int term_set_parity(int fd, enum parity_e parity);

/* F term_set_databits
 *
 * Sets the databits number in the "nexttermios" structure associated
 * with the managed filedes "fd" to "databits". The effective settings
 * of the device are not affected by this function.
 *
 * 5, 6, 7, and 8 databits are supported by the library.
 *
 * Returns negative on failure, non negative on success. Returns
 * failure only to indicate invalid arguments, so the return value can
 * be safely ignored.
 */
int term_set_databits(int fd, int databits);

/* F term_set_stopbits
 *
 * Sets the stopbits number in the "nexttermios" structure associated
 * with the managed filedes "fd" to "stopbits". The effective settings
 * of the device are not affected by this function.
 *
 * 1 and 2 stopbits are supported by the library.
 *
 * Returns negative on failure, non negative on success. Returns
 * failure only to indicate invalid arguments, so the return value can
 * be safely ignored.
 */
int term_set_stopbits(int fd, int stopbits);

/* F term_set_flowcntrl
 *
 * Sets the folwcontrol mode in the "nexttermios" structure associated
 * with the managed filedes "fd" to "flowcntl". The effective settings
 * of the device are not affected by this function.
 *
 * The following flow control modes are supportd by the library:
 * FC_NONE, FC_RTSCTS, FC_XONXOFF.
 *
 * Returns negative on failure, non negative on success. Returns
 * failure only to indicate invalid arguments, so the return value can
 * be safely ignored.
 */
int term_set_flowcntrl(int fd, enum flowcntrl_e flowcntl);

/* F term_set_hupcl
 *
 * Enables ("on" = nonzero) or disables ("on" = zero) the
 * "HUP-on-close" setting in the "nexttermios" structure associated
 * with the managed filedes "fd". The effective settings of the device
 * are not affected by this function.
 *
 * Returns negative on failure, non negative on success. Returns
 * failure only to indicate invalid arguments, so the return value can
 * be safely ignored.
 */
int term_set_hupcl(int fd, int on);

/* F term_set_local.
 *
 * Enables ("local" = nonzero) or disables ("local" = zero) the
 * "local-mode" setting in the "nexttermios" structure associated with
 * the managed filedes "fd". The effective settings of the device are
 * not affected by this function.
 *
 * Returns negative on failure, non negative on success. Returns
 * failure only to indicate invalid arguments, so the return value can
 * be safely ignored.
 */
int term_set_local(int fd, int local);

/* F temr_set
 *
 * Sets most of the parameters in the "nexttermios" structure
 * associated with the managed filedes "fd". Actually sets the
 * following:
 *
 *   Raw mode if "raw" is nonzero.
 *   Baudrate to "baud".
 *   Parity mode to "parity".
 *   Flow control mode to "fc".
 *   Enables local mode if "local" is nonzero, dis. otherwise.
 *   Enables HUP-on-close if "hupcl" is nonzero, dis. otherwise
 *
 * The effective settings of the device are not affected by this
 * function. Additionally if the filedes "fd" is not managed, it is
 * added to the framework.
 *
 * Returns negative on failure, non negative on success. On failure
 * none of the settings of "nexttermios" is affected. *If* the filedes
 * "fd" is already in the framework, then the function returns failure
 * only to indicate invalid arguments, so, in this case, the return
 * value can be safely ignored. If the function successfully adds the
 * filedes to the framework, and following this it fails, then it will
 * remove the filedes before returning.
 */
int term_set(int fd, int raw, int baud, enum parity_e parity, int databits,
             int stopbits, enum flowcntrl_e fc, int local, int hupcl);

/* F term_get_baudrate
 *
 * Reads and decodes the current baudrate settings in the
 * "currtermios" structure of the managed filedes "fd".
 *
 * Returns the decoded output baudrate (as bits-per-second), or -1 if
 * the output baudrate cannot be decoded, or if "fd" does not
 * correspond to a managed filedes. If "ispeed" is not NULL, it writes
 * the decoded input baudrate to the integer pointed-to by "ispeed";
 * if the input baudrate cannot be decoded in writes -1 instead.
 */
int term_get_baudrate(int fd, int *ispeed);

/* F term_get_parity
 *
 * Reads and decodes the current parity settings in the
 * "currtermios" structure of the managed filedes "fd".
 *
 * Returns one of the "enum parity_e" members. Returns P_ERROR if "fd"
 * does not correspond to a managed filedes.
 */
enum parity_e term_get_parity(int fd);

/* F term_get_databits
 *
 * Reads and decodes the current databits settings in the
 * "currtermios" structure of the managed filedes "fd".
 *
 * Returns the number of databits (5..8), or -1 if "fd" does not
 * correspond to a managed filedes.
 */
int term_get_databits(int fd);

/* F term_get_stopbits
 *
 * Reads and decodes the current stopbits settings in the
 * "currtermios" structure of the managed filedes "fd".
 *
 * Returns the number of databits (1 or 2), or -1 if "fd" does not
 * correspond to a managed filedes.
 */
int term_get_stopbits(int fd);

/* F term_get_flowcntrl
 *
 * Reads and decodes the current flow-control settings in the
 * "currtermios" structure of the managed filedes "fd".
 *
 * Returns one of the "enum flowcntrl_e" members. Returns FC_ERROR if
 * "fd" does not correspond to a managed filedes.
 */
enum flowcntrl_e term_get_flowcntrl(int fd);

/* F term_pulse_dtr
 *
 * Pulses the DTR line of the device associated with the managed
 * filedes "fd". The DTR line is lowered for 1sec and then raised
 * again.
 *
 * Returns negative on failure, non negative on success.
 */
int term_pulse_dtr(int fd);

/* F term_lower_dtr
 *
 * Lowers the DTR line of the device associated with the managed
 * filedes "fd".
 *
 * Returns negative on failure, non negative on success.
 */
int term_lower_dtr(int fd);

/* F term_raise_dtr
 *
 * Raises the DTR line of the device associated with the managed
 * filedes "fd".
 *
 * Returns negative on failure, non negative on success.
 */
int term_raise_dtr(int fd);

/* F term_lower_rts
 *
 * Lowers the RTS line of the device associated with the managed
 * filedes "fd".
 *
 * Returns negative on failure, non negative on success.
 */
int term_lower_rts(int fd);

/* F term_raise_rts
 *
 * Raises the RTS line of the device associated with the managed
 * filedes "fd".
 *
 * Returns negative on failure, non negative on success.
 */
int term_raise_rts(int fd);

/* F term_get_mctl
 *
 * Get the status of the modem control lines of the serial port
 * (terminal) associated with the managed filedes "fd".
 *
 * On error (fd is not managed) return a negative. If the feature is
 * not available returns MCTL_UNAVAIL. Otherwise returns a word that
 * can be checked against the MCTL_* flags.
 */
int term_get_mctl(int fd);

/* F term_drain
 *
 * Drains (flushes) the output queue of the device associated with the
 * managed filedes "fd". This functions blocks until all the contents
 * of output queue have been transmited.
 *
 * Returns negative on failure, non negative on success.
 */
int term_drain(int fd);

/* F term_flush
 *
 * Discards all the contents of the input AND output queues of the
 * device associated with the managed filedes "fd". Although it is
 * called flush this functions does NOT FLUSHES the terminal
 * queues. It just DISCARDS their contents. The name has stuck from
 * the POSIX terminal call: "tcflush".
 *
 * Returns negative on failure, non negative on success.
 */
int term_flush(int fd);

/* F term_fake_flush
 *
 * Fake a term_flush, by temporarily configuring the device associated
 * with the managed fd to no flow-control and waiting until its output
 * queue drains.
 *
 * Returns negative on failure, non-negative on success.
 */
int term_fake_flush(int fd);

/* F term_break
 *
 * This function generates a break condition on the device associated
 * with the managed filedes "fd", by transmiting a stream of
 * zero-bits. The stream of zero-bits has a duriation typically
 * between 0.25 and 0.5 seconds.
 *
 * Returns negative on failure, non negative on success.
 */
int term_break(int fd);

/***************************************************************************/

/* F term_baud_up
 *
 * Returns the next higher valid baudrate. Returns "baud" if there is
 * no higher valid baudrate.
 */
int term_baud_up(int baud);

/* F term_baud_down
 *
 * Returns the next lower valid baudrate. Returns "baud" if there is
 * no lower valid baudrate.
 */
int term_baud_down(int baud);

/* F term_baud_ok
 *
 * Returns non-zero if "baud" is a valid baudrate, zero otherwise.
 */
int term_baud_ok(int baud);

/* F term_baud_std
 *
 * Returns non-zero if "baud" is a standard baudrate, zero otherwise.
 */
int term_baud_std(int baud);

/***************************************************************************/

#endif /* of TERM_H */

/***************************************************************************/

/*
 * Local Variables:
 * mode:c
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 */

/* vi: set sw=4 ts=4:
 *
 * custbaud.h
 *
 * Automatically enable custom baudrate support for systems (OS /
 * version / architecture combinations) we know it works.
 *
 * by Nick Patavalis (npat@efault.net)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */

#ifndef CUSTBAUD_H
#define CUSTBAUD_H

#include <termios.h>

#ifndef NO_CUSTOM_BAUD

#if defined(__linux__)

/* Enable by-default for kernels > 2.6.0 on x86 and x86_64 only */
#include <linux/version.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 0)
/* Some libc implementations (e.g. musl) do not define the cispeed and
   cospeed struct termios fields. We do not support custom baudrates
   on them. */
#if ((defined(__i386__) || defined(__x86_64__)) &&                             \
     defined(_HAVE_STRUCT_TERMIOS_C_ISPEED) &&                                 \
     defined(_HAVE_STRUCT_TERMIOS_C_OSPEED)) ||                                \
    defined(USE_CUSTOM_BAUD)
#ifndef USE_CUSTOM_BAUD
#define USE_CUSTOM_BAUD
#endif
#endif /* of arch */
#endif /* of version */

#elif defined(__APPLE__) && defined(__MACH__)

#include <AvailabilityMacros.h>
#include <TargetConditionals.h>
#if TARGET_IPHONE_SIMULATOR
/* Do not enable by default for iOS in Xcode simulator */
#elif TARGET_OS_IPHONE
/* Do not enable by default for iOS until it has been tested */
#elif TARGET_OS_MAC
#if defined(__i386__) || defined(__x86_64__)
/* Enable by-default for Intel Mac, macOS / OSX >= 10.4 (Tiger) */
#ifndef USE_CUSTOM_BAUD
#define USE_CUSTOM_BAUD
#endif
#endif /* of arch */
#endif /* of TARGET_OS_... */

#elif defined(__NetBSD__)

/* Do not enable by default */
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)

/* I believe it doesn't hurt to enable by-default for these */
#ifndef USE_CUSTOM_BAUD
#define USE_CUSTOM_BAUD
#endif

#elif defined(USE_CUSTOM_BAUD)

#error "USE_CUSTOM_BAUD not supported on this system!"

#endif /* of platforms */

#else /* of ndef NO_CUSTOM_BAUD */

#ifdef USE_CUSTOM_BAUD
#undef USE_CUSTOM_BAUD
#endif

#endif /* of ndef NO_CUSTOM_BAUD else */

static int use_custom_baud();
int cfsetispeed_custom(struct termios *tios, int speed);
int cfsetospeed_custom(struct termios *tios, int speed);
int cfgetispeed_custom(const struct termios *tios);
int cfgetospeed_custom(const struct termios *tios);

#endif /* CUSTBAUD_H */

/*
 * custbaud_bsd.h
 *
 * Custom baud rate support for BSD and macOS.
 *
 * by Joe Merten (https://github.com/JoeMerten www.jme.de)
 *
 * ATTENTION: BSD and macOS specific stuff!
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */

#ifndef CUSTBAUD_BSD_H
#define CUSTBAUD_BSD_H

#include <termios.h>

/***************************************************************************/

/* macOS termios.h unfortunately just provides constants for baudrates
 * up to 230k, so we add the missing constants here. Regardless, that
 * most of the high baudrates needs special handling (implementation in
 * tcsetattr_custom()), we want to provide the values here to have them
 * available for term_baud_up()/down().
 *
 * FreeBSD 11.0 termios.h has 460k and 921k but misses e.g. 500k and >=1M.
 * OpenBSD 6.2 termios.h is missing all >230k (like macOS).
 * NetBSD 7.1.1 do same as FreeBSD 11.0.
 * DragonFly 5.0.2 looks same as OpenBSD 6.2.
 */

#if defined(HIGH_BAUD)

#ifndef B460800
#define B460800 460800
#endif
#ifndef B500000
#define B500000 500000
#endif
#ifndef B576000
#define B576000 576000
#endif
#ifndef B921600
#define B921600 921600
#endif
#ifndef B1000000
#define B1000000 1000000
#endif
#ifndef B1152000
#define B1152000 1152000
#endif
#ifndef B1500000
#define B1500000 1500000
#endif
#ifndef B2000000
#define B2000000 2000000
#endif
#ifndef B2500000
#define B2500000 2500000
#endif
#ifndef B3000000
#define B3000000 3000000
#endif
#ifndef B3500000
#define B3500000 3500000
#endif
#ifndef B4000000
#define B4000000 4000000
#endif

#endif /* HIGH_BAUD */

/***************************************************************************/

int cfsetospeed_custom(struct termios *tiop, int speed);
int cfsetispeed_custom(struct termios *tiop, int speed);
int cfgetospeed_custom(const struct termios *tiop);
int cfgetispeed_custom(const struct termios *tiop);

/***************************************************************************/

#ifdef __APPLE__
/* Replace tcsetattr function with our macOS specific one */
#define tcsetattr tcsetattr_custom
int tcsetattr_custom(int fd, int optional_actions, const struct termios *tiop);
#endif

/***************************************************************************/

#endif /* CUSTBAUD_BSD_H */

/**************************************************************************/

/*
 * Local Variables:
 * mode:c
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 */
/*
 * custbaud_bsd.c
 *
 * Custom baud rate support for BSD and macOS.
 *
 * by Joe Merten (https://github.com/JoeMerten www.jme.de)
 *
 * ATTENTION: BSD and macOS specific stuff!
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */

/***************************************************************************/
/* Known issues:
 * - FT232H 12MBaud not working
 *   - using OSX El Capitan 10.11.6, FTDIUSBSerialDriver_v2_3.dmg
 *   - tried with 2 different chips (FT232H and FT2232H)
 *   Testing with Ftdi FT232H, which is capable to use up to 12MBaud, only
 *   line speed up to 3MBaud were accepted. For higher baudrates we earn
 *   a failure in the ioctl(IOSSIOSPEED) call.
 *   But as `python -m serial.tools.miniterm` shows the same behaviour, it
 *   looks that this is a bug or limitation in OSX and/or Ftdi driver.
 *   Trying with PL2303 (driver version PL2303_MacOSX_1.6.1_20160309.zip),
 *   baudrates up to 6MBaud were accepted.
 *   - Have not tested with more recent macOS or Ftdi driver until now.
 */

/* Note that this code might also work with other BSD variants, but I have only
 * tested with those listed below. Also tested __NetBSD__ but won't work. */
#if (defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) ||    \
     defined(__DragonFly__) || defined(__APPLE__)) &&                          \
    defined(USE_CUSTOM_BAUD)

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#ifdef __APPLE__
#include <IOKit/serial/ioss.h>
#endif

/***************************************************************************/
/* As we can see in BSD and macOS termios.h all the baudrate constants are
 * transparent, like B115200=115200. There is no need for any integer <-> code
 * translation. So we can pass any baudrate we want directly to / from
 * cfsetospeed() & co.
 */
int cfsetospeed_custom(struct termios *tiop, int speed) {
  return cfsetospeed(tiop, speed);
}

int cfsetispeed_custom(struct termios *tiop, int speed) {
  return cfsetispeed(tiop, speed);
}

int cfgetospeed_custom(const struct termios *tiop) { return cfgetospeed(tiop); }

int cfgetispeed_custom(const struct termios *tiop) { return cfgetispeed(tiop); }

#ifdef __APPLE__
/***************************************************************************/
/* Need to undef tcsetattr to get access to the original tcsetattr()
 * function inside our module.
 */
#undef tcsetattr

/***************************************************************************/
/* The strategy of picocom's terminal handling library is to hold all the
 * terminal settings (including baudrate) using termios struct.
 * Problem on macOS is, that tcsetattr() will fail if termios contains an
 * unusual baudrate (like e.g. 12345 of 12M), The official macOS way to apply
 * those baudrates is to use ioctl(IOSSIOSPEED) instead.
 * Our workaround strategy is:
 * - set the baudrate stored in termios back to a standard value (e.g. 9600)
 * - call tcsetattr() to apply all the rest termios data to the fd
 * - and then applying the real desired baudrate to the fd by calling
 * ioctl(IOSSIOSPEED) Note, that in case of failed ioctl(IOSSIOSPEED), our 9600
 * staying configured at the fd.
 */
int tcsetattr_custom(int fd, int optional_actions, const struct termios *tiop) {
  int r;
  int workaround = 0;
  int baudrate;
  struct termios tios = *tiop;
  struct termios tio0;
  int baudrate0;

  if (fd >= 3) { /* don't apply this workaround for stdin/stdout/stderr */
    baudrate = cfgetospeed(&tios);
    if (baudrate > 460800 || !term_baud_std(baudrate)) {
      /* save fd's current termios to recover in case of later falure */
      r = tcgetattr(fd, &tio0);
      if (r < 0)
        return -1;
      baudrate0 = cfgetospeed(&tio0);
      /* now temporarily switching baudrate back to 9600 */
      r = cfsetspeed(&tios, B9600);
      if (r < 0)
        return -1;
      workaround = 1;
    }
  }

  r = tcsetattr(fd, optional_actions, &tios);
  if (r < 0)
    return -1;

  if (workaround) {
    r = ioctl(fd, IOSSIOSPEED, &baudrate);
    /*if ( r < 0 ) fprintf(stderr, "%s: ioctl(%d, %d) = %d, optional_actions =
     * %d, %s\r\n", __FUNCTION__, fd, baudrate, r, optional_actions,
     * strerror(errno));*/
    if (r < 0) {
      /* ioctl() failed, so we try to restore the fd to the old termios data */
      r = cfsetspeed(&tio0, B9600);
      /*if ( r < 0 ) fprintf(stderr, "%s: cfsetspeed() = %d, %s\r\n",
       * __FUNCTION__, r, strerror(errno));*/
      if (r < 0)
        return -1;
      r = tcsetattr(fd, optional_actions, &tio0);
      /*if ( r < 0 ) fprintf(stderr, "%s: tcsetattr() = %d, %s\r\n",
       * __FUNCTION__, r, strerror(errno));*/
      if (r < 0)
        return -1;
      r = ioctl(fd, IOSSIOSPEED, &baudrate0);
      /*if ( r < 0 ) fprintf(stderr, "%s: ioctl(%d) = %d, %s\r\n", __FUNCTION__,
       * baudrate0, r, strerror(errno));*/
      return -1;
    }
  }

  return 0;
}
#endif /*__APPLE__ */

/***************************************************************************/

#endif /* __FreeBSD__ || ... || __APPLE__ && USE_CUSTOM_BAUD */

/* vi: set sw=4 ts=4:
 *
 * custbaud.c
 *
 * by Nick Patavalis (npat@efault.net)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef USE_CUSTOM_BAUD

int use_custom_baud() { return 0; }

int cfsetispeed_custom(struct termios *tios, int speed) {
  errno = EINVAL;
  return -1;
}
int cfsetospeed_custom(struct termios *tios, int speed) {
  errno = EINVAL;
  return -1;
}
int cfgetispeed_custom(const struct termios *tios) {
  errno = EINVAL;
  return -1;
}
int cfgetospeed_custom(const struct termios *tios) {
  errno = EINVAL;
  return -1;
}

#else /* USE_CUSTOM_BAUD */

static int use_custom_baud() {
#ifdef __linux__
  static int use = -1;
  if (use < 0)
    use = getenv("NO_CUSTOM_BAUD") ? 0 : 1;
  return use;
#else
  return 1;
#endif
}

#endif

/**************************************************************************/

/*
 * Local Variables:
 * mode:c
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 */

/*
 * termios2.h
 *
 * Use termios2 interface to set custom baud rates to serial ports.
 *
 * by Nick Patavalis (npat@efault.net)
 *
 * ATTENTION: Linux-specific kludge!
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */

#ifndef TERMIOS2_H
#define TERMIOS2_H

#include <termios.h>

/* Replace termios functions, with termios2 functions */
#define tcsetattr tc2setattr
#define tcgetattr tc2getattr
#define cfsetispeed cf2setispeed
#define cfgetispeed cf2getispeed

/* And define these new ones */
#define cfsetospeed_custom cf2setospeed_custom
#define cfsetispeed_custom cf2setispeed_custom
#define cfgetospeed_custom(tiop) ((tiop)->c_ospeed)
#define cfgetispeed_custom(tiop) ((tiop)->c_ispeed)

/* Replacements for the standard tcsetattr(3), tcgetattr(3)
 * functions. Same user interface, but these use the new termios2
 * kernel interface (new ioctl's) which allow custom baud-rate
 * setting. */

int tc2setattr(int fd, int optional_actions, const struct termios *tios);
int tc2getattr(int fd, struct termios *tios);

/* Replacements for the standard cfgetispeed(3), cfsetispeed(3)
 * functions. Use these to set / get standard *input* baudrates. You
 * can still use cfgetospeed(3), cfsetospeed(3) to set / get the
 * standard output baudrates. The new termios2 interface, unlike the
 * old one, supports different input and output speeds for a
 * device. The "speed" argument must be (and the return value will be)
 * one of the standard "Bxxxx" macros. If cf2getispeed() or
 * cfgetospeed(3) return BOTHER, then the respective baudrate is a
 * custom one. Read the "termios.c_ispeed" / "termios.c_ospeed" fields
 * to get the custom value (as a numeric speed). */

int cf2setispeed(struct termios *tios, speed_t speed);
speed_t cf2getispeed(const struct termios *tios);

/* Use these to set *custom* input and output baudrates for a
 * device. The "speed" argument must be a numeric baudrate value
 * (e.g. 1234 for 1234 bps). */

int cf2setispeed_custom(struct termios *tios, int speed);
int cf2setospeed_custom(struct termios *tios, int speed);

/***************************************************************************/

#endif /* of TERMIOS2_H */

/***************************************************************************/

/*
 * Local Variables:
 * mode:c
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 */

#if defined(__linux__) && defined(USE_CUSTOM_BAUD)

#include <linux/version.h>
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 0)
#error "This code requires Linux kernel > 2.6!"
#endif

#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

/* Contains the definition of the termios2 structure and some related
   constants that we should normally include from system
   headers. Unfortunatelly, we can't. See comments in "termbits2.h"
   for more. */

/*
 * termbits2.c
 *
 * Stuff that we should include from kernel sources, if we could; but
 * we can't. Included from "termios2.h"
 *
 * by Nick Patavalis (npat@efault.net)
 *
 * ATTENTION: Linux-specific kludge!
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */

#ifndef TERMBITS2_H
#define TERMBITS2_H

#ifndef __linux__
#error "Linux specific code!"
#endif

/* We need tcflag_t, cc_t, speed_t, CBAUDEX, etc */
#include <termios.h>

/* These definitions must correspond to the kernel structures as
   defined in:

     <linux-kernel>/arch/<arch>/include/uapi/asm/termbits.h
     or <linux-kernel>/include/uapi/asm-generic/termbits.h

   which are the same as:

     /usr/include/<arch>/asm/termbits.h
     or /usr/include/asm-generic/termbits.h

  Unfortunatelly, we cannot just include <asm/termbits.h> or
  <asm/termios.h> or <linux/termios.h> (all would do the trick)
  because then "struct termios" would be re-defined to the kernel
  version, which is not the same as the libc version. In effect, you
  cannot both include <termios.h> and <linux/termios.h> because both
  define a "struct termios" which may or maynot be the same. We want
  our "struct termios" here to be the libc version (as defined in
  <termios.h>), because that's what our callers use. As a result we
  cannot get the definion of "struct termios2" from the above header
  files, since this would also bring-in the clashing definition of the
  kernel version of "struct termios". If you have an idea for a better
  way out of this mess, I would REALLY like to hear it.

  I hope that soon GLIBC will pick-up termios2 and all these will be
  useless. Until then ...

  ATTENTION: For most architectures "struct termios2" and the
  associated constants we care about (NCCS, BOTHER, IBSHIFT) are the
  same. For some there are small differences, and some architectures
  do not support termios2 at all. I don't claim to have done a
  thorough job figuring out the specifics for every architecture, so
  your milleage may vary. In any case, if you want support for
  something that's missing, just copy the relevant definitions from
  the kernel header file in here, recompile, test, and send me a
  patch. */

#if defined(__alpha__)

#error "Architecure has no termios2 support"

#elif defined(__powerpc__) || defined(__powerpc64__)

#define K_NCCS 19
/* The "old" termios is the same with termios2 for powerpc's */
struct termios2 {
  tcflag_t c_iflag;  /* input mode flags */
  tcflag_t c_oflag;  /* output mode flags */
  tcflag_t c_cflag;  /* control mode flags */
  tcflag_t c_lflag;  /* local mode flags */
  cc_t c_cc[K_NCCS]; /* control characters */
  cc_t c_line;       /* line discipline */
  speed_t c_ispeed;  /* input speed */
  speed_t c_ospeed;  /* output speed */
};

#define BOTHER 00037
#define IBSHIFT 16

/* powerpc ioctl numbers have the argument-size encoded. Make sure we
   use the correct structure (i.e. kernel termios, not LIBC termios)
   when calculating them. */
#define IOCTL_SETS _IOW('t', 20, struct termios2)
#define IOCTL_SETSW _IOW('t', 21, struct termios2)
#define IOCTL_SETSF _IOW('t', 22, struct termios2)
#define IOCTL_GETS _IOR('t', 19, struct termios2)

#elif defined(__mips__)

#define K_NCCS 23
struct termios2 {
  tcflag_t c_iflag;  /* input mode flags */
  tcflag_t c_oflag;  /* output mode flags */
  tcflag_t c_cflag;  /* control mode flags */
  tcflag_t c_lflag;  /* local mode flags */
  cc_t c_line;       /* line discipline */
  cc_t c_cc[K_NCCS]; /* control characters */
  speed_t c_ispeed;  /* input speed */
  speed_t c_ospeed;  /* output speed */
};

#define BOTHER CBAUDEX
#define IBSHIFT 16

#define IOCTL_SETS TCSETS2
#define IOCTL_SETSW TCSETSW2
#define IOCTL_SETSF TCSETSF2
#define IOCTL_GETS TCGETS2

#else /* All others */

#define K_NCCS 19
struct termios2 {
  tcflag_t c_iflag;  /* input mode flags */
  tcflag_t c_oflag;  /* output mode flags */
  tcflag_t c_cflag;  /* control mode flags */
  tcflag_t c_lflag;  /* local mode flags */
  cc_t c_line;       /* line discipline */
  cc_t c_cc[K_NCCS]; /* control characters */
  speed_t c_ispeed;  /* input speed */
  speed_t c_ospeed;  /* output speed */
};

#define BOTHER CBAUDEX
#define IBSHIFT 16

#define IOCTL_SETS TCSETS2
#define IOCTL_SETSW TCSETSW2
#define IOCTL_SETSF TCSETSF2
#define IOCTL_GETS TCGETS2

#endif /* of architectures */

/***************************************************************************/

#endif /* of TERMBITS2_H */

/***************************************************************************/

/*
 * Local Variables:
 * mode:c
 * tab-width: 4
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

/* GLIBC termios use an (otherwise unused) bit in c_iflags to
   internally record the fact that ispeed was set to zero (which is
   special behavior and means "same as ospeed". We want to clear this
   bit before passing c_iflags back to the kernel. See:

       <glibc-source>/sysdeps/unix/sysv/linux/speed.c
*/
#define IBAUD0 020000000000

int tc2setattr(int fd, int optional_actions, const struct termios *tios) {
  struct termios2 t2;
  int cmd;

  if (!use_custom_baud())
    return tcsetattr(fd, optional_actions, tios);

  switch (optional_actions) {
  case TCSANOW:
    cmd = IOCTL_SETS;
    break;
  case TCSADRAIN:
    cmd = IOCTL_SETSW;
    break;
  case TCSAFLUSH:
    cmd = IOCTL_SETSF;
    break;
  default:
    errno = EINVAL;
    return -1;
  }

  t2.c_iflag = tios->c_iflag & ~IBAUD0;
  t2.c_oflag = tios->c_oflag;
  t2.c_cflag = tios->c_cflag;
  t2.c_lflag = tios->c_lflag;
  t2.c_line = tios->c_line;
  t2.c_ispeed = tios->c_ispeed;
  t2.c_ospeed = tios->c_ospeed;
  memcpy(&t2.c_cc[0], &tios->c_cc[0], K_NCCS * sizeof(cc_t));

  return ioctl(fd, cmd, &t2);
}

int tc2getattr(int fd, struct termios *tios) {
  struct termios2 t2;
  size_t i;
  int r;

  if (!use_custom_baud())
    return tcgetattr(fd, tios);

  r = ioctl(fd, IOCTL_GETS, &t2);
  if (r < 0)
    return r;

  tios->c_iflag = t2.c_iflag;
  tios->c_oflag = t2.c_oflag;
  tios->c_cflag = t2.c_cflag;
  tios->c_lflag = t2.c_lflag;
  tios->c_line = t2.c_line;
  tios->c_ispeed = t2.c_ispeed;
  tios->c_ospeed = t2.c_ospeed;
  memcpy(&tios->c_cc[0], &t2.c_cc[0], K_NCCS * sizeof(cc_t));

  for (i = K_NCCS; i < NCCS; i++)
    tios->c_cc[i] = _POSIX_VDISABLE;

  return 0;
}

/* The termios2 interface supports separate input and output
   speeds. GLIBC's termios support only one terminal speed. So the
   standard tcsetispeed(3), actually sets the output-speed field, not
   the input-speed field (or does nothing if speed == B0). Use
   cf2setispeed if you want to set a *standard* input speed (one of
   the Bxxxxx speeds) that may be different from the output
   speed. Also if someone, somehow, has set the input speed to
   something other than B0, then you *must* use cf2setispeed() to
   change it. Using the standard cfsetispeed() obviously won't do
   (since it affects only the output-speed field).
*/

int cf2setispeed(struct termios *tios, speed_t speed) {

  if (!use_custom_baud())
    return cfsetispeed(tios, speed);

  if ((speed & ~CBAUD) != 0 && (speed < B57600 || speed > __MAX_BAUD)) {
    errno = EINVAL;
    return -1;
  }
  tios->c_ispeed = speed;
  tios->c_cflag &= ~((CBAUD | CBAUDEX) << IBSHIFT);
  tios->c_cflag |= (speed << IBSHIFT);

  return 0;
}

speed_t cf2getispeed(const struct termios *tios) {
  if (!use_custom_baud())
    return cfgetispeed(tios);

  return (tios->c_cflag >> IBSHIFT) & (CBAUD | CBAUDEX);
}

/* Use these to set custom input or output speeds (i.e. speeds that do
   not necessarily correspond to one of the Bxxx macros. */

int cf2setospeed_custom(struct termios *tios, int speed) {
  if (!use_custom_baud()) {
    errno = EINVAL;
    return -1;
  }

  if (speed <= 0) {
    errno = EINVAL;
    return -1;
  }
  tios->c_cflag &= ~(CBAUD | CBAUDEX);
  tios->c_cflag |= BOTHER;
  tios->c_ospeed = speed;

  return 0;
}

int cf2setispeed_custom(struct termios *tios, int speed) {
  if (!use_custom_baud()) {
    errno = EINVAL;
    return -1;
  }

  if (speed < 0) {
    errno = EINVAL;
    return -1;
  }
  if (speed == 0) {
    /* Special case: ispeed == 0 means "same as ospeed". Kernel
       does this if it sees B0 in the "CIBAUD" field (i.e. in
       CBAUD << IBSHIFT) */
    tios->c_cflag &= ~((CBAUD | CBAUDEX) << IBSHIFT);
    tios->c_cflag |= (B0 << IBSHIFT);
  } else {
    tios->c_cflag &= ~((CBAUD | CBAUDEX) << IBSHIFT);
    tios->c_cflag |= (BOTHER << IBSHIFT);
    tios->c_ispeed = speed;
  }

  return 0;
}

/***************************************************************************/

#endif /* __linux__ && USE_CUSTOM_BAUD */

/*
 * Local Variables:
 * mode:c
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 */

/* vi: set sw=4 ts=4:
 *
 * term.c
 *
 * General purpose terminal handling library.
 *
 * by Nick Patavalis (npat@efault.net)
 *
 * originaly by Pantelis Antoniou (https://github.com/pantoniou),
 *              Nick Patavalis
 *
 * Documentation can be found in the header file "term.h".
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 * $Id$
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#ifdef USE_FLOCK
#include <sys/file.h>
#endif

/* glibc for MIPS has its own bits/termios.h which does not define
 * CMSPAR, so we use the value from the generic bits/termios.h
 */
#ifdef __linux__
#ifndef CMSPAR
#define CMSPAR 010000000000
#endif
#endif

/* Some BSDs (and possibly other systems too) have no mark / space
 * parity support, and they don't define CMSPAR. Use a zero CMSPAR in
 * these cases. If the user tries to set P_MARK or P_SPACE he will get
 * P_EVEN or P_ODD instead. */
#ifndef CMSPAR
#define CMSPAR 0
#endif

/* On these systems, use the TIOCM[BIS|BIC|GET] ioctls to manipulate
 * the modem control lines (DTR / RTS) */
#if defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||      \
    defined(__NetBSD__) || defined(__DragonFly__) || defined(__APPLE__)
#define USE_IOCTL
#endif
#ifdef USE_IOCTL
#include <sys/ioctl.h>
#endif

/* Time to wait for UART to clear after a drain (in usec). */
#define DRAIN_DELAY 200000

/***************************************************************************/

static struct term_s {
  int init;
  int fd[MAX_TERMS];
  struct termios origtermios[MAX_TERMS];
  struct termios currtermios[MAX_TERMS];
  struct termios nexttermios[MAX_TERMS];
} term;

/***************************************************************************/

int term_errno;

static const char *const term_err_str[] = {
    [TERM_EOK] = "No error",
    [TERM_ENOINIT] = "Framework is uninitialized",
    [TERM_EFULL] = "Framework is full",
    [TERM_ENOTFOUND] = "Filedes not in the framework",
    [TERM_EEXISTS] = "Filedes already in the framework",
    [TERM_EATEXIT] = "Cannot install atexit handler",
    [TERM_EISATTY] = "Filedes is not a tty",
    [TERM_EFLUSH] = "Cannot flush the device",
    [TERM_EGETATTR] = "Cannot get the device attributes",
    [TERM_ESETATTR] = "Cannot set the device attributes",
    [TERM_EBAUD] = "Invalid baud rate",
    [TERM_ESETOSPEED] = "Cannot set the output speed",
    [TERM_ESETISPEED] = "Cannot set the input speed",
    [TERM_EGETSPEED] = "Cannot decode speed",
    [TERM_EPARITY] = "Invalid parity mode",
    [TERM_EDATABITS] = "Invalid number of databits",
    [TERM_ESTOPBITS] = "Invalid number of stopbits",
    [TERM_EFLOW] = "Invalid flowcontrol mode",
    [TERM_EDTRDOWN] = "Cannot lower DTR",
    [TERM_EDTRUP] = "Cannot raise DTR",
    [TERM_EMCTL] = "Cannot get mctl status",
    [TERM_EDRAIN] = "Cannot drain the device",
    [TERM_EBREAK] = "Cannot send break sequence",
    [TERM_ERTSDOWN] = "Cannot lower RTS",
    [TERM_ERTSUP] = "Cannot raise RTS"};

static char term_err_buff[1024];

const char *term_strerror(int terrnum, int errnum) {
  const char *rval;

  switch (terrnum) {
  case TERM_EFLUSH:
  case TERM_EGETATTR:
  case TERM_ESETATTR:
  case TERM_ESETOSPEED:
  case TERM_ESETISPEED:
  case TERM_EDRAIN:
  case TERM_EBREAK:
    snprintf(term_err_buff, sizeof(term_err_buff), "%s: %s",
             term_err_str[terrnum], strerror(errnum));
    rval = term_err_buff;
    break;
  case TERM_EOK:
  case TERM_ENOINIT:
  case TERM_EFULL:
  case TERM_ENOTFOUND:
  case TERM_EEXISTS:
  case TERM_EATEXIT:
  case TERM_EISATTY:
  case TERM_EBAUD:
  case TERM_EPARITY:
  case TERM_EDATABITS:
  case TERM_ESTOPBITS:
  case TERM_EFLOW:
  case TERM_EDTRDOWN:
  case TERM_EDTRUP:
  case TERM_EMCTL:
  case TERM_ERTSDOWN:
  case TERM_ERTSUP:
    snprintf(term_err_buff, sizeof(term_err_buff), "%s", term_err_str[terrnum]);
    rval = term_err_buff;
    break;
  default:
    rval = NULL;
    break;
  }

  return rval;
}

int term_perror(const char *prefix) {
  return fprintf(stderr, "%s %s\n", prefix, term_strerror(term_errno, errno));
}

/***************************************************************************/

#define BNONE 0xFFFFFFFF

struct baud_codes {
  int speed;
  speed_t code;
} baud_table[] = {
    {0, B0},
    {50, B50},
    {75, B75},
    {110, B110},
    {134, B134},
    {150, B150},
    {200, B200},
    {300, B300},
    {600, B600},
    {1200, B1200},
    {1800, B1800},
    {2400, B2400},
    {4800, B4800},
    {9600, B9600},
    {19200, B19200},
    {38400, B38400},
    {57600, B57600},
    {115200, B115200},
#ifdef HIGH_BAUD
#ifdef B230400
    {230400, B230400},
#endif
#ifdef B460800
    {460800, B460800},
#endif
#ifdef B500000
    {500000, B500000},
#endif
#ifdef B576000
    {576000, B576000},
#endif
#ifdef B921600
    {921600, B921600},
#endif
#ifdef B1000000
    {1000000, B1000000},
#endif
#ifdef B1152000
    {1152000, B1152000},
#endif
#ifdef B1500000
    {1500000, B1500000},
#endif
#ifdef B2000000
    {2000000, B2000000},
#endif
#ifdef B2500000
    {2500000, B2500000},
#endif
#ifdef B3000000
    {3000000, B3000000},
#endif
#ifdef B3500000
    {3500000, B3500000},
#endif
#ifdef B4000000
    {4000000, B4000000},
#endif
#endif /* of HIGH_BAUD */
};

#define BAUD_TABLE_SZ ((int)(sizeof(baud_table) / sizeof(baud_table[0])))

int term_baud_up(int baud) {
  int i;

  for (i = 0; i < BAUD_TABLE_SZ; i++) {
    if (baud >= baud_table[i].speed)
      continue;
    else {
      baud = baud_table[i].speed;
      break;
    }
  }

  return baud;
}

int term_baud_down(int baud) {
  int i;

  for (i = BAUD_TABLE_SZ - 1; i >= 0; i--) {
    if (baud <= baud_table[i].speed)
      continue;
    else {
      baud = baud_table[i].speed;
      break;
    }
  }

  return baud;
}

static speed_t Bcode(int speed) {
  speed_t code = BNONE;
  int i;

  for (i = 0; i < BAUD_TABLE_SZ; i++) {
    if (baud_table[i].speed == speed) {
      code = baud_table[i].code;
      break;
    }
  }
  return code;
}

static int Bspeed(speed_t code) {
  int speed = -1, i;

  for (i = 0; i < BAUD_TABLE_SZ; i++) {
    if (baud_table[i].code == code) {
      speed = baud_table[i].speed;
      break;
    }
  }
  return speed;
}

int term_baud_ok(int baud) {
  if (use_custom_baud())
    return (baud >= 0);
  else
    return (Bcode(baud) != BNONE) ? 1 : 0;
}

int term_baud_std(int baud) { return (Bcode(baud) != BNONE) ? 1 : 0; }

/**************************************************************************/

static int term_find_next_free(void) {
  int rval, i;

  do { /* dummy */
    if (!term.init) {
      term_errno = TERM_ENOINIT;
      rval = -1;
      break;
    }

    for (i = 0; i < MAX_TERMS; i++)
      if (term.fd[i] == -1)
        break;

    if (i == MAX_TERMS) {
      term_errno = TERM_EFULL;
      rval = -1;
      break;
    }

    rval = i;
  } while (0);

  return rval;
}

/***************************************************************************/

static int term_find(int fd) {
  int rval, i;

  do { /* dummy */
    if (!term.init) {
      term_errno = TERM_ENOINIT;
      rval = -1;
      break;
    }

    for (i = 0; i < MAX_TERMS; i++)
      if (term.fd[i] == fd)
        break;

    if (i == MAX_TERMS) {
      term_errno = TERM_ENOTFOUND;
      rval = -1;
      break;
    }

    rval = i;
  } while (0);

  return rval;
}

/***************************************************************************/

static void term_exitfunc(void) {
  int r, i;

  do { /* dummy */
    if (!term.init)
      break;

    for (i = 0; i < MAX_TERMS; i++) {
      if (term.fd[i] == -1)
        continue;
      term_drain(term.fd[i]);
      tcflush(term.fd[i], TCIFLUSH);
      do {
        r = tcsetattr(term.fd[i], TCSANOW, &term.origtermios[i]);
      } while (r < 0 && errno == EINTR);
      if (r < 0) {
        const char *tname;

        tname = ttyname(term.fd[i]);
        if (!tname)
          tname = "UNKNOWN";
        fprintf(stderr, "%s: reset failed for dev %s: %s\r\n", __FUNCTION__,
                tname, strerror(errno));
      }
#ifdef USE_FLOCK
      /* Explicitly unlock the file. If the file is not in fact
         flock(2)'ed, no harm is done. This should normally not
         be necessary. Normally, exiting the program should take
         care of unlocking the file. Unfortuntelly, it has been
         observed that, on some systems, exiting or closing an
         flock(2)'ed tty fd has peculiar side effects (like not
         reseting the modem-control lines, even if HUPCL is
         set). */
      flock(term.fd[i], LOCK_UN);
#endif
      close(term.fd[i]);
      term.fd[i] = -1;
    }
  } while (0);
}

/***************************************************************************/

int term_lib_init(void) {
  int rval, r, i;

  rval = 0;

  do { /* dummy */
    if (term.init) {
      /* reset all terms back to their original settings */
      for (i = 0; i < MAX_TERMS; i++) {
        if (term.fd[i] == -1)
          continue;
        tcflush(term.fd[i], TCIOFLUSH);
        do {
          r = tcsetattr(term.fd[i], TCSANOW, &term.origtermios[i]);
        } while (r < 0 && errno == EINTR);
        if (r < 0) {
          const char *tname;

          tname = ttyname(term.fd[i]);
          if (!tname)
            tname = "UNKNOWN";
          fprintf(stderr, "%s: reset failed for dev %s: %s\n", __FUNCTION__,
                  tname, strerror(errno));
        }
        term.fd[i] = -1;
      }
    } else {
      /* initialize term structure. */
      for (i = 0; i < MAX_TERMS; i++)
        term.fd[i] = -1;
      if (atexit(term_exitfunc) != 0) {
        term_errno = TERM_EATEXIT;
        rval = -1;
        break;
      }
      /* ok. term struct is now initialized. */
      term.init = 1;
    }
  } while (0);

  return rval;
}

/***************************************************************************/

int term_add(int fd) {
  int rval, r, i;

  rval = 0;

  do { /* dummy */
    i = term_find(fd);
    if (i >= 0) {
      term_errno = TERM_EEXISTS;
      rval = -1;
      break;
    }

    if (!isatty(fd)) {
      term_errno = TERM_EISATTY;
      rval = -1;
      break;
    }

    i = term_find_next_free();
    if (i < 0) {
      rval = -1;
      break;
    }

    r = tcgetattr(fd, &term.origtermios[i]);
    if (r < 0) {
      term_errno = TERM_EGETATTR;
      rval = -1;
      break;
    }

    term.currtermios[i] = term.origtermios[i];
    term.nexttermios[i] = term.origtermios[i];
    term.fd[i] = fd;
  } while (0);

  return rval;
}

/***************************************************************************/

int term_remove(int fd) {
  int rval, r, i;

  rval = 0;

  do { /* dummy */
    i = term_find(fd);
    if (i < 0) {
      rval = -1;
      break;
    }

    do { /* dummy */
      r = tcflush(term.fd[i], TCIOFLUSH);
      if (r < 0) {
        term_errno = TERM_EFLUSH;
        rval = -1;
        break;
      }
      r = tcsetattr(term.fd[i], TCSANOW, &term.origtermios[i]);
      if (r < 0) {
        term_errno = TERM_ESETATTR;
        rval = -1;
        break;
      }
    } while (0);

    term.fd[i] = -1;
  } while (0);

  return rval;
}

/***************************************************************************/

int term_erase(int fd) {
  int rval, i;

  rval = 0;

  do { /* dummy */
    i = term_find(fd);
    if (i < 0) {
      rval = -1;
      break;
    }

    term.fd[i] = -1;
  } while (0);

  return rval;
}

/***************************************************************************/

int term_replace(int oldfd, int newfd) {
  int rval, r, i;

  rval = 0;

  do { /* dummy */

    i = term_find(oldfd);
    if (i < 0) {
      rval = -1;
      break;
    }

    r = tcsetattr(newfd, TCSANOW, &term.currtermios[i]);
    if (r < 0) {
      term_errno = TERM_ESETATTR;
      rval = -1;
      break;
    }
    r = tcgetattr(newfd, &term.currtermios[i]);
    if (r < 0) {
      term_errno = TERM_EGETATTR;
      rval = -1;
      break;
    }

    term.fd[i] = newfd;

  } while (0);

  return rval;
}

/***************************************************************************/

int term_reset(int fd) {
  int rval, r, i;

  rval = 0;

  do { /* dummy */

    i = term_find(fd);
    if (i < 0) {
      rval = -1;
      break;
    }

    r = tcflush(term.fd[i], TCIOFLUSH);
    if (r < 0) {
      term_errno = TERM_EFLUSH;
      rval = -1;
      break;
    }
    r = tcsetattr(term.fd[i], TCSANOW, &term.origtermios[i]);
    if (r < 0) {
      term_errno = TERM_ESETATTR;
      rval = -1;
      break;
    }
    r = tcgetattr(term.fd[i], &term.currtermios[i]);
    if (r < 0) {
      term_errno = TERM_EGETATTR;
      rval = -1;
      break;
    }

    term.nexttermios[i] = term.currtermios[i];
  } while (0);

  return rval;
}

/***************************************************************************/

int term_revert(int fd) {
  int rval, i;

  rval = 0;

  do { /* dummy */

    i = term_find(fd);
    if (i < 0) {
      rval = -1;
      break;
    }

    term.nexttermios[i] = term.currtermios[i];

  } while (0);

  return rval;
}

/***************************************************************************/

int term_refresh(int fd) {
  int rval, r, i;

  rval = 0;

  do { /* dummy */

    i = term_find(fd);
    if (i < 0) {
      rval = -1;
      break;
    }

    r = tcgetattr(fd, &term.currtermios[i]);
    if (r < 0) {
      term_errno = TERM_EGETATTR;
      rval = -1;
      break;
    }

  } while (0);

  return rval;
}

/***************************************************************************/

int term_apply(int fd, int now) {
  int when, rval, r, i;

  when = now ? TCSANOW : TCSAFLUSH;

  rval = 0;

  do { /* dummy */

    i = term_find(fd);
    if (i < 0) {
      rval = -1;
      break;
    }

    r = tcsetattr(term.fd[i], when, &term.nexttermios[i]);
    if (r < 0) {
      term_errno = TERM_ESETATTR;
      rval = -1;
      break;
    }
    r = tcgetattr(term.fd[i], &term.nexttermios[i]);
    if (r < 0) {
      term_errno = TERM_EGETATTR;
      rval = -1;
      break;
    }

    term.currtermios[i] = term.nexttermios[i];

    /* Set HUPCL to origtermios as well. Since setting HUPCL
       affects the behavior on close(2), we most likely want it to
       also apply when the filedes is implicitly closed by
       exit(3)ing the program. Since, uppon exiting, we restore
       the original settings, this wouldn't happen unless we also
       set HUPCL to origtermios. */
    if (term.currtermios[i].c_cflag & HUPCL)
      term.origtermios[i].c_cflag |= HUPCL;
    else
      term.origtermios[i].c_cflag &= ~HUPCL;

  } while (0);

  return rval;
}

/***************************************************************************/

int term_set_raw(int fd) {
  int rval, i;

  rval = 0;

  do { /* dummy */

    i = term_find(fd);
    if (i < 0) {
      rval = -1;
      break;
    }

    /* BSD raw mode */
    cfmakeraw(&term.nexttermios[i]);
    /* one byte at a time, no timer */
    term.nexttermios[i].c_cc[VMIN] = 1;
    term.nexttermios[i].c_cc[VTIME] = 0;

  } while (0);

  return rval;
}

/***************************************************************************/

int term_set_baudrate(int fd, int baudrate) {
  int rval, r, i;
  speed_t spd;
  struct termios tio;

  rval = 0;

  do { /* dummy */

    i = term_find(fd);
    if (i < 0) {
      rval = -1;
      break;
    }

    tio = term.nexttermios[i];
    spd = Bcode(baudrate);
    if (spd != BNONE) {
      r = cfsetospeed(&tio, spd);
      if (r < 0) {
        term_errno = TERM_ESETOSPEED;
        rval = -1;
        break;
      }
      /* ispeed = 0, means same as ospeed (see POSIX) */
      cfsetispeed(&tio, B0);
    } else {
      if (!use_custom_baud()) {
        term_errno = TERM_EBAUD;
        rval = -1;
        break;
      }
      r = cfsetospeed_custom(&tio, baudrate);
      if (r < 0) {
        term_errno = TERM_ESETOSPEED;
        rval = -1;
        break;
      }
      /* ispeed = 0, means same as ospeed (see POSIX) */
      cfsetispeed(&tio, B0);
    }

    term.nexttermios[i] = tio;

  } while (0);

  return rval;
}

int term_get_baudrate(int fd, int *ispeed) {
  speed_t code;
  int i, ospeed;

  do { /* dummy */

    i = term_find(fd);
    if (i < 0) {
      ospeed = -1;
      break;
    }

    if (ispeed) {
      code = cfgetispeed(&term.currtermios[i]);
      *ispeed = Bspeed(code);
      if (use_custom_baud()) {
        if (*ispeed < 0) {
          *ispeed = cfgetispeed_custom(&term.currtermios[i]);
        }
      }
    }
    code = cfgetospeed(&term.currtermios[i]);
    ospeed = Bspeed(code);
    if (ospeed < 0) {
      if (!use_custom_baud()) {
        term_errno = TERM_EGETSPEED;
        break;
      }
      ospeed = cfgetospeed_custom(&term.currtermios[i]);
      if (ospeed < 0) {
        term_errno = TERM_EGETSPEED;
      }
    }

  } while (0);

  return ospeed;
}

/***************************************************************************/

int term_set_parity(int fd, enum parity_e parity) {
  int rval, i;
  struct termios *tiop;

  rval = 0;

  do { /* dummy */

    i = term_find(fd);
    if (i < 0) {
      rval = -1;
      break;
    }

    tiop = &term.nexttermios[i];

    switch (parity) {
    case P_EVEN:
      tiop->c_cflag &= ~(PARODD | CMSPAR);
      tiop->c_cflag |= PARENB;
      break;
    case P_ODD:
      tiop->c_cflag &= ~CMSPAR;
      tiop->c_cflag |= PARENB | PARODD;
      break;
    case P_MARK:
      tiop->c_cflag |= PARENB | PARODD | CMSPAR;
      break;
    case P_SPACE:
      tiop->c_cflag &= ~PARODD;
      tiop->c_cflag |= PARENB | CMSPAR;
      break;
    case P_NONE:
      tiop->c_cflag &= ~(PARENB | PARODD | CMSPAR);
      break;
    default:
      term_errno = TERM_EPARITY;
      rval = -1;
      break;
    }
    if (rval < 0)
      break;

  } while (0);

  return rval;
}

enum parity_e term_get_parity(int fd) {
  tcflag_t flg;
  int i;
  enum parity_e parity;

  do { /* dummy */

    i = term_find(fd);
    if (i < 0) {
      parity = P_ERROR;
      break;
    }

    flg = term.currtermios[i].c_cflag;
    if (!(flg & PARENB)) {
      parity = P_NONE;
    } else if (flg & CMSPAR) {
      parity = (flg & PARODD) ? P_MARK : P_SPACE;
    } else {
      parity = (flg & PARODD) ? P_ODD : P_EVEN;
    }

  } while (0);

  return parity;
}

/***************************************************************************/

int term_set_databits(int fd, int databits) {
  int rval, i;
  struct termios *tiop;

  rval = 0;

  do { /* dummy */

    i = term_find(fd);
    if (i < 0) {
      rval = -1;
      break;
    }

    tiop = &term.nexttermios[i];

    switch (databits) {
    case 5:
      tiop->c_cflag = (tiop->c_cflag & ~CSIZE) | CS5;
      break;
    case 6:
      tiop->c_cflag = (tiop->c_cflag & ~CSIZE) | CS6;
      break;
    case 7:
      tiop->c_cflag = (tiop->c_cflag & ~CSIZE) | CS7;
      break;
    case 8:
      tiop->c_cflag = (tiop->c_cflag & ~CSIZE) | CS8;
      break;
    default:
      term_errno = TERM_EDATABITS;
      rval = -1;
      break;
    }
    if (rval < 0)
      break;

  } while (0);

  return rval;
}

int term_get_databits(int fd) {
  tcflag_t flg;
  int i, bits;

  do { /* dummy */

    i = term_find(fd);
    if (i < 0) {
      bits = -1;
      break;
    }

    flg = term.currtermios[i].c_cflag & CSIZE;
    switch (flg) {
    case CS5:
      bits = 5;
      break;
    case CS6:
      bits = 6;
      break;
    case CS7:
      bits = 7;
      break;
    case CS8:
    default:
      bits = 8;
      break;
    }

  } while (0);

  return bits;
}

/***************************************************************************/

int term_set_stopbits(int fd, int stopbits) {
  int rval, i;
  struct termios *tiop;

  rval = 0;

  do { /* dummy */

    i = term_find(fd);
    if (i < 0) {
      rval = -1;
      break;
    }

    tiop = &term.nexttermios[i];

    switch (stopbits) {
    case 1:
      tiop->c_cflag &= ~CSTOPB;
      break;
    case 2:
      tiop->c_cflag |= CSTOPB;
      break;
    default:
      term_errno = TERM_ESTOPBITS;
      rval = -1;
      break;
    }
    if (rval < 0)
      break;

  } while (0);

  return rval;
}

int term_get_stopbits(int fd) {
  int i, bits;

  do { /* dummy */

    i = term_find(fd);
    if (i < 0) {
      bits = -1;
      break;
    }

    bits = (term.currtermios[i].c_cflag & CSTOPB) ? 2 : 1;

  } while (0);

  return bits;
}

/***************************************************************************/

int term_set_flowcntrl(int fd, enum flowcntrl_e flowcntl) {
  int rval, i;
  struct termios *tiop;

  rval = 0;

  do { /* dummy */

    i = term_find(fd);
    if (i < 0) {
      rval = -1;
      break;
    }

    tiop = &term.nexttermios[i];

    switch (flowcntl) {
    case FC_RTSCTS:
      tiop->c_cflag |= CRTSCTS;
      tiop->c_iflag &= ~(IXON | IXOFF | IXANY);
      break;
    case FC_XONXOFF:
      tiop->c_cflag &= ~(CRTSCTS);
      tiop->c_iflag |= IXON | IXOFF;
      break;
    case FC_NONE:
      tiop->c_cflag &= ~(CRTSCTS);
      tiop->c_iflag &= ~(IXON | IXOFF | IXANY);
      break;
    default:
      term_errno = TERM_EFLOW;
      rval = -1;
      break;
    }
    if (rval < 0)
      break;

  } while (0);

  return rval;
}

enum flowcntrl_e term_get_flowcntrl(int fd) {
  int i;
  enum flowcntrl_e flow;
  int rtscts, xoff, xon;

  do { /* dummy */

    i = term_find(fd);
    if (i < 0) {
      flow = FC_ERROR;
      break;
    }

    rtscts = (term.currtermios[i].c_cflag & CRTSCTS) ? 1 : 0;
    xoff = (term.currtermios[i].c_iflag & IXOFF) ? 1 : 0;
    xon = (term.currtermios[i].c_iflag & (IXON | IXANY)) ? 1 : 0;

    if (rtscts && !xoff && !xon) {
      flow = FC_RTSCTS;
    } else if (!rtscts && xoff && xon) {
      flow = FC_XONXOFF;
    } else if (!rtscts && !xoff && !xon) {
      flow = FC_NONE;
    } else {
      flow = FC_OTHER;
    }

  } while (0);

  return flow;
}

/***************************************************************************/

int term_set_local(int fd, int local) {
  int rval, i;
  struct termios *tiop;

  rval = 0;

  do { /* dummy */

    i = term_find(fd);
    if (i < 0) {
      rval = -1;
      break;
    }

    tiop = &term.nexttermios[i];

    if (local)
      tiop->c_cflag |= CLOCAL;
    else
      tiop->c_cflag &= ~CLOCAL;

  } while (0);

  return rval;
}

/***************************************************************************/

int term_set_hupcl(int fd, int on) {
  int rval, i;
  struct termios *tiop;

  rval = 0;

  do { /* dummy */

    i = term_find(fd);
    if (i < 0) {
      rval = -1;
      break;
    }

    tiop = &term.nexttermios[i];

    if (on)
      tiop->c_cflag |= HUPCL;
    else
      tiop->c_cflag &= ~HUPCL;

  } while (0);

  return rval;
}

/***************************************************************************/

int term_set(int fd, int raw, int baud, enum parity_e parity, int databits,
             int stopbits, enum flowcntrl_e fc, int local, int hup_close) {
  int rval, r, i, ni;
  struct termios tio;

  rval = 0;

  do { /* dummy */

    i = term_find(fd);
    if (i < 0) {
      ni = term_add(fd);
      if (ni < 0) {
        rval = -1;
        break;
      }
    } else {
      ni = i;
    }

    tio = term.nexttermios[ni];

    do { /* dummy */

      if (raw) {
        r = term_set_raw(fd);
        if (r < 0) {
          rval = -1;
          break;
        }
      }

      r = term_set_baudrate(fd, baud);
      if (r < 0) {
        rval = -1;
        break;
      }

      r = term_set_parity(fd, parity);
      if (r < 0) {
        rval = -1;
        break;
      }

      r = term_set_databits(fd, databits);
      if (r < 0) {
        rval = -1;
        break;
      }

      r = term_set_stopbits(fd, stopbits);
      if (r < 0) {
        rval = -1;
        break;
      }

      r = term_set_flowcntrl(fd, fc);
      if (r < 0) {
        rval = -1;
        break;
      }

      r = term_set_local(fd, local);
      if (r < 0) {
        rval = -1;
        break;
      }

      r = term_set_hupcl(fd, hup_close);
      if (r < 0) {
        rval = -1;
        break;
      }

    } while (0);

    if (rval < 0) {
      if (i < 0)
        /* new addition. must be removed */
        term.fd[ni] = -1;
      else
        /* just revert to previous settings */
        term.nexttermios[ni] = tio;
    }

  } while (0);

  return rval;
}

/***************************************************************************/

int term_pulse_dtr(int fd) {
  int rval, r, i;

  rval = 0;

  do { /* dummy */

    i = term_find(fd);
    if (i < 0) {
      rval = -1;
      break;
    }

#ifdef USE_IOCTL
    {
      int opins = TIOCM_DTR;

      r = ioctl(fd, TIOCMBIC, &opins);
      if (r < 0) {
        term_errno = TERM_EDTRDOWN;
        rval = -1;
        break;
      }

      sleep(1);

      r = ioctl(fd, TIOCMBIS, &opins);
      if (r < 0) {
        term_errno = TERM_EDTRUP;
        rval = -1;
        break;
      }
    }
#else
    {
      struct termios tio, tioold;

      r = tcgetattr(fd, &tio);
      if (r < 0) {
        term_errno = TERM_EGETATTR;
        rval = -1;
        break;
      }

      tioold = tio;

      /* ospeed = 0, means hangup (see POSIX) */
      cfsetospeed(&tio, B0);
      r = tcsetattr(fd, TCSANOW, &tio);
      if (r < 0) {
        term_errno = TERM_ESETATTR;
        rval = -1;
        break;
      }

      sleep(1);

      r = tcsetattr(fd, TCSANOW, &tioold);
      if (r < 0) {
        term.currtermios[i] = tio;
        term_errno = TERM_ESETATTR;
        rval = -1;
        break;
      }
    }
#endif /* of USE_IOCTL */

  } while (0);

  return rval;
}

/***************************************************************************/

int term_raise_dtr(int fd) {
  int rval, i;

  rval = 0;

  do { /* dummy */

    i = term_find(fd);
    if (i < 0) {
      rval = -1;
      break;
    }

#ifdef USE_IOCTL
    {
      int r, opins = TIOCM_DTR;

      r = ioctl(fd, TIOCMBIS, &opins);
      if (r < 0) {
        term_errno = TERM_EDTRUP;
        rval = -1;
        break;
      }
    }
#else
    term_errno = TERM_EDTRUP;
    rval = -1;
#endif /* of USE_IOCTL */
  } while (0);

  return rval;
}

/***************************************************************************/

int term_lower_dtr(int fd) {
  int rval, i;

  rval = 0;

  do { /* dummy */

    i = term_find(fd);
    if (i < 0) {
      rval = -1;
      break;
    }

#ifdef USE_IOCTL
    {
      int r, opins = TIOCM_DTR;

      r = ioctl(fd, TIOCMBIC, &opins);
      if (r < 0) {
        term_errno = TERM_EDTRDOWN;
        rval = -1;
        break;
      }
    }
#else
    term_errno = TERM_EDTRDOWN;
    rval = -1;
#endif /* of USE_IOCTL */
  } while (0);

  return rval;
}

/***************************************************************************/

int term_raise_rts(int fd) {
  int rval, i;

  rval = 0;

  do { /* dummy */

    i = term_find(fd);
    if (i < 0) {
      rval = -1;
      break;
    }

#ifdef USE_IOCTL
    {
      int r;
      int opins = TIOCM_RTS;

      r = ioctl(fd, TIOCMBIS, &opins);
      if (r < 0) {
        term_errno = TERM_ERTSUP;
        rval = -1;
        break;
      }
    }
#else
    term_errno = TERM_ERTSUP;
    rval = -1;
#endif /* of USE_IOCTL */
  } while (0);

  return rval;
}

/***************************************************************************/

int term_lower_rts(int fd) {
  int rval, i;

  rval = 0;

  do { /* dummy */

    i = term_find(fd);
    if (i < 0) {
      rval = -1;
      break;
    }

#ifdef USE_IOCTL
    {
      int r;
      int opins = TIOCM_RTS;

      r = ioctl(fd, TIOCMBIC, &opins);
      if (r < 0) {
        term_errno = TERM_ERTSDOWN;
        rval = -1;
        break;
      }
    }
#else
    term_errno = TERM_ERTSDOWN;
    rval = -1;
#endif /* of USE_IOCTL */
  } while (0);

  return rval;
}

/***************************************************************************/

int term_get_mctl(int fd) {
  int mctl, i;

  do { /* dummy */

    i = term_find(fd);
    if (i < 0) {
      mctl = -1;
      break;
    }

#ifdef USE_IOCTL
    {
      int r, pmctl;

      r = ioctl(fd, TIOCMGET, &pmctl);
      if (r < 0) {
        mctl = -1;
        break;
      }
      mctl = 0;
      if (pmctl & TIOCM_DTR)
        mctl |= MCTL_DTR;
      if (pmctl & TIOCM_DSR)
        mctl |= MCTL_DSR;
      if (pmctl & TIOCM_CD)
        mctl |= MCTL_DCD;
      if (pmctl & TIOCM_RTS)
        mctl |= MCTL_RTS;
      if (pmctl & TIOCM_CTS)
        mctl |= MCTL_CTS;
      if (pmctl & TIOCM_RI)
        mctl |= MCTL_RI;
    }
#else
    mctl = MCTL_UNAVAIL;
#endif /* of USE_IOCTL */
  } while (0);

  return mctl;
}

int term_drain(int fd) {
  int rval, r;

  rval = 0;

  do { /* dummy */

    r = term_find(fd);
    if (r < 0) {
      rval = -1;
      break;
    }

    do {
#ifdef __BIONIC__
      /* See: http://dan.drown.org/android/src/gdb/no-tcdrain */
      r = ioctl(fd, TCSBRK, 1);
#else
      r = tcdrain(fd);
#endif
    } while (r < 0 && errno == EINTR);
    if (r < 0) {
      term_errno = TERM_EDRAIN;
      rval = -1;
      break;
    }
    /* Give some time to the UART to transmit everything. Some
       systems and / or drivers corrupt the last character(s) if
       the port is immediately reconfigured, even after a
       drain. (I guess, drain does not wait for everything to
       actually be transitted on the wire). */
    if (DRAIN_DELAY)
      usleep(DRAIN_DELAY);

  } while (0);

  return rval;
}

/***************************************************************************/

int term_fake_flush(int fd) {
  struct termios tio;
  int rval, i, r;

  rval = 0;

  do { /* dummy */

    i = term_find(fd);
    if (i < 0) {
      rval = -1;
      break;
    }

    /* Get current termios */
    r = tcgetattr(fd, &tio);
    if (r < 0) {
      term_errno = TERM_EGETATTR;
      rval = -1;
      break;
    }
    term.currtermios[i] = tio;
    /* Set flow-control to none */
    tio.c_cflag &= ~(CRTSCTS);
    tio.c_iflag &= ~(IXON | IXOFF | IXANY);
    /* Apply termios */
    r = tcsetattr(fd, TCSANOW, &tio);
    if (r < 0) {
      term_errno = TERM_ESETATTR;
      rval = -1;
      break;
    }
    /* Wait for output to drain. Without flow-control this should
       complete in finite time. */
    r = tcdrain(fd);
    if (r < 0) {
      term_errno = TERM_EDRAIN;
      rval = -1;
      break;
    }
    /* see comment in term_drain */
    if (DRAIN_DELAY)
      usleep(DRAIN_DELAY);
    /* Reset flow-control to original setting. */
    r = tcsetattr(fd, TCSANOW, &term.currtermios[i]);
    if (r < 0) {
      term_errno = TERM_ESETATTR;
      rval = -1;
      break;
    }

  } while (0);

  return rval;
}

int term_flush(int fd) {
  int rval, r;

  rval = 0;

  do { /* dummy */

    r = term_find(fd);
    if (r < 0) {
      rval = -1;
      break;
    }

    r = tcflush(fd, TCIOFLUSH);
    if (r < 0) {
      term_errno = TERM_EFLUSH;
      rval = -1;
      break;
    }

  } while (0);

  return rval;
}

/***************************************************************************/

int term_break(int fd) {
  int rval, r;

  rval = 0;

  do { /* dummy */

    r = term_find(fd);
    if (r < 0) {
      rval = -1;
      break;
    }

    r = tcsendbreak(fd, 0);
    if (r < 0) {
      term_errno = TERM_EBREAK;
      rval = -1;
      break;
    }

  } while (0);

  return rval;
}

/**************************************************************************/

/*
 * Local Variables:
 * mode:c
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 */

/**********************************************************************/

/* parity modes names */
const char *parity_str[] = {
    [P_NONE] = "none", [P_EVEN] = "even",   [P_ODD] = "odd",
    [P_MARK] = "mark", [P_SPACE] = "space", [P_ERROR] = "invalid parity mode",
};

/* flow control modes names */
const char *flow_str[] = {
    [FC_NONE] = "none",
    [FC_RTSCTS] = "RTS/CTS",
    [FC_XONXOFF] = "xon/xoff",
    [FC_OTHER] = "other",
    [FC_ERROR] = "invalid flow control mode",
};

/**********************************************************************/

/* control-key to printable character (lowcase) */
#define KEYC(k) ((k) | 0x60)
/* printable character to control-key */
#define CKEY(c) ((c)&0x1f)

#define KEY_EXIT CKEY('x')    /* exit picocom */
#define KEY_QUIT CKEY('q')    /* exit picocom without reseting port */
#define KEY_PULSE CKEY('p')   /* pulse DTR */
#define KEY_TOG_DTR CKEY('t') /* toggle DTR */
#define KEY_TOG_RTS CKEY('g') /* toggle RTS */
#define KEY_BAUD CKEY('b')    /* set baudrate */
#define KEY_BAUD_UP CKEY('u') /* increase baudrate (up) */
#define KEY_BAUD_DN CKEY('d') /* decrase baudrate (down) */
#define KEY_FLOW CKEY('f')    /* change flowcntrl mode */
#define KEY_PARITY CKEY('y')  /* change parity mode */
#define KEY_BITS CKEY('i')    /* change number of databits */
#define KEY_STOP CKEY('j')    /* change number of stopbits */
#define KEY_LECHO CKEY('c')   /* toggle local echo */
#define KEY_STATUS CKEY('v')  /* show program options */
#define KEY_HELP CKEY('h')    /* show help (same as [C-k]) */
#define KEY_KEYS CKEY('k')    /* show available command keys */
#define KEY_SEND CKEY('s')    /* send file */
#define KEY_RECEIVE CKEY('r') /* receive file */
#define KEY_HEX CKEY('w')     /* write hex */
#define KEY_BREAK CKEY('\\')  /* break */

/**********************************************************************/

/* implemented caracter mappings */
#define M_CRLF (1 << 0)     /* map CR  --> LF */
#define M_CRCRLF (1 << 1)   /* map CR  --> CR + LF */
#define M_IGNCR (1 << 2)    /* map CR  --> <nothing> */
#define M_LFCR (1 << 3)     /* map LF  --> CR */
#define M_LFCRLF (1 << 4)   /* map LF  --> CR + LF */
#define M_IGNLF (1 << 5)    /* map LF  --> <nothing> */
#define M_DELBS (1 << 6)    /* map DEL --> BS */
#define M_BSDEL (1 << 7)    /* map BS  --> DEL */
#define M_SPCHEX (1 << 8)   /* map special chars --> hex */
#define M_TABHEX (1 << 9)   /* map TAB --> hex */
#define M_CRHEX (1 << 10)   /* map CR --> hex */
#define M_LFHEX (1 << 11)   /* map LF --> hex */
#define M_8BITHEX (1 << 12) /* map 8-bit chars --> hex */
#define M_NRMHEX (1 << 13)  /* map normal ascii chars --> hex */
#define M_NFLAGS 14

/* default character mappings */
#define M_I_DFL 0
#define M_O_DFL 0
#define M_E_DFL (M_DELBS | M_CRCRLF)

/* character mapping names */
struct map_names_s {
  const char *name;
  int flag;
} map_names[] = {{"crlf", M_CRLF},
                 {"crcrlf", M_CRCRLF},
                 {"igncr", M_IGNCR},
                 {"lfcr", M_LFCR},
                 {"lfcrlf", M_LFCRLF},
                 {"ignlf", M_IGNLF},
                 {"delbs", M_DELBS},
                 {"bsdel", M_BSDEL},
                 {"spchex", M_SPCHEX},
                 {"tabhex", M_TABHEX},
                 {"crhex", M_CRHEX},
                 {"lfhex", M_LFHEX},
                 {"8bithex", M_8BITHEX},
                 {"nrmhex", M_NRMHEX},
                 /* Sentinel */
                 {NULL, 0}};

struct {
  char *port;
  int baud;
  enum flowcntrl_e flow;
  enum parity_e parity;
  int databits;
  int stopbits;
  int lecho;
  int noinit;
  int noreset;
  int hangup;
#if defined(UUCP_LOCK_DIR) || defined(USE_FLOCK)
  int nolock;
#endif
  unsigned char escape;
  int noescape;
  char send_cmd[128];
  char receive_cmd[128];
  int imap;
  int omap;
  int emap;
  char *log_filename;
  char *initstring;
  int exit_after;
  int exit;
  int lower_rts;
  int lower_dtr;
  int raise_rts;
  int raise_dtr;
  int quiet;
} opts = {.port = NULL,
          .baud = 9600,
          .flow = FC_NONE,
          .parity = P_NONE,
          .databits = 8,
          .stopbits = 1,
          .lecho = 0,
          .noinit = 0,
          .noreset = 0,
          .hangup = 0,
#if defined(UUCP_LOCK_DIR) || defined(USE_FLOCK)
          .nolock = 0,
#endif
          .escape = CKEY('a'),
          .noescape = 0,
          .send_cmd = "sz -vv",
          .receive_cmd = "rz -vv -E",
          .imap = M_I_DFL,
          .omap = M_O_DFL,
          .emap = M_E_DFL,
          .log_filename = NULL,
          .initstring = NULL,
          .exit_after = -1,
          .exit = 0,
          .lower_rts = 0,
          .lower_dtr = 0,
          .raise_rts = 0,
          .raise_dtr = 0,
          .quiet = 1};

int sig_exit = 0;

#define STI STDIN_FILENO
#define STO STDOUT_FILENO
#define STE STDERR_FILENO

int tty_fd = -1;
int log_fd = -1;

/* RTS and DTR are usually raised upon opening the serial port (at least
   as tested on Linux, OpenBSD and macOS, but FreeBSD behave different) */
int rts_up = 1;
int dtr_up = 1;

#define TTY_Q_SZ_MIN 256
#ifndef TTY_Q_SZ
#define TTY_Q_SZ 32768
#endif

struct tty_q {
  int sz;
  int len;
  unsigned char *buff;
} tty_q = {.sz = 0, .len = 0, .buff = NULL};

#define STI_RD_SZ 16
#define TTY_RD_SZ 128

int tty_write_sz;

#define TTY_WRITE_SZ_DIV 10
#define TTY_WRITE_SZ_MIN 8

#define set_tty_write_sz(baud)                                                 \
  do {                                                                         \
    tty_write_sz = (baud) / TTY_WRITE_SZ_DIV;                                  \
    if (tty_write_sz < TTY_WRITE_SZ_MIN)                                       \
      tty_write_sz = TTY_WRITE_SZ_MIN;                                         \
  } while (0)

#define HEXBUF_SZ 128
#define HEXDELIM " \r;:-_.,/"

#define hexisdelim(c) (strchr(HEXDELIM, (c)) != NULL)

static inline int hex2byte(char c) {
  int r;

  if (c >= '0' && c <= '9')
    r = c - '0';
  else if (c >= 'A' && c <= 'F')
    r = c - 'A' + 10;
  else if (c >= 'a' && c <= 'f')
    r = c - 'a' + 10;
  else
    r = -1;

  return r;
}

int hex2bin(unsigned char *buf, int sz, const char *str) {
  char c;
  int b0, b1;
  int i;

  i = 0;
  while (i < sz) {
    /* delimiter, end of string, or high nibble */
    c = *str++;
    if (c == '\0')
      break;
    if (hexisdelim(c))
      continue;
    b0 = hex2byte(c);
    if (b0 < 0)
      return -1;
    /* low nibble */
    c = *str++;
    if (c == '\0')
      return -1;
    b1 = hex2byte(c);
    if (b1 < 0)
      return -1;
    /* pack byte */
    buf[i++] = (unsigned char)b0 << 4 | (unsigned char)b1;
  }

  return i;
}

/**********************************************************************/

#ifndef LINENOISE

char *read_filename(void) {
  char fname[_POSIX_PATH_MAX];
  int r;

  fd_printf(STO, "\r\n*** file: ");
  r = fd_readline(STI, STO, fname, sizeof(fname));
  fd_printf(STO, "\r\n");
  if (r < 0)
    return NULL;
  else
    return strdup(fname);
}

int read_baud(void) {
  char baudstr[9], *ep;
  int baud = -1, r;

  do {
    fd_printf(STO, "\r\n*** baud: ");
    r = fd_readline(STI, STO, baudstr, sizeof(baudstr));
    fd_printf(STO, "\r\n");
    if (r < 0)
      break;
    baud = strtol(baudstr, &ep, 0);
    if (!ep || *ep != '\0' || !term_baud_ok(baud) || baud == 0) {
      fd_printf(STO, "*** Invalid baudrate!");
      baud = -1;
    }
  } while (baud < 0);

  return baud;
}

int read_hex(unsigned char *buff, int sz) {
  char hexstr[256];
  int r, n;

  do {
    fd_printf(STO, "\r\n*** hex: ");
    r = fd_readline(STI, STO, hexstr, sizeof(hexstr));
    fd_printf(STO, "\r\n");
    if (r < 0) {
      n = 0;
      break;
    }
    n = hex2bin(buff, sz, hexstr);
    if (n < 0)
      fd_printf(STO, "*** Invalid hex!");
  } while (n < 0);

  return n;
}

#else /* LINENOISE defined */

void file_completion_cb(const char *buf, linenoiseCompletions *lc) {
  DIR *dirp;
  struct dirent *dp;
  char *basec, *basen, *dirc, *dirn;
  int baselen, dirlen, namelen;
  char *fullpath;
  struct stat filestat;

  basec = strdup(buf);
  dirc = strdup(buf);
  dirn = dirname(dirc);
  dirlen = strlen(dirn);
  basen = basename(basec);
  baselen = strlen(basen);
  dirp = opendir(dirn);

  if (dirp) {
    while ((dp = readdir(dirp)) != NULL) {
      namelen = strlen(dp->d_name);
      if (strncmp(basen, dp->d_name, baselen) == 0) {
        /* add 2 extra bytes for possible / in middle & at end */
        fullpath = (char *)malloc(namelen + dirlen + 3);
        memcpy(fullpath, dirn, dirlen + 1);
        if (fullpath[dirlen - 1] != '/')
          strcat(fullpath, "/");
        strncat(fullpath, dp->d_name, namelen);
        if (stat(fullpath, &filestat) == 0) {
          if (S_ISDIR(filestat.st_mode)) {
            strcat(fullpath, "/");
          }
          linenoiseAddCompletion(lc, fullpath);
        }
        free(fullpath);
      }
    }

    closedir(dirp);
  }
  free(basec);
  free(dirc);
}

static char *history_file_path = NULL;

void init_history(void) {
  char *home_directory;
  int home_directory_len;

  home_directory = getenv("HOME");
  if (home_directory) {
    home_directory_len = strlen(home_directory);
    history_file_path = malloc(home_directory_len + 2 + strlen(HISTFILE));
    memcpy(history_file_path, home_directory, home_directory_len + 1);
    if (home_directory[home_directory_len - 1] != '/') {
      strcat(history_file_path, "/");
    }
    strcat(history_file_path, HISTFILE);
    linenoiseHistoryLoad(history_file_path);
  }
}

void cleanup_history(void) {
  if (history_file_path)
    free(history_file_path);
}

void add_history(char *fname) {
  linenoiseHistoryAdd(fname);
  if (history_file_path)
    linenoiseHistorySave(history_file_path);
}

char *read_filename(void) {
  char *fname;
  linenoiseSetCompletionCallback(file_completion_cb);
  fd_printf(STO, "\r\n");
  fname = linenoise("*** file: ");
  fd_printf(STO, "\r");
  linenoiseSetCompletionCallback(NULL);
  if (fname != NULL)
    add_history(fname);
  return fname;
}

int read_baud(void) {
  char *baudstr, *ep;
  int baud = -1;

  do {
    fd_printf(STO, "\r\n");
    baudstr = linenoise("*** baud: ");
    fd_printf(STO, "\r");
    if (baudstr == NULL)
      break;
    baud = strtol(baudstr, &ep, 0);
    if (!ep || *ep != '\0' || !term_baud_ok(baud) || baud == 0) {
      fd_printf(STO, "*** Invalid baudrate!");
      baud = -1;
    }
    free(baudstr);
  } while (baud < 0);

  if (baudstr != NULL)
    add_history(baudstr);

  return baud;
}

int read_hex(unsigned char *buff, int sz) {
  char *hexstr;
  int n;

  do {
    fd_printf(STO, "\r\n");
    hexstr = linenoise("*** hex: ");
    fd_printf(STO, "\r");
    if (hexstr == NULL) {
      n = 0;
      break;
    }
    n = hex2bin(buff, sz, hexstr);
    if (n < 0)
      fd_printf(STO, "*** Invalid hex!");
    free(hexstr);
  } while (n < 0);

  return n;
}

#endif /* of ifndef LINENOISE */

/**********************************************************************/

int pinfo(const char *format, ...) {
  va_list args;
  int len;

  if (opts.quiet) {
    return 0;
  }
  va_start(args, format);
  len = fd_vprintf(STO, format, args);
  va_end(args);

  return len;
}

void cleanup(int drain, int noreset, int hup) {
  if (tty_fd >= 0) {
    /* Print msg if they fail? Can't do anything, anyway... */
    if (drain)
      term_drain(tty_fd);
    term_flush(tty_fd);
    /* term_flush does not work with some drivers. If we try to
       drain or even close the port while there are still data in
       it's output buffers *and* flow-control is enabled we may
       block forever. So we "fake" a flush, by temporarily setting
       f/c to none, waiting for any data in the output buffer to
       drain, and then reseting f/c to it's original setting. If
       the real flush above does works, then the fake one should
       amount to instantaneously switching f/c to none and then
       back to its propper setting. */
    if (opts.flow != FC_NONE)
      term_fake_flush(tty_fd);
    term_set_hupcl(tty_fd, !noreset || hup);
    term_apply(tty_fd, 1);
    if (noreset) {
      pinfo("Skipping tty reset...\r\n");
      term_erase(tty_fd);
#ifdef USE_FLOCK
      /* Explicitly unlock tty_fd before exiting. See
         comments in term.c/term_exitfunc() for more. */
      flock(tty_fd, LOCK_UN);
#endif
      close(tty_fd);
      tty_fd = -1;
    }
  }

#ifdef LINENOISE
  cleanup_history();
#endif
#ifdef UUCP_LOCK_DIR
  uucp_unlock();
#endif
  if (opts.initstring) {
    free(opts.initstring);
    opts.initstring = NULL;
  }
  if (tty_q.buff) {
    free(tty_q.buff);
    tty_q.buff = NULL;
  }
  free(opts.port);
  if (opts.log_filename) {
    free(opts.log_filename);
    close(log_fd);
  }
}

void fatal(const char *format, ...) {
  va_list args;

  fd_printf(STE, "\r\nFATAL: ");
  va_start(args, format);
  fd_vprintf(STE, format, args);
  va_end(args);
  fd_printf(STE, "\r\n");

  cleanup(0 /* drain */, opts.noreset, opts.hangup);

  exit(EXIT_FAILURE);
}

/**********************************************************************/

/* maximum number of chars that can replace a single characted
   due to mapping */
#define M_MAXMAP 4

int map2hex(char *b, char c) {
  const char *hexd = "0123456789abcdef";

  b[0] = '[';
  b[1] = hexd[(unsigned char)c >> 4];
  b[2] = hexd[(unsigned char)c & 0x0f];
  b[3] = ']';
  return 4;
}

int do_map(char *b, int map, char c) {
  int n = -1;

  switch (c) {
  case '\x7f':
    /* DEL mapings */
    if (map & M_DELBS) {
      b[0] = '\x08';
      n = 1;
    }
    break;
  case '\x08':
    /* BS mapings */
    if (map & M_BSDEL) {
      b[0] = '\x7f';
      n = 1;
    }
    break;
  case '\x0d':
    /* CR mappings */
    if (map & M_CRLF) {
      b[0] = '\x0a';
      n = 1;
    } else if (map & M_CRCRLF) {
      b[0] = '\x0d';
      b[1] = '\x0a';
      n = 2;
    } else if (map & M_IGNCR) {
      n = 0;
    } else if (map & M_CRHEX) {
      n = map2hex(b, c);
    }
    break;
  case '\x0a':
    /* LF mappings */
    if (map & M_LFCR) {
      b[0] = '\x0d';
      n = 1;
    } else if (map & M_LFCRLF) {
      b[0] = '\x0d';
      b[1] = '\x0a';
      n = 2;
    } else if (map & M_IGNLF) {
      n = 0;
    } else if (map & M_LFHEX) {
      n = map2hex(b, c);
    }
    break;
  case '\x09':
    /* TAB mappings */
    if (map & M_TABHEX) {
      n = map2hex(b, c);
    }
    break;
  default:
    break;
  }

  if (n < 0 && map & M_SPCHEX) {
    if (c == '\x7f' || ((unsigned char)c < 0x20 && c != '\x09' && c != '\x0a' &&
                        c != '\x0d')) {
      n = map2hex(b, c);
    }
  }
  if (n < 0 && map & M_8BITHEX) {
    if (c & 0x80) {
      n = map2hex(b, c);
    }
  }
  if (n < 0 && map & M_NRMHEX) {
    if ((unsigned char)c >= 0x20 && (unsigned char)c < 0x7f) {
      n = map2hex(b, c);
    }
  }
  if (n < 0) {
    b[0] = c;
    n = 1;
  }

  assert(n > 0 && n <= M_MAXMAP);

  return n;
}

void map_and_write(int fd, int map, char c) {
  char b[M_MAXMAP];
  int n;

  n = do_map(b, map, c);
  if (n)
    if (writen_ni(fd, b, n) < n)
      fatal("write to stdout failed: %s", strerror(errno));
}

#define RUNCMD_ARGS_MAX 32
#define RUNCMD_EXEC_FAIL 126

void establish_child_signal_handlers(void) {
  struct sigaction dfl_action;

  /* Set up the structure to specify the default action. */
  dfl_action.sa_handler = SIG_DFL;
  sigemptyset(&dfl_action.sa_mask);
  dfl_action.sa_flags = 0;

  sigaction(SIGINT, &dfl_action, NULL);
  sigaction(SIGTERM, &dfl_action, NULL);
}

int run_cmd(int fd, const char *cmd, const char *args_extra) {
  pid_t pid;
  sigset_t sigm, sigm_old;
  struct sigaction ign_action, old_action;

  /* Picocom ignores SIGINT while the command is running */
  ign_action.sa_handler = SIG_IGN;
  sigemptyset(&ign_action.sa_mask);
  ign_action.sa_flags = 0;
  sigaction(SIGINT, &ign_action, &old_action);
  /* block signals, let child establish its own handlers */
  sigemptyset(&sigm);
  sigaddset(&sigm, SIGTERM);
  sigaddset(&sigm, SIGINT);
  sigprocmask(SIG_BLOCK, &sigm, &sigm_old);

  pid = fork();
  if (pid < 0) {
    sigprocmask(SIG_SETMASK, &sigm_old, NULL);
    fd_printf(STO, "*** cannot fork: %s ***\r\n", strerror(errno));
    return -1;
  } else if (pid) {
    /* father: picocom */
    int status, r;

    /* reset the mask */
    sigprocmask(SIG_SETMASK, &sigm_old, NULL);
    /* wait for child to finish */
    do {
      r = waitpid(pid, &status, 0);
    } while (r < 0 && errno == EINTR);
    /* reset terminal (back to raw mode) */
    term_apply(STI, 0);
    /* re-enable SIGINT */
    sigaction(SIGINT, &old_action, NULL);
    /* check and report child return status */
    if (WIFEXITED(status)) {
      fd_printf(STO, "\r\n*** exit status: %d ***\r\n", WEXITSTATUS(status));
      return WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
      fd_printf(STO, "\r\n*** killed by signal: %d ***\r\n", WTERMSIG(status));
      return -1;
    } else {
      fd_printf(STO, "\r\n*** abnormal termination: 0x%x ***\r\n", r);
      return -1;
    }
  } else {
    /* child: external program */
    long fl;
    int argc;
    char *argv[RUNCMD_ARGS_MAX + 1];
    int r;

    /* unmanage terminal, and reset it to canonical mode */
    term_drain(STI);
    term_remove(STI);
    /* unmanage serial port fd, without reset */
    term_erase(fd);
    /* set serial port fd to blocking mode */
    fl = fcntl(fd, F_GETFL);
    fl &= ~O_NONBLOCK;
    fcntl(fd, F_SETFL, fl);
    /* connect stdin and stdout to serial port */
    close(STI);
    close(STO);
    dup2(fd, STI);
    dup2(fd, STO);

    /* build command arguments vector */
    argc = 0;
    r = split_quoted(cmd, &argc, argv, RUNCMD_ARGS_MAX);
    if (r < 0) {
      fd_printf(STE, "Cannot parse command\n");
      exit(RUNCMD_EXEC_FAIL);
    }
    r = split_quoted(args_extra, &argc, argv, RUNCMD_ARGS_MAX);
    if (r < 0) {
      fd_printf(STE, "Cannot parse extra args\n");
      exit(RUNCMD_EXEC_FAIL);
    }
    if (argc < 1) {
      fd_printf(STE, "No command given\n");
      exit(RUNCMD_EXEC_FAIL);
    }
    argv[argc] = NULL;

    /* run extenral command */
    fd_printf(STE, "$ %s %s\n", cmd, args_extra);
    establish_child_signal_handlers();
    sigprocmask(SIG_SETMASK, &sigm_old, NULL);
    execvp(argv[0], argv);

    fd_printf(STE, "exec: %s\n", strerror(errno));
    exit(RUNCMD_EXEC_FAIL);
  }
}

/**********************************************************************/

int tty_q_push(const char *s, int len) {
  int i, sz, n;
  unsigned char *b;

  for (i = 0; i < len; i++) {
    while (tty_q.len + M_MAXMAP > tty_q.sz) {
      sz = tty_q.sz * 2;
      if (TTY_Q_SZ && sz > TTY_Q_SZ)
        return i;
      b = realloc(tty_q.buff, sz);
      if (!b)
        return i;
      tty_q.buff = b;
      tty_q.sz = sz;
#if 0
            fd_printf(STO, "New tty_q size: %d\r\n", sz);
#endif
    }
    n = do_map((char *)tty_q.buff + tty_q.len, opts.omap, s[i]);
    tty_q.len += n;
    /* write to STO if local-echo is enabled */
    if (opts.lecho)
      map_and_write(STO, opts.emap, s[i]);
  }

  return i;
}

/* Process command key. Returns non-zero if command results in picocom
   exit, zero otherwise. */
int do_command(unsigned char c) {
  int newbaud, newbits, newstopbits;
  enum flowcntrl_e newflow;
  enum parity_e newparity;
  const char *xfr_cmd;
  char *fname;
  unsigned char hexbuf[HEXBUF_SZ];
  int n, r;

  switch (c) {
  case KEY_EXIT:
    return 1;
  case KEY_QUIT:
    opts.noreset = 1;
    return 1;
  case KEY_STATUS:
    break;
  case KEY_PULSE:
    fd_printf(STO, "\r\n*** pulse DTR ***\r\n");
    if (term_pulse_dtr(tty_fd) < 0)
      fd_printf(STO, "*** FAILED\r\n");
    else
      dtr_up = 1;
    break;
  case KEY_TOG_DTR:
    if (dtr_up)
      r = term_lower_dtr(tty_fd);
    else
      r = term_raise_dtr(tty_fd);
    if (r >= 0)
      dtr_up = !dtr_up;
    fd_printf(STO, "\r\n*** DTR: %s ***\r\n", dtr_up ? "up" : "down");
    break;
  case KEY_TOG_RTS:
    if (rts_up)
      r = term_lower_rts(tty_fd);
    else
      r = term_raise_rts(tty_fd);
    if (r >= 0)
      rts_up = !rts_up;
    fd_printf(STO, "\r\n*** RTS: %s ***\r\n", rts_up ? "up" : "down");
    break;
  case KEY_BAUD:
    if (c == KEY_BAUD) {
      newbaud = read_baud();
      if (newbaud < 0) {
        fd_printf(STO, "*** cannot read baudrate ***\r\n");
        break;
      }
      opts.baud = newbaud;
    }
    term_set_baudrate(tty_fd, opts.baud);
    tty_q.len = 0;
    term_flush(tty_fd);
    term_apply(tty_fd, 1);
    newbaud = term_get_baudrate(tty_fd, NULL);
    if (opts.baud != newbaud) {
      fd_printf(STO, "\r\n*** baud: %d (%d) ***\r\n", opts.baud, newbaud);
    } else {
      fd_printf(STO, "\r\n*** baud: %d ***\r\n", opts.baud);
    }
    set_tty_write_sz(newbaud);
    break;
  case KEY_LECHO:
    opts.lecho = !opts.lecho;
    fd_printf(STO, "\r\n*** local echo: %s ***\r\n", opts.lecho ? "yes" : "no");
    break;
  case KEY_SEND:
  case KEY_RECEIVE:
    xfr_cmd = (c == KEY_SEND) ? opts.send_cmd : opts.receive_cmd;
    if (xfr_cmd[0] == '\0') {
      fd_printf(STO, "\r\n*** command disabled ***\r\n");
      break;
    }
    fname = read_filename();
    if (fname == NULL) {
      fd_printf(STO, "*** cannot read filename ***\r\n");
      break;
    }
    run_cmd(tty_fd, xfr_cmd, fname);
    free(fname);
    break;
  case KEY_HEX:
    n = read_hex(hexbuf, sizeof(hexbuf));
    if (n < 0) {
      fd_printf(STO, "*** cannot read hex ***\r\n");
      break;
    }
    if (tty_q_push((char *)hexbuf, n) != n)
      fd_printf(STO, "*** output buffer full ***\r\n");
    fd_printf(STO, "*** wrote %d bytes ***\r\n", n);
    break;
  case KEY_BREAK:
    term_break(tty_fd);
    fd_printf(STO, "\r\n*** break sent ***\r\n");
    break;
  default:
    break;
  }

  return 0;
}

/**********************************************************************/

static struct timeval *msec2tv(struct timeval *tv, long ms) {
  tv->tv_sec = ms / 1000;
  tv->tv_usec = (ms % 1000) * 1000;

  return tv;
}

/**********************************************************************/

void deadly_handler(int signum) {
  (void)signum; /* silence unused warning */

  if (!sig_exit) {
    sig_exit = 1;
    kill(0, SIGTERM);
  }
}

void establish_signal_handlers(void) {
  struct sigaction exit_action, ign_action;

  /* Set up the structure to specify the exit action. */
  exit_action.sa_handler = deadly_handler;
  sigemptyset(&exit_action.sa_mask);
  exit_action.sa_flags = 0;

  /* Set up the structure to specify the ignore action. */
  ign_action.sa_handler = SIG_IGN;
  sigemptyset(&ign_action.sa_mask);
  ign_action.sa_flags = 0;

  // sigaction(SIGTERM, &exit_action, NULL);
  // sigaction(SIGINT, &exit_action, NULL);

  // sigaction(SIGHUP, &ign_action, NULL);
  // sigaction(SIGQUIT, &ign_action, NULL);
  // sigaction(SIGALRM, &ign_action, NULL);
  // sigaction(SIGUSR1, &ign_action, NULL);
  // sigaction(SIGUSR2, &ign_action, NULL);
  // sigaction(SIGPIPE, &ign_action, NULL);
}

void set_dtr_rts(void) {
  int r;
  if (opts.lower_rts) {
    r = term_lower_rts(tty_fd);
    if (r < 0)
      fatal("failed to lower RTS of port: %s",
            term_strerror(term_errno, errno));
    rts_up = 0;
  } else if (opts.raise_rts) {
    r = term_raise_rts(tty_fd);
    if (r < 0)
      fatal("failed to raise RTS of port: %s",
            term_strerror(term_errno, errno));
    rts_up = 1;
  }

  if (opts.lower_dtr) {
    r = term_lower_dtr(tty_fd);
    if (r < 0)
      fatal("failed to lower DTR of port: %s",
            term_strerror(term_errno, errno));
    dtr_up = 0;
  } else if (opts.raise_dtr) {
    r = term_raise_dtr(tty_fd);
    if (r < 0)
      fatal("failed to raise DTR of port: %s",
            term_strerror(term_errno, errno));
    dtr_up = 1;
  }
  /* Try to read the status of the modem-conrtol lines from the
     port. */
  r = term_get_mctl(tty_fd);
  if (r >= 0 && r != MCTL_UNAVAIL) {
    rts_up = (r & MCTL_RTS) != 0;
    dtr_up = (r & MCTL_DTR) != 0;
  }
}

static int xcode = EXIT_SUCCESS;
static int ler;

/* loop-exit reason */
enum le_reason { LE_CMD, LE_IDLE, LE_STDIN, LE_SIGNAL };

enum le_reason tty_loop(char *buff_rd, int nbytes) {
  int rdbytes = 0;
  enum { ST_COMMAND, ST_TRANSPARENT } state;
  fd_set rdset, wrset;
  int r, n = 0;

  state = ST_TRANSPARENT;

  while (1) {
    struct timeval tv, *ptv;

    ptv = NULL;
    FD_ZERO(&rdset);
    FD_ZERO(&wrset);
    if (!opts.exit)
      FD_SET(tty_fd, &rdset);
    if (tty_q.len) {
      FD_SET(tty_fd, &wrset);
    } else {
      if (opts.exit_after >= 0) {
        msec2tv(&tv, opts.exit_after);
        ptv = &tv;
      }
    }

    r = select(tty_fd + 1, &rdset, &wrset, NULL, ptv);
    if (r < 0) {
      if (errno == EINTR)
        continue;
      else
        fatal("select failed: %d : %s", errno, strerror(errno));
    }
    if (r == 0) {
      /* Idle timeout expired */
      return ler = LE_IDLE;
    }
  skip_proc_STI:
    if (FD_ISSET(tty_fd, &rdset)) {
      if (buff_rd == NULL) {
        continue;
      }

      char buff_map[TTY_RD_SZ * M_MAXMAP];

      /* read from port */

      do {
        n = read(tty_fd, &buff_rd[rdbytes], nbytes - rdbytes);
      } while (n < 0 && errno == EINTR);
      if (n == 0) {
        fatal("read zero bytes from port");
      } else if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
          fatal("read from port failed: %s", strerror(errno));
      } else {
        rdbytes += n;
        char *bmp = buff_map;
        if (opts.log_filename)
          if (writen_ni(log_fd, buff_rd, n) < n)
            fatal("write to logfile failed: %s", strerror(errno));
        for (int i = 0; i < n; i++) {
          bmp += do_map(bmp, opts.imap, buff_rd[i]);
        }
        n = bmp - buff_map;
        // if (writen_ni(STO, buff_map, n) < n)
        //   fatal("write to stdout failed: %s", strerror(errno));
        if (rdbytes == nbytes) {
          return LE_SIGNAL;
        }
      }
    }

    if (FD_ISSET(tty_fd, &wrset)) {

      /* write to port */

      int sz;
      sz = (tty_q.len < tty_write_sz) ? tty_q.len : tty_write_sz;
      do {
        n = write(tty_fd, tty_q.buff, sz);
        // printf("written %d bytes\n", n);
      } while (n < 0 && errno == EINTR);
      if (n <= 0)
        fatal("write to port failed: %s", strerror(errno));
      if (opts.lecho && opts.log_filename)
        if (writen_ni(log_fd, tty_q.buff, n) < n)
          fatal("write to logfile failed: %s", strerror(errno));
      memmove(tty_q.buff, tty_q.buff + n, tty_q.len - n);
      tty_q.len -= n;
    }
  }
  return ler = LE_SIGNAL;
}

int tty_init() {
  int r;

  establish_signal_handlers();

  r = term_lib_init();
  if (r < 0)
    fatal("term_lib_init failed: %s", term_strerror(term_errno, errno));

#ifdef UUCP_LOCK_DIR
  if (!opts.nolock)
    uucp_lockname(UUCP_LOCK_DIR, opts.port);
  if (uucp_lock() < 0)
    fatal("cannot lock %s: %s", opts.port, strerror(errno));
#endif

  if (opts.log_filename) {
    log_fd = open(opts.log_filename, O_CREAT | O_RDWR | O_APPEND,
                  S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
    if (log_fd < 0)
      fatal("cannot open %s: %s", opts.log_filename, strerror(errno));
  }

  tty_fd = open(opts.port, O_RDWR | O_NONBLOCK | O_NOCTTY);
  if (tty_fd < 0)
    fatal("cannot open %s: %s", opts.port, strerror(errno));

#ifdef USE_FLOCK
  if (!opts.nolock) {
    r = flock(tty_fd, LOCK_EX | LOCK_NB);
    if (r < 0)
      fatal("cannot lock %s: %s", opts.port, strerror(errno));
  }
#endif

  if (opts.noinit) {
    r = term_add(tty_fd);
  } else {
    r = term_set(tty_fd, 1,      /* raw mode. */
                 opts.baud,      /* baud rate. */
                 opts.parity,    /* parity. */
                 opts.databits,  /* data bits. */
                 opts.stopbits,  /* stop bits. */
                 opts.flow,      /* flow control. */
                 1,              /* local or modem */
                 !opts.noreset); /* hup-on-close. */
  }
  if (r < 0)
    fatal("failed to add port: %s", term_strerror(term_errno, errno));
  /* Set DTR and RTS status, as quickly as possible after opening
     the serial port (i.e. before configuring it) */
  set_dtr_rts();
  r = term_apply(tty_fd, 0);
  if (r < 0)
    fatal("failed to config port: %s", term_strerror(term_errno, errno));
  /* Set DTR and RTS status *again* after configuring the port. On
     some systems term_apply() resets the status of DTR and / or
     RTS */
  set_dtr_rts();

  set_tty_write_sz(term_get_baudrate(tty_fd, NULL));

  /* Check for settings mismatch and print warning */
  if (!opts.quiet && !opts.noinit) {
    pinfo("!! Settings mismatch !!");
    if (!opts.noescape)
      pinfo(" Type [C-%c] [C-%c] to see actual port settings",
            KEYC(opts.escape), KEYC(KEY_STATUS));
    pinfo("\r\n");
  }

  if (!opts.exit) {
    if (isatty(STI)) {
      r = term_add(STI);
      if (r < 0)
        fatal("failed to add I/O device: %s", term_strerror(term_errno, errno));
      term_set_raw(STI);
      r = term_apply(STI, 0);
      if (r < 0)
        fatal("failed to set I/O device to raw mode: %s",
              term_strerror(term_errno, errno));
    } else {
      pinfo("!! STDIN is not a TTY !! Continue anyway...\r\n");
    }
  } else {
    close(STI);
  }

#ifdef LINENOISE
  init_history();
#endif

  /* Allocate output buffer with initial size */
  tty_q.buff = calloc(TTY_Q_SZ_MIN, sizeof(*tty_q.buff));
  if (!tty_q.buff)
    fatal("out of memory");
  tty_q.sz = TTY_Q_SZ_MIN;
  tty_q.len = 0;

  /* Prime output buffer with initstring */
  if (opts.initstring) {
    if (opts.noinit) {
      pinfo("Ignoring init-string (--noinit)\r\n");
    } else {
      int l;
      l = strlen(opts.initstring);
      if (tty_q_push(opts.initstring, l) != l) {
        fatal("initstring too long!");
      }
    }
  }
  /* Free initstirng, no longer needed */
  if (opts.initstring) {
    free(opts.initstring);
    opts.initstring = NULL;
  }

#ifndef NO_HELP
  if (!opts.noescape) {
    pinfo("Type [C-%c] [C-%c] to see available commands\r\n", KEYC(opts.escape),
          KEYC(KEY_HELP));
  }
#endif
  pinfo("Terminal ready\r\n");

  return EXIT_SUCCESS;
}

int tty_exit() {

  /* Terminating picocom */
  pinfo("\r\n");
  pinfo("Terminating...\r\n");

  if (ler == LE_CMD || ler == LE_SIGNAL)
    cleanup(0 /* drain */, opts.noreset, opts.hangup);
  else
    cleanup(1 /* drain */, opts.noreset, opts.hangup);

  if (ler == LE_SIGNAL) {
    pinfo("Picocom was killed\r\n");
    xcode = EXIT_FAILURE;
  } else
    pinfo("Thanks for using picocom\r\n");

  return xcode;
}

/**********************************************************************/

/*
 * Local Variables:
 * mode:c
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 */
