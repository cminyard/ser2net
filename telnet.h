
#ifndef _SER2NET_TELNET_H
#define _SER2NET_TELNET_H

#include "buffer.h"

/* Telnet commands */
#define TN_SE   240
#define TN_DATA_MARK 242
#define TN_BREAK 243
#define TN_SB   250
#define TN_WILL	251
#define TN_WONT	252
#define TN_DO	253
#define TN_DONT	254
#define TN_IAC  255

#define TN_OPT_BINARY_TRANSMISSION	0
#define TN_OPT_ECHO			1
#define TN_OPT_SUPPRESS_GO_AHEAD	3
#define TN_OPT_COM_PORT			44

typedef struct telnet_data_s telnet_data_t;

#define TELNET_CMD_END_OPTION	255
struct telnet_cmd
{
    unsigned char option;
    unsigned int i_will : 1;
    unsigned int i_do : 1;
    unsigned int sent_will : 1;
    unsigned int sent_do : 1;
    unsigned int rem_will : 1;
    unsigned int rem_do : 1;

    /* If this is non-null, this will be called on any options
       received by the code */
    void (*option_handler)(void *cb_data, unsigned char *option, int len);

    /* If this is non-null, this will be called if a will command is
       sent by the remote end.  If this returns 1, the option will be
       allowed (a DO is returned).  If it return 0, a DONT is
       returned. */
    int (*will_handler)(void *cb_data);
};

#define MAX_TELNET_CMD_SIZE 31

#define MAX_TELNET_CMD_XMIT_BUF 256

struct telnet_data_s
{
  /* Incoming telnet commands.  This is "+1" because the last byte
     always holds the previous byte received, even on an overflow, so
     that the end of the options can be correctly detected. */
    unsigned char  telnet_cmd[MAX_TELNET_CMD_SIZE + 1];
    int            telnet_cmd_pos;      /* Current position in the
					   telnet_cmd buffer.  If zero,
					   no telnet command is in
					   progress. */
    int            suboption_iac;	/* If true, we are in a
					   suboption and processing an
					   IAC. */

    /* Outgoing telnet commands.  The output routines should look at
       this *first* to see if they should transmit some data from
       here. */
    struct sbuf out_telnet_cmd;
    unsigned char out_telnet_cmdbuf[MAX_TELNET_CMD_XMIT_BUF];

    /* Marks that an output error occurred.  The only error that can
       occur is "out of space", meaning that the code needed to do
       output wut out_telnet_cmd was full. */
    int error;

    void *cb_data;
    void (*output_ready)(void *cb_data);
    void (*cmd_handler)(void *cb_data, unsigned char cmd);

    /* An array of commands, the last option must be set to 255 to
       mark the end of the array. */
    struct telnet_cmd *cmds;
};

/* Send a telnet command.  This will set td->error to true if an
   output error occurs (out of space). */
void telnet_cmd_send(telnet_data_t *td, unsigned char *cmd, int len);

/* Received some data from the TCP port representing telnet, process
   it.  The leftover length is returned by this function, and the
   telnet data will be removed from data.  This will set td->error to
   true if an output error occurs (out of space).*/
int process_telnet_data(unsigned char *data, int len, telnet_data_t *td);

/* Used to send an option.  The option should *not* contain the inital
   "255 250" nor the tailing "255 240" and should *not* double
   internal 255 values. */
void telnet_send_option(telnet_data_t *td, unsigned char *option, int len);

/* Initialize the telnet data. */
void telnet_init(telnet_data_t *td,
		 void *cb_data,
		 void (*output_ready)(void *cb_data),
		 void (*cmd_handler)(void *cb_data, unsigned char cmd),
		 struct telnet_cmd *cmds,
		 unsigned char *init_seq,
		 int init_seq_len);

#endif /* _SER2NET_TELNET_H */
