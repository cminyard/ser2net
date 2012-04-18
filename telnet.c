
#include <stdlib.h>
#include <string.h>

#include "telnet.h"

static struct telnet_cmd *
find_cmd(struct telnet_cmd *array, unsigned char option)
{
    int i;

    for (i=0; array[i].option != 255; i++) {
	if (array[i].option == option)
	    return &array[i];
    }
    return NULL;
}

void
telnet_cmd_send(telnet_data_t *td, unsigned char *cmd, int len)
{
    if (buffer_output(&td->out_telnet_cmd, cmd, len) == -1) {
	/* Out of data, abort the connection.  This really shouldn't
	   happen.*/
	td->error = 1;
	return;
    }

    td->output_ready(td->cb_data);
}

static void
send_i(telnet_data_t *td, unsigned char type, unsigned char option)
{
    unsigned char i[3];
    i[0] = TN_IAC;
    i[1] = type;
    i[2] = option;
    telnet_cmd_send(td, i, 3);
}

static void
handle_telnet_cmd(telnet_data_t *td)
{
    int size = td->telnet_cmd_pos;
    unsigned char *cmd_str = td->telnet_cmd;
    struct telnet_cmd *cmd;
    int rv;

    if (size < 2)
	return;

    if (cmd_str[1] < 250) { /* A one-byte command. */
	td->cmd_handler(td->cb_data, cmd_str[1]);
    } else if (cmd_str[1] == 250) { /* Option */
	cmd = find_cmd(td->cmds, cmd_str[2]);
	if (!cmd)
	    return;
	cmd->option_handler(td->cb_data, cmd_str+2, size-2);
    } else if (cmd_str[1] == 251) { /* WILL */
	unsigned char option = cmd_str[2];
	cmd = find_cmd(td->cmds, option);
	if (!cmd || !cmd->sent_do) {
	    if ((!cmd) || (!cmd->i_will))
		send_i(td, TN_DONT, option);
	    else {
		rv = 1;
		if (cmd->will_handler)
		    rv = cmd->will_handler(td->cb_data);
		if (rv)
		    send_i(td, TN_DO, option);
		else
		    send_i(td, TN_DONT, option);
	    }
	} else if (cmd)
	    cmd->sent_do = 0;
	if (cmd) {
	    cmd->rem_will = 1;
	}
    } else if (cmd_str[1] == 252) { /* WONT */
	unsigned char option = cmd_str[2];
	cmd = find_cmd(td->cmds, option);
	if (!cmd || !cmd->sent_do)
	    send_i(td, TN_DONT, option);
	else if (cmd)
	    cmd->sent_do = 0;
	if (cmd)
	    cmd->rem_will = 0;
    } else if (cmd_str[1] == 253) { /* DO */
	unsigned char option = cmd_str[2];
	cmd = find_cmd(td->cmds, option);
	if (!cmd || !cmd->sent_will) {
	    if ((!cmd) || (! cmd->i_do))
		send_i(td, TN_WONT, option);
	    else
		send_i(td, TN_WILL, option);
	} else if (cmd)
	    cmd->sent_will = 0;
	if (cmd)
	    cmd->rem_do = 1;
    } else if (cmd_str[1] == 254) { /* DONT */
	unsigned char option = cmd_str[2];
	cmd = find_cmd(td->cmds, option);
	if (!cmd || !cmd->sent_will)
	    send_i(td, TN_WONT, option);
	else if (cmd)
	    cmd->sent_will = 0;
	if (cmd)
	    cmd->rem_do = 0;
    }
}

void
telnet_send_option(telnet_data_t *td, unsigned char *option, int len)
{
    unsigned int real_len;
    unsigned int i;

    /* Make sure to account for any duplicate 255s. */
    for (real_len=0, i=0; i<len; i++, real_len++) {
	if (option[i] == 255)
	    real_len++;
    }

    real_len += 4; /* Add the initial and end markers. */

    if (real_len > buffer_left(&td->out_telnet_cmd)) {
	/* Out of data, abort the connection.  This really shouldn't
	   happen.*/
	td->error = 1;
	return;
    }

    buffer_outchar(&td->out_telnet_cmd, 255);
    buffer_outchar(&td->out_telnet_cmd, 250);
    for (i=0; i<len; i++) {
	buffer_outchar(&td->out_telnet_cmd, option[i]);
	if (option[i] == 255)
	    buffer_outchar(&td->out_telnet_cmd, option[i]);
    }
    buffer_outchar(&td->out_telnet_cmd, 255);
    buffer_outchar(&td->out_telnet_cmd, 240);

    td->output_ready(td->cb_data);
}

static int
delete_char(unsigned char *data, int pos, int len)
{
    int i;

    for (i=pos; i<len-1; i++) {
	data[i] = data[i+1];
    }
    return len-1;
}

int
process_telnet_data(unsigned char *data, int len, telnet_data_t *td)
{
    int i;

    /* If it's a telnet port, get the commands out of the stream. */
    for (i=0; i<len;) {
	if (td->telnet_cmd_pos != 0) {
	    unsigned char tn_byte;

	    tn_byte = data[i];

	    if ((td->telnet_cmd_pos == 1) && (tn_byte == 255)) {
		/* Two IACs in a row causes one IAC to be sent, so
		   just let this one go through. */
		i++;
		td->telnet_cmd_pos = 0;
		continue;
	    }

	    len = delete_char(data, i, len);

	    if (td->telnet_cmd_pos == 1) {
		/* These are two byte commands, so we have
		   everything we need to handle the command. */
		td->telnet_cmd[td->telnet_cmd_pos] = tn_byte;
		td->telnet_cmd_pos++;
		if (tn_byte < 250) {
		    handle_telnet_cmd(td);
		    td->telnet_cmd_pos = 0;
		}
	    } else if (td->telnet_cmd_pos == 2) {
		td->telnet_cmd[td->telnet_cmd_pos] = tn_byte;
		td->telnet_cmd_pos++;
		if (td->telnet_cmd[1] != 250) {
		    /* It's a will/won't/do/don't */
		    handle_telnet_cmd(td);
		    td->telnet_cmd_pos = 0;
		}
	    } else {
		/* It's in a suboption, look for the end and IACs. */
	      if (td->suboption_iac) {
		    if (tn_byte == 240) {
			/* Remove the IAC 240 from the end. */
			td->telnet_cmd_pos--;
			handle_telnet_cmd(td);
			td->telnet_cmd_pos = 0;
		    } else if (tn_byte == 255) {
			/* Don't do anything, a double 255 means
			   we leave on 255 in. */
		    } else {
			/* If we have an IAC and an invalid
			   character, delete them both */
			td->telnet_cmd_pos--;
		    }
		    td->suboption_iac = 0;
		} else {
		    if (td->telnet_cmd_pos > MAX_TELNET_CMD_SIZE)
			/* Always store the last character
			   received in the final postition (the
			   array is one bigger than the max size)
			   so we can detect the end of the
			   suboption. */
			td->telnet_cmd_pos = MAX_TELNET_CMD_SIZE;
	  
		    td->telnet_cmd[td->telnet_cmd_pos] = tn_byte;
		    td->telnet_cmd_pos++;
		    if (tn_byte == 255)
		      td->suboption_iac = 1;
		}
	    }
	} else if (data[i] == 255) {
	    td->telnet_cmd[td->telnet_cmd_pos] = 255;
	    len = delete_char(data, i, len);
	    td->telnet_cmd_pos++;
	    td->suboption_iac = 0;
	} else {
	    i++;
	}
    }

    return len;
}

void
telnet_init(telnet_data_t *td,
	    void *cb_data,
	    void (*output_ready)(void *cb_data),
	    void (*cmd_handler)(void *cb_data, unsigned char cmd),
	    struct telnet_cmd *cmds,
	    unsigned char *init_seq,
	    int init_seq_len)
{
    td->telnet_cmd_pos = 0;
    buffer_init(&td->out_telnet_cmd, td->out_telnet_cmdbuf,
		sizeof(td->out_telnet_cmdbuf));
    td->error = 0;
    td->cb_data = cb_data;
    td->output_ready = output_ready;
    td->cmd_handler = cmd_handler;
    td->cmds = cmds;

    telnet_cmd_send(td, init_seq, init_seq_len);
}
