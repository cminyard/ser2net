#ifndef _SER2NET_BUFFER_H
#define _SER2NET_BUFFER_H

struct sbuf {
    unsigned char *buf;
    unsigned int maxsize;
    unsigned int cursize;
    unsigned int pos;
};

int buffer_write(int fd, struct sbuf *buf, int *buferr);

int buffer_output(struct sbuf *buf, unsigned char *data, unsigned int len);

int buffer_outchar(struct sbuf *buf, unsigned char data);

void buffer_init(struct sbuf *buf, unsigned char *data, unsigned int datalen);

#define buffer_left(buf) ((buf)->maxsize - (buf)->cursize)

#define buffer_cursize(buf) ((buf)->cursize)

#define buffer_reset(buf) \
    do {			\
	(buf)->cursize = 0;	\
	(buf)->pos = 0;		\
    } while(0)

#endif /* _SER2NET_BUFFER_H */
