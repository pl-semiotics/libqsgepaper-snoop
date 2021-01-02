#ifndef LIBQSGEPAPER_SNOOP_H_
#define LIBQSGEPAPER_SNOOP_H_

struct libqsgepaper_snoop_fb {
  int fb_fd;
  size_t offset;
  int socket_fd;
};

struct libqsgepaper_snoop_fb libqsgepaper_snoop(void);

#endif /* LIBQSGEPAPER_SNOOP_H_ */
