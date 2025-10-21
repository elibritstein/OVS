/* NVIDIA */

#ifndef LIBRARY_H
#define LIBRARY_H 1

struct ovsrec_library;
struct smap;

void
library_register(void);

void
library_init(const char *name, const struct smap *cfg);

void
library_status(const struct ovsrec_library *lib_cfg);

#endif /* LIBRARY_H */
