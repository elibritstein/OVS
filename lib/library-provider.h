
#ifndef LIBRARY_PROVIDER_H
#define LIBRARY_PROVIDER_H 1

struct ovsrec_library;
struct smap;

struct library_class {
    const char *name;

/* ## ------------------- ## */
/* ## Top-Level Functions ## */
/* ## ------------------- ## */

    /* Called when the library provider is registered, typically at program
     * startup.  Returning an error from this function will prevent any network
     * device in this class from being opened.
     *
     * This function may be set to null if a network device class needs no
     * initialization at registration time. */
    void (*init)(const struct smap *cfg);
    void (*status)(const struct ovsrec_library *lib);
};

#endif /* LIBRARY_PROVIDER_H */
