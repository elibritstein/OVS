/* NVIDIA */

#include <config.h>

#include <errno.h>

#include "cmap.h"
#include "hash.h"
#include "library.h"
#include "library-provider.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/vlog.h"
#include "ovs-thread.h"
#include "unixctl.h"
#include "util.h"
#include "vswitch-idl.h"

VLOG_DEFINE_THIS_MODULE(library);

struct library_registered_class {
    struct cmap_node cmap_node; /* In 'library_classes', by class->name. */
    const struct library_class *class;
};

static struct ovs_mutex library_class_mutex = OVS_MUTEX_INITIALIZER;

/* Contains 'struct library_registered_class'es. */
static struct cmap library_classes = CMAP_INITIALIZER;

static struct library_registered_class *
library_lookup_class(const char *name)
{
    struct library_registered_class *rc;

    CMAP_FOR_EACH_WITH_HASH (rc, cmap_node, hash_string(name, 0),
                             &library_classes) {
        if (!strcmp(name, rc->class->name)) {
            return rc;
        }
    }
    return NULL;
}

/* Initializes and registers a new library provider. */
OVS_UNUSED
static int
library_register_one(const struct library_class *new_class)
    OVS_EXCLUDED(library_class_mutex)
{
    int error = 0;

    ovs_mutex_lock(&library_class_mutex);
    if (library_lookup_class(new_class->name)) {
        VLOG_WARN("attempted to register duplicate library provider: %s",
                   new_class->name);
        error = EEXIST;
    } else {
        struct library_registered_class *rc;

        rc = xmalloc(sizeof *rc);
        rc->class = new_class;
        cmap_insert(&library_classes, &rc->cmap_node,
                    hash_string(new_class->name, 0));
    }
    ovs_mutex_unlock(&library_class_mutex);

    return error;
}

static void
library_list(struct unixctl_conn *conn, int argc OVS_UNUSED,
             const char *argv[] OVS_UNUSED,
             void *aux OVS_UNUSED)
{
    struct ds reply = DS_EMPTY_INITIALIZER;
    struct library_registered_class *rc;

    CMAP_FOR_EACH (rc, cmap_node, &library_classes) {
        ds_put_format(&reply, "- %s\n", rc->class->name);
    }
    unixctl_command_reply(conn, ds_cstr(&reply));
    ds_destroy(&reply);
}

void
library_register(void)
{
    unixctl_command_register("library/list", "",
                             0, 0, library_list,
                             NULL);
}

void
library_init(const char *name, const struct smap *cfg)
{
    struct library_registered_class *rc;

    rc = library_lookup_class(name);
    if (!rc) {
        VLOG_WARN_ONCE("Unkown library '%s'", name);
        return;
    }

    if (!rc->class->init) {
        return;
    }

    rc->class->init(cfg);
}

void
library_status(const struct ovsrec_library *lib_cfg)
{
    struct library_registered_class *rc;

    rc = library_lookup_class(lib_cfg->name);
    if (!rc) {
        VLOG_WARN_ONCE("Unkown library '%s'", lib_cfg->name);
        return;
    }

    rc->class->status(lib_cfg);
}
