#ifndef AUTH_MELLON_COMPAT_H
#define AUTH_MELLON_COMPAT_H

#include <glib.h>

#include "ap_config.h"
#include "ap_release.h"
#ifdef AP_NEED_SET_MUTEX_PERMS
#include "unixd.h"
#endif

/* Old glib compatibility */
#if (GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 14)

static void g_hash_table_get_keys_helper(gpointer key, gpointer value,
                                         gpointer user_data)
{
    GList **out = user_data;

    *out = g_list_prepend(*out, key);
}

static GList *g_hash_table_get_keys(GHashTable *ht)
{
    GList *ret = NULL;

    g_hash_table_foreach(ht, g_hash_table_get_keys_helper, &ret);

    return g_list_reverse(ret);
}
#endif


/* "remote_ip" in struct conn_rec changed name to "client_ip" in Apache 2.4.
 * This function retrieves the corrent member depending on the Apache version.
 */
static inline const char *am_compat_request_ip(request_rec *r) {
#if (AP_SERVER_MAJORVERSION_NUMBER == 2) && (AP_SERVER_MINORVERSION_NUMBER < 4)
    return r->connection->remote_ip;
#else
    return r->connection->client_ip;
#endif
}

/* unixd_set_global_mutex_perms changed name to ap_unixd_set_global_mutex_perms
 * in Apache 2.4. This function provides a wrapper with the new name for old
 * versions.
 */
#ifdef AP_NEED_SET_MUTEX_PERMS
#if (AP_SERVER_MAJORVERSION_NUMBER == 2) && (AP_SERVER_MINORVERSION_NUMBER < 4)
static inline apr_status_t ap_unixd_set_global_mutex_perms(apr_global_mutex_t *gmutex) {
    return unixd_set_global_mutex_perms(gmutex);
}
#endif
#endif /* AP_NEED_SET_MUTEX_PERMS */

#endif /* AUTH_MELLON_COMPAT_H */
