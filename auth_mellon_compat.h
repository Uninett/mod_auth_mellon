#ifndef AUTH_MELLON_COMPAT_H
#define AUTH_MELLON_COMPAT_H

#include <glib.h>

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

#endif /* AUTH_MELLON_COMPAT_H */
