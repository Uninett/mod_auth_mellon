/*
 *
 *   auth_mellon_cache.c: an authentication apache module
 *   Copyright © 2003-2007 UNINETT (http://www.uninett.no/)
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "auth_mellon.h"

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(auth_mellon);
#endif

/* Calculate the pointer to a cache entry.
 *
 * Parameters:
 *  am_mod_cfg_rec *mod_cfg  The module configuration.
 *  void *table              The base pointer for the table.
 *  apr_size_t index         The index we are looking for.
 *
 * Returns:
 *  The session entry with the given index.
 */
static inline am_cache_entry_t *am_cache_entry_ptr(am_mod_cfg_rec *mod_cfg,
                                                   void *table, apr_size_t index)
{
    uint8_t *table_calc;
    table_calc = table;
    return (am_cache_entry_t *)&table_calc[mod_cfg->init_entry_size * index];
}

/* Initialize the session table.
 *
 * Parameters:
 *  am_mod_cfg_rec *mod_cfg  The module configuration.
 *
 * Returns:
 *  Nothing.
 */
void am_cache_init(am_mod_cfg_rec *mod_cfg)
{
    void *table;
    apr_size_t i;
    /* Initialize the session table. */
    table = apr_shm_baseaddr_get(mod_cfg->cache);
    for (i = 0; i < mod_cfg->init_cache_size; i++) {
        am_cache_entry_t *e = am_cache_entry_ptr(mod_cfg, table, i);
        e->key[0] = '\0';
        e->access = 0;
    }
}

/* This function locks the session table and locates a session entry.
 * Unlocks the table and returns NULL if the entry wasn't found.
 * If a entry was found, then you _must_ unlock it with am_cache_unlock
 * after you are done with it.
 *
 * Parameters:
 *  request_rec *r       The request we are processing.
 *  am_cache_key_t type  AM_CACHE_SESSION or AM_CACHE_NAMEID
 *  const char *key      The session key or user
 *
 * Returns:
 *  The session entry on success or NULL on failure.
 */
am_cache_entry_t *am_cache_lock(request_rec *r, 
                                am_cache_key_t type,
                                const char *key)
{
    am_mod_cfg_rec *mod_cfg;
    void *table;
    apr_size_t i;
    int rv;
    char buffer[512];


    /* Check if we have a valid session key. We abort if we don't. */
    if (key == NULL)
        return NULL;

    switch (type) {
    case AM_CACHE_SESSION:
        if (strlen(key) != AM_ID_LENGTH)
            return NULL;
        break;
    case AM_CACHE_NAMEID:
        break;
    default:
        return NULL;
        break;
    }

    mod_cfg = am_get_mod_cfg(r->server);


    /* Lock the table. */
    if((rv = apr_global_mutex_lock(mod_cfg->lock)) != APR_SUCCESS) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "apr_global_mutex_lock() failed [%d]: %s",
                      rv, apr_strerror(rv, buffer, sizeof(buffer)));
        return NULL;
    }

    table = apr_shm_baseaddr_get(mod_cfg->cache);


    for(i = 0; i < mod_cfg->init_cache_size; i++) {
        am_cache_entry_t *e = am_cache_entry_ptr(mod_cfg, table, i);
        const char *tablekey;

        if (e->key[0] == '\0') {
            /* This entry is empty. Skip it. */
            continue;
        }

        switch (type) {
        case AM_CACHE_SESSION:
            tablekey = e->key;
            break;
        case AM_CACHE_NAMEID:
            /* tablekey may be NULL */
            tablekey = am_cache_env_fetch_first(e, "NAME_ID");
            break;
        default:
            tablekey = NULL;
            break;
        }

        if (tablekey == NULL)
            continue;

        if(strcmp(tablekey, key) == 0) {
            apr_time_t now = apr_time_now();
            /* We found the entry. */
            if(e->expires > now) {
                /* And it hasn't expired. */
                return e;
            }
            else {
                am_diag_log_cache_entry(r, 0, e,
                                        "found expired session, now %s\n",
                                        am_diag_time_t_to_8601(r, now));
            }
        }
    }


    /* We didn't find a entry matching the key. Unlock the table and
     * return NULL;
     */
    apr_global_mutex_unlock(mod_cfg->lock);
    return NULL;
}

static inline bool am_cache_entry_slot_is_empty(am_cache_storage_t *slot)
{
    return (slot->ptr == 0);
}

static inline void am_cache_storage_null(am_cache_storage_t *slot)
{
    slot->ptr = 0;
}

static inline void am_cache_entry_env_null(am_cache_entry_t *e)
{
    for (int i = 0; i < AM_CACHE_ENVSIZE; i++) {
        am_cache_storage_null(&e->env[i].varname);
        am_cache_storage_null(&e->env[i].value);
    }
}

static inline apr_size_t am_cache_entry_pool_left(am_cache_entry_t *e)
{
    return e->pool_size - e->pool_used;
}

static inline apr_size_t am_cache_entry_pool_size(am_mod_cfg_rec *cfg)
{
    return cfg->init_entry_size - sizeof(am_cache_entry_t);
}

/* This function sets a string into the specified storage on the entry.
 *
 * NOTE: The string pointer may be NULL, in that case storage is freed
 * and set to NULL.
 *
 * Parametrs:
 *  am_cache_entry_t *entry         Pointer to an entry
 *  am_cache_storage_t *slot        Pointer to storage
 *  const char *string              Pointer to a replacement string
 *
 * Returns:
 *  0 on success, HTTP_INTERNAL_SERVER_ERROR on error.
 */
static int am_cache_entry_store_string(am_cache_entry_t *entry,
                                       am_cache_storage_t *slot,
                                       const char *string)
{
    char *datastr = NULL;
    apr_size_t datalen = 0;
    apr_size_t str_len = 0;

    if (string == NULL) return 0;

    if (slot->ptr != 0) {
        datastr = &entry->pool[slot->ptr];
        datalen = strlen(datastr) + 1;
    }
    str_len = strlen(string) + 1;
    if (str_len - datalen <= 0) {
        memcpy(datastr, string, str_len);
        return 0;
    }

    /* recover space if slot happens to point to the last allocated space */
    if (slot->ptr + datalen == entry->pool_used) {
        entry->pool_used -= datalen;
        slot->ptr = 0;
    }

    if (am_cache_entry_pool_left(entry) < str_len) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "apr_cache_entry_store_string() asked %zd available: %zd. "
                     "It may be a good idea to increase MellonCacheEntrySize.",
                     str_len, am_cache_entry_pool_left(entry));
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    slot->ptr = entry->pool_used;
    datastr = &entry->pool[slot->ptr];
    memcpy(datastr, string, str_len);
    entry->pool_used += str_len;
    return 0;
}

/* Returns a pointer to the string in the storage slot specified
 *
 *
 * Parametrs:
 *  am_cache_entry_t *entry         Pointer to an entry
 *  am_cache_storage_t *slot        Pointer to storage slot
 *
 * Returns:
 *  A string or NULL if the slot is empty.
 */
const char *am_cache_entry_get_string(am_cache_entry_t *e,
                                      am_cache_storage_t *slot)
{
    char *ret = NULL;

    if (slot->ptr != 0) {
        ret = &e->pool[slot->ptr];
    }

    return ret;
}

/* This function locks the session table and creates a new session entry.
 * It will first attempt to locate a free session. If it doesn't find a
 * free session, then it will take the least recentry used session.
 *
 * Remember to unlock the table with am_cache_unlock(...) afterwards.
 *
 * Parameters:
 *  request_rec *r       The request we are processing.
 *  const char *key      The key of the session to allocate.
 *  const char *cookie_token  The cookie token to tie the session to.
 *
 * Returns:
 *  The new session entry on success. NULL if key is a invalid session
 *  key.
 */
am_cache_entry_t *am_cache_new(request_rec *r,
                               const char *key,
                               const char *cookie_token)
{
    am_cache_entry_t *t;
    am_mod_cfg_rec *mod_cfg;
    void *table;
    apr_time_t current_time;
    int i;
    apr_time_t age;
    int rv;
    char buffer[512];

    /* Check if we have a valid session key. We abort if we don't. */
    if(key == NULL || strlen(key) != AM_ID_LENGTH) {
        return NULL;
    }


    mod_cfg = am_get_mod_cfg(r->server);


    /* Lock the table. */
    if((rv = apr_global_mutex_lock(mod_cfg->lock)) != APR_SUCCESS) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "apr_global_mutex_lock() failed [%d]: %s",
                      rv, apr_strerror(rv, buffer, sizeof(buffer)));
        return NULL;
    }

    table = apr_shm_baseaddr_get(mod_cfg->cache);

    /* Get current time. If we find a entry with expires <= the current
     * time, then we can use it.
     */
    current_time = apr_time_now();

    /* We will use 't' to remember the best/oldest entry. We
     * initalize it to the first entry in the table to simplify the
     * following code (saves test for t == NULL).
     */
    t = am_cache_entry_ptr(mod_cfg, table, 0);

    /* Iterate over the session table. Update 't' to match the "best"
     * entry (the least recently used). 't' will point a free entry
     * if we find one. Otherwise, 't' will point to the least recently
     * used entry.
     */
    for(i = 0; i < mod_cfg->init_cache_size; i++) {
        am_cache_entry_t *e = am_cache_entry_ptr(mod_cfg, table, i);
        if (e->key[0] == '\0') {
            /* This entry is free. Update 't' to this entry
             * and exit loop.
             */
            t = e;
            break;
        }

        if (e->expires <= current_time) {
            /* This entry is expired, and is therefore free.
             * Update 't' and exit loop.
             */
            t = e;
            am_diag_log_cache_entry(r, 0, e,
                                    "%s ejecting expired sessions, now %s\n",
                                    __func__,
                                    am_diag_time_t_to_8601(r, current_time));
            break;
        }

        if (e->access < t->access) {
            /* This entry is older than 't' - update 't'. */
            t = e;
        }
    }


    if(t->key[0] != '\0' && t->expires > current_time) {
        /* We dropped a LRU entry. Calculate the age in seconds. */
        age = (current_time - t->access) / 1000000;

        if(age < 3600) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_NOTICE, 0, r,
                          "Dropping LRU entry entry with age = %" APR_TIME_T_FMT
                          "s, which is less than one hour. It may be a good"
                          " idea to increase MellonCacheSize.",
                          age);
        }
    }

    /* Now 't' points to the entry we are going to use. We initialize
     * it and returns it.
     */

    strcpy(t->key, key);

    /* Far far into the future. */
    t->expires = 0x7fffffffffffffffLL;

    t->logged_in = 0;
    t->size = 0;

    am_cache_storage_null(&t->cookie_token);
    am_cache_storage_null(&t->user);
    am_cache_storage_null(&t->lasso_identity);
    am_cache_storage_null(&t->lasso_session);
    am_cache_storage_null(&t->lasso_saml_response);
    am_cache_entry_env_null(t);

    t->pool_size = am_cache_entry_pool_size(mod_cfg);
    t->pool[0] = '\0';
    t->pool_used = 1;

    rv = am_cache_entry_store_string(t, &t->cookie_token, cookie_token);
    if (rv != 0) {
        /* For some strange reason our cookie token is too big to fit in the
         * session. This should never happen outside of absurd configurations.
         */
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Unable to store cookie token in new session.");
        t->key[0] = '\0'; /* Mark the entry as free. */
        apr_global_mutex_unlock(mod_cfg->lock);
        return NULL;
    }

    am_diag_printf(r, "%s created new session, id=%s at %s"
                   " cookie_token=\"%s\"\n",
                   __func__, t->key, am_diag_time_t_to_8601(r, current_time),
                   cookie_token);

    return t;
}


/* This function unlocks a session entry.
 *
 * Parameters:
 *  request_rec *r           The request we are processing.
 *  am_cache_entry_t *entry  The session entry.
 *
 * Returns:
 *  Nothing.
 */
void am_cache_unlock(request_rec *r, am_cache_entry_t *entry)
{
    am_mod_cfg_rec *mod_cfg;

    /* Update access time. */
    entry->access = apr_time_now();

    mod_cfg = am_get_mod_cfg(r->server);
    apr_global_mutex_unlock(mod_cfg->lock);
}


/* This function updates the expire-timestamp of a session, if the new
 * timestamp is earlier than the previous.
 *
 * Parameters:
 *  request_rec *r        The request we are processing.
 *  am_cache_entry_t *t   The current session.
 *  apr_time_t expires    The new timestamp.
 *
 * Returns:
 *  Nothing.
 */
void am_cache_update_expires(request_rec *r, am_cache_entry_t *t, apr_time_t expires)
{
    /* Check if we should update the expires timestamp. */
    if(t->expires == 0 || t->expires > expires) {
        t->expires = expires;
    }
}


/* This function appends a name-value pair to a session. It is possible to
 * store several values with the same name. This is the method used to store
 * multivalued fields.
 *
 * Parameters:
 *  am_cache_entry_t *t  The current session.
 *  const char *var      The name of the value to be stored.
 *  const char *val      The value which should be stored in the session.
 *
 * Returns:
 *  OK on success or HTTP_INTERNAL_SERVER_ERROR on failure.
 */
int am_cache_env_append(am_cache_entry_t *t,
                        const char *var, const char *val)
{
    int status;

    /* Make sure that the name and value will fit inside the
     * fixed size buffer.
     */
    if(t->size >= AM_CACHE_ENVSIZE) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "Unable to store attribute value because we have"
                     " reached the maximum number of name-value pairs for"
                     " this session. The maximum number is %d.",
                     AM_CACHE_ENVSIZE);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    status = am_cache_entry_store_string(t, &t->env[t->size].varname, var);
    if (status != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "Unable to store session data because there is no more "
                     "space in the session. Attribute Name = \"%s\".", var);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    status = am_cache_entry_store_string(t, &t->env[t->size].value, val);
    if (status != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "Unable to store session data because there is no more "
                     "space in the session. Attribute Value = \"%s\".", val);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    t->size++;

    return OK;
}

/* This function fetches a value from a session.
 * If multiple values are available, the first one is returned.
 *
 * Parameters:
 *  am_cache_entry_t *t  The current session.
 *  const char *var      The name of the value to be stored.
 *
 * Returns:
 *  The first value, NULL if it does not exist.
 */
const char *am_cache_env_fetch_first(am_cache_entry_t *t,
                                     const char *var)
{
    const char *str;
    int i;

    for (i = 0; i < t->size; i++) {
        str = am_cache_entry_get_string(t, &t->env[i].varname);
        if (str == NULL)
            break;
        if (strcmp(str, var) == 0)
            return am_cache_entry_get_string(t, &t->env[i].value);
    }

    return NULL;
}


/* This function populates the subprocess environment with data received
 * from the IdP.
 *
 * Parameters:
 *  request_rec *r       The request we should add the data to.
 *  am_cache_entry_t *t  The session data.
 *
 * Returns:
 *  Nothing.
 */
void am_cache_env_populate(request_rec *r, am_cache_entry_t *t)
{
    am_dir_cfg_rec *d;
    int i;
    apr_hash_t *counters;
    am_envattr_conf_t *env_varname_conf;
    const char *varname;
    const char *varname_prefix;
    const char *value;
    const char *prefixed_varname;
    int *count;
    int status;

    d = am_get_dir_cfg(r);

    /* Check if the user attribute has been set, and set it if it
     * hasn't been set. */
    if (am_cache_entry_slot_is_empty(&t->user)) {
        for(i = 0; i < t->size; ++i) {
            varname = am_cache_entry_get_string(t, &t->env[i].varname);
            if (strcasecmp(varname, d->userattr) == 0) {
                value = am_cache_entry_get_string(t, &t->env[i].value);
                status = am_cache_entry_store_string(t, &t->user, value);
                if (status != 0) {
                    AM_LOG_RERROR(APLOG_MARK, APLOG_NOTICE, 0, r,
                                  "Unable to store the user name because there"
                                  " is no more space in the session. "
                                  "Username = \"%s\".", value);
                }
            }
        }
    }

    /* Allocate a set of counters for duplicate variables in the list. */
    counters = apr_hash_make(r->pool);

    /* Populate the subprocess environment with the attributes we
     * received from the IdP.
     */
    for(i = 0; i < t->size; ++i) {
        varname = am_cache_entry_get_string(t, &t->env[i].varname);
        varname_prefix = "MELLON_";

        /* Check if we should map this name into another name. */
        env_varname_conf = (am_envattr_conf_t *)apr_hash_get(
            d->envattr, varname, APR_HASH_KEY_STRING);

        if(env_varname_conf != NULL) {
            varname = env_varname_conf->name;
            if (!env_varname_conf->prefixed) {
              varname_prefix = "";
            }
        }

        value = am_cache_entry_get_string(t, &t->env[i].value);

        /*  
         * If we find a variable remapping to MellonUser, use it.
         */
        if (am_cache_entry_slot_is_empty(&t->user) &&
            (strcasecmp(varname, d->userattr) == 0)) {
            status = am_cache_entry_store_string(t, &t->user, value);
            if (status != 0) {
                AM_LOG_RERROR(APLOG_MARK, APLOG_NOTICE, 0, r,
                              "Unable to store the user name because there"
                              " is no more space in the session. "
                              "Username = \"%s\".", value);
            }
        }

        prefixed_varname = apr_pstrcat(r->pool, varname_prefix, varname, NULL);

        /* Find the number of times this variable has been set. */
        count = apr_hash_get(counters, varname, APR_HASH_KEY_STRING);
        if(count == NULL) {

            /* This is the first time. Create a counter for this variable. */
            count = apr_palloc(r->pool, sizeof(int));
            *count = 0;
            apr_hash_set(counters, varname, APR_HASH_KEY_STRING, count);

            /* Add the variable without a suffix. */
            apr_table_set(r->subprocess_env,prefixed_varname,value);
        }

        /* Check if merging of environment variables is disabled.
         * This is either if it is NULL (default value if not configured
         * by user) or an empty string (if specifically disabled by the user).
         */
        if (d->merge_env_vars == NULL || *d->merge_env_vars == '\0') {
         
            /* Add the variable with a suffix indicating how many times it has
             * been added before.
             */
            apr_table_set(r->subprocess_env,
                          apr_psprintf(r->pool, "%s_%d", prefixed_varname,
                              (d->env_vars_index_start > -1
                                  ? *count + d->env_vars_index_start
                                  : *count)),
                          value);

        } else if (*count > 0) {

            /*
             * Merge multiple values, separating by default with ";"
             * this makes auth_mellon work same way mod_shib is:
             * https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPAttributeAccess
             */
             apr_table_set(r->subprocess_env,
                           prefixed_varname,
                           apr_pstrcat(r->pool, 
                                       apr_table_get(r->subprocess_env,prefixed_varname),
                                       d->merge_env_vars, value, NULL));
        }
          
        /* Increase the count. */
        ++(*count);

        if (d->env_vars_count_in_n > 0) {
             apr_table_set(r->subprocess_env,
                           apr_pstrcat(r->pool, prefixed_varname, "_N", NULL),
                           apr_itoa(r->pool, *count));
        }
    }

    if (!am_cache_entry_slot_is_empty(&t->user)) {
        /* We have a user-"name". Set r->user and r->ap_auth_type. */
        r->user = apr_pstrdup(r->pool, am_cache_entry_get_string(t, &t->user));
        r->ap_auth_type = apr_pstrdup(r->pool, "Mellon");
    } else {
        /* We don't have a user-"name". Log error. */
        AM_LOG_RERROR(APLOG_MARK, APLOG_NOTICE, 0, r,
                      "Didn't find the attribute \"%s\" in the attributes"
                      " which were received from the IdP. Cannot set a user"
                      " for this request without a valid user attribute.",
                      d->userattr);
    }


    /* Populate with the session? */
    if (d->dump_session) {
        char *session;
        const char *srcstr;
        int srclen, dstlen;

        srcstr = am_cache_entry_get_string(t, &t->lasso_session);
        srclen = strlen(srcstr);
        dstlen = apr_base64_encode_len(srclen);

        session = apr_palloc(r->pool, dstlen);
        (void)apr_base64_encode(session, srcstr, srclen);
        apr_table_set(r->subprocess_env, "MELLON_SESSION", session);
    }

    if (d->dump_saml_response) {
        const char *sr = am_cache_entry_get_string(t, &t->lasso_saml_response);
        if (sr) {
            apr_table_set(r->subprocess_env, "MELLON_SAML_RESPONSE", sr);
        }
    }
}


/* This function deletes a given key from the session store.
 *
 * Parameters:
 *  request_rec *r            The request we are processing.
 *  am_cache_entry_t *cache   The entry we are deleting.
 *
 * Returns:
 *  Nothing.
 */
void am_cache_delete(request_rec *r, am_cache_entry_t *cache)
{
    /* We write a null-byte at the beginning of the key to
     * mark this slot as unused. 
     */
    cache->key[0] = '\0';

    /* Unlock the entry. */
    am_cache_unlock(r, cache);
}


/* This function stores a lasso identity dump and a lasso session dump in
 * the given session object.
 *
 * Parameters:
 *  am_cache_entry_t *session   The session object.
 *  const char *lasso_identity  The identity dump.
 *  const char *lasso_session   The session dump.
 *
 * Returns:
 *  OK on success or HTTP_INTERNAL_SERVER_ERROR if the lasso state information
 *  is to big to fit in our session.
 */
int am_cache_set_lasso_state(am_cache_entry_t *session,
                             const char *lasso_identity,
                             const char *lasso_session,
                             const char *lasso_saml_response)
{
    int status;

    status = am_cache_entry_store_string(session,
                                         &session->lasso_identity,
                                         lasso_identity);
    if (status != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "Lasso identity is too big for storage. Size of lasso"
                     " identity is %" APR_SIZE_T_FMT ".",
                     (apr_size_t)strlen(lasso_identity));
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    status = am_cache_entry_store_string(session,
                                         &session->lasso_session,
                                         lasso_session);
    if (status != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "Lasso session is too big for storage. Size of lasso"
                     " session is %" APR_SIZE_T_FMT ".",
                     (apr_size_t)strlen(lasso_session));
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    status = am_cache_entry_store_string(session,
                                         &session->lasso_saml_response,
                                         lasso_saml_response);
    if (status != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "Lasso SAML response is too big for storage. Size of "
                     "lasso SAML Response is %" APR_SIZE_T_FMT ".",
                     (apr_size_t)strlen(lasso_saml_response));
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    return OK;
}


/* This function retrieves a lasso identity dump from the session object.
 *
 * Parameters:
 *  am_cache_entry_t *session  The session object.
 *
 * Returns:
 *  The identity dump, or NULL if we don't have a session dump.
 */
const char *am_cache_get_lasso_identity(am_cache_entry_t *session)
{
    return am_cache_entry_get_string(session, &session->lasso_identity);
}


/* This function retrieves a lasso session dump from the session object.
 *
 * Parameters:
 *  am_cache_entry_t *session  The session object.
 *
 * Returns:
 *  The session dump, or NULL if we don't have a session dump.
 */
const char *am_cache_get_lasso_session(am_cache_entry_t *session)
{
    return am_cache_entry_get_string(session, &session->lasso_session);
}
