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

/* This function locks the session table and locates a session entry.
 * Unlocks the table and returns NULL if the entry wasn't found.
 * If a entry was found, then you _must_ unlock it with am_cache_unlock
 * after you are done with it.
 *
 * Parameters:
 *  server_rec *s        The current server.
 *  const char *key      The session key or user
 *  am_cache_key_t type  AM_CACHE_SESSION or AM_CACHE_NAMEID
 *
 * Returns:
 *  The session entry on success or NULL on failure.
 */
am_cache_entry_t *am_cache_lock(server_rec *s, 
                                am_cache_key_t type,
                                const char *key)
{
    am_mod_cfg_rec *mod_cfg;
    am_cache_entry_t *table;
    int i;
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
        if (strlen(key) > AM_CACHE_MAX_LASSO_IDENTITY_SIZE)
            return NULL;
        break;
    default:
        return NULL;
        break;
    }

    mod_cfg = am_get_mod_cfg(s);


    /* Lock the table. */
    if((rv = apr_global_mutex_lock(mod_cfg->lock)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "apr_global_mutex_lock() failed [%d]: %s",
                     rv, apr_strerror(rv, buffer, sizeof(buffer)));
        return NULL;
    }

    table = apr_shm_baseaddr_get(mod_cfg->cache);


    for(i = 0; i < mod_cfg->init_cache_size; i++) {
        const char *tablekey;

        switch (type) {
        case AM_CACHE_SESSION:
            tablekey = table[i].key;
            break;
        case AM_CACHE_NAMEID:
            /* tablekey may be NULL */
            tablekey = am_cache_env_fetch_first(&table[i], "NAME_ID");
            break;
        default:
            tablekey = NULL;
            break;
        }

        if (tablekey == NULL)
            continue;

        if(strcmp(tablekey, key) == 0) {
            /* We found the entry. */
            if(table[i].expires > apr_time_now()) {
                /* And it hasn't expired. */
                return &table[i];
            }
        }
    }


    /* We didn't find a entry matching the key. Unlock the table and
     * return NULL;
     */
    apr_global_mutex_unlock(mod_cfg->lock);
    return NULL;
}


/* This function locks the session table and creates a new session entry.
 * It will first attempt to locate a free session. If it doesn't find a
 * free session, then it will take the least recentry used session.
 *
 * Remember to unlock the table with am_cache_unlock(...) afterwards.
 *
 * Parameters:
 *  server_rec *s        The current server.
 *  const char *key      The key of the session to allocate.
 *
 * Returns:
 *  The new session entry on success. NULL if key is a invalid session
 *  key.
 */
am_cache_entry_t *am_cache_new(server_rec *s, const char *key)
{
    am_cache_entry_t *t;
    am_mod_cfg_rec *mod_cfg;
    am_cache_entry_t *table;
    apr_time_t current_time;
    int i;
    apr_time_t age;
    int rv;
    char buffer[512];

    /* Check if we have a valid session key. We abort if we don't. */
    if(key == NULL || strlen(key) != AM_ID_LENGTH) {
        return NULL;
    }


    mod_cfg = am_get_mod_cfg(s);


    /* Lock the table. */
    if((rv = apr_global_mutex_lock(mod_cfg->lock)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
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
    t = &table[0];

    /* Iterate over the session table. Update 't' to match the "best"
     * entry (the least recently used). 't' will point a free entry
     * if we find one. Otherwise, 't' will point to the least recently
     * used entry.
     */
    for(i = 0; i < mod_cfg->init_cache_size; i++) {
        if(table[i].key[0] == '\0') {
            /* This entry is free. Update 't' to this entry
             * and exit loop.
             */
            t = &table[i];
            break;
        }

        if(table[i].expires <= current_time) {
            /* This entry is expired, and is therefore free.
             * Update 't' and exit loop.
             */
            t = &table[i];
            break;
        }

        if(table[i].access < t->access) {
            /* This entry is older than 't' - update 't'. */
            t = &table[i];
        }
    }


    if(t->key[0] != '\0' && t->expires > current_time) {
        /* We dropped a LRU entry. Calculate the age in seconds. */
        age = (current_time - t->access) / 1000000;

        if(age < 3600) {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
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
    t->user[0] = '\0';

    t->lasso_identity[0] = '\0';
    t->lasso_session[0] = '\0';

    return t;
}


/* This function unlocks a session entry.
 *
 * Parameters:
 *  server_rec *s            The current server.
 *  am_cache_entry_t *entry  The session entry.
 *
 * Returns:
 *  Nothing.
 */
void am_cache_unlock(server_rec *s, am_cache_entry_t *entry)
{
    am_mod_cfg_rec *mod_cfg;

    /* Update access time. */
    entry->access = apr_time_now();

    mod_cfg = am_get_mod_cfg(s);
    apr_global_mutex_unlock(mod_cfg->lock);
}


/* This function updates the expire-timestamp of a session, if the new
 * timestamp is earlier than the previous.
 *
 * Parameters:
 *  am_cache_entry_t *t   The current session.
 *  apr_time_t expires    The new timestamp.
 *
 * Returns:
 *  Nothing.
 */
void am_cache_update_expires(am_cache_entry_t *t, apr_time_t expires)
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
    /* Make sure that the name and value will fit inside the
     * fixed size buffer.
     */
    if(strlen(val) >= AM_CACHE_VALSIZE ||
       strlen(var) >= AM_CACHE_VARSIZE) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "Unable to store session data because it is to big. "
                     "Name = \"%s\"; Value = \"%s\".", var, val);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if(t->size >= AM_CACHE_ENVSIZE) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "Unable to store attribute value because we have"
                     " reached the maximum number of name-value pairs for"
                     " this session.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    strcpy(t->env[t->size].varname, var);
    strcpy(t->env[t->size].value, val);
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
    int i;

    for (i = 0; t->size; i++) {
        if (strcmp(t->env[i].varname, var) == 0)
            return t->env[i].value;
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
    int *count;

    d = am_get_dir_cfg(r);

    /* Check if the user attribute has been set, and set it if it
     * hasn't been set. */
    if(t->user[0] == '\0') {
        for(i = 0; i < t->size; ++i) {
            if(strcmp(t->env[i].varname, d->userattr) == 0) {
                strcpy(t->user, t->env[i].value);
            }
        }
    }

    /* Allocate a set of counters for duplicate variables in the list. */
    counters = apr_hash_make(r->pool);

    /* Populate the subprocess environment with the attributes we
     * received from the IdP.
     */
    for(i = 0; i < t->size; ++i) {
        varname = t->env[i].varname;
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

        value = t->env[i].value;

        /*  
         * If we find a variable remapping to MellonUser, use it.
         */
        if ((t->user[0] == '\0') && (strcmp(varname, d->userattr) == 0))
            strcpy(t->user, value);

        /* Find the number of times this variable has been set. */
        count = apr_hash_get(counters, varname, APR_HASH_KEY_STRING);
        if(count == NULL) {

            /* This is the first time. Create a counter for this variable. */
            count = apr_palloc(r->pool, sizeof(int));
            *count = 0;
            apr_hash_set(counters, varname, APR_HASH_KEY_STRING, count);

            /* Add the variable without a suffix. */
            apr_table_set(r->subprocess_env,
                          apr_pstrcat(r->pool, varname_prefix, varname, NULL),
                          value);
        }

        /* Add the variable with a suffix indicating how many times it has
         * been added before.
         */
        apr_table_set(r->subprocess_env,
                      apr_psprintf(r->pool, "%s%s_%d", varname_prefix, varname, *count),
                      value);

        /* Increase the count. */
        ++(*count);
    }

    if(t->user[0] != '\0') {
        /* We have a user-"name". Set r->user and r->ap_auth_type. */
        r->user = apr_pstrdup(r->pool, t->user);
        r->ap_auth_type = apr_pstrdup(r->pool, "Mellon");
    } else {
        /* We don't have a user-"name". Log error. */
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                      "Didn't find the attribute \"%s\" in the attributes"
                      " which were received from the IdP. Cannot set a user"
                      " for this request without a valid user attribute.",
                      d->userattr);
    }


    /* Populate with the session? */
    if (d->dump_session) {
        char *session;
        int srclen, dstlen;

        srclen = strlen(t->lasso_session);
        dstlen = apr_base64_encode_len(srclen);

        session = apr_palloc(r->pool, dstlen);
        (void)apr_base64_encode(session, t->lasso_session, srclen);
        apr_table_set(r->subprocess_env, "MELLON_SESSION", session);
    }

    if (d->dump_saml_response)
        apr_table_set(r->subprocess_env, 
		      "MELLON_SAML_RESPONSE", 
		       t->lasso_saml_response);
}


/* This function deletes a given key from the session store.
 *
 * Parameters:
 *  server_rec *s             The current server.
 *  am_cache_entry_t *cache   The entry we are deleting.
 *
 * Returns:
 *  Nothing.
 */
void am_cache_delete(server_rec *s, am_cache_entry_t *cache)
{
    /* We write a null-byte at the beginning of the key to
     * mark this slot as unused. 
     */
    cache->key[0] = '\0';

    /* Unlock the entry. */
    am_cache_unlock(s, cache);
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
    if(lasso_identity != NULL) {
        if(strlen(lasso_identity) < AM_CACHE_MAX_LASSO_IDENTITY_SIZE) {
            strcpy(session->lasso_identity, lasso_identity);
        } else {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                         "Lasso identity is to big for storage. Size of lasso"
                         " identity is %" APR_SIZE_T_FMT ", max size is %"
                         APR_SIZE_T_FMT ".",
                         (apr_size_t)strlen(lasso_identity),
                         (apr_size_t)AM_CACHE_MAX_LASSO_IDENTITY_SIZE - 1);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    } else {
        /* No identity dump to save. */
        strcpy(session->lasso_identity, "");
    }


    if(lasso_session != NULL) {
        if(strlen(lasso_session) < AM_CACHE_MAX_LASSO_SESSION_SIZE) {
            strcpy(session->lasso_session, lasso_session);
        } else {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                         "Lasso session is to big for storage. Size of lasso"
                         " session is %" APR_SIZE_T_FMT ", max size is %"
                         APR_SIZE_T_FMT ".",
                         (apr_size_t)strlen(lasso_session),
                         (apr_size_t)AM_CACHE_MAX_LASSO_SESSION_SIZE - 1);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    } else {
        /* No session dump to save. */
        strcpy(session->lasso_session, "");
    }

    if(lasso_saml_response != NULL) {
        if(strlen(lasso_saml_response) < AM_CACHE_MAX_LASSO_SAML_RESPONSE_SIZE) {
            strcpy(session->lasso_saml_response, lasso_saml_response);
        } else {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                         "Lasso SAML response is to big for storage. "
                         "Size of lasso session is %" APR_SIZE_T_FMT
                         ", max size is %" APR_SIZE_T_FMT ".",
                         (apr_size_t)strlen(lasso_saml_response),
                         (apr_size_t)AM_CACHE_MAX_LASSO_SAML_RESPONSE_SIZE - 1);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    } else {
        /* No session dump to save. */
        strcpy(session->lasso_saml_response, "");
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
    if(strlen(session->lasso_identity) == 0) {
        return NULL;
    }

    return session->lasso_identity;
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
    if(strlen(session->lasso_session) == 0) {
        return NULL;
    }

    return session->lasso_session;
}
