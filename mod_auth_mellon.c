/*
 *
 *   mod_auth_mellon.c: an authentication apache module
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

#include <curl/curl.h>

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(auth_mellon);
#endif

/* This function is called after the configuration of the server is parsed
 * (it's a post-config hook).
 *
 * It initializes the shared memory and the mutex which is used to protect
 * the shared memory.
 *
 * Parameters:
 *  apr_pool_t *conf     The configuration pool. Valid as long as this
 *                       configuration is valid.
 *  apr_pool_t *log      A pool for memory which is cleared after each read
 *                       through the config files.
 *  apr_pool_t *tmp      A pool for memory which will be destroyed after
 *                       all the post_config hooks are run.
 *  server_rec *s        The current server record.
 *
 * Returns:
 *  OK on successful initialization, or !OK on failure.
 */
static int am_global_init(apr_pool_t *conf, apr_pool_t *log,
                          apr_pool_t *tmp, server_rec *s)
{
    apr_size_t        mem_size;
    am_mod_cfg_rec   *mod;
    int rv;
    const char userdata_key[] = "auth_mellon_init";
    char buffer[512];
    void *data;

    /* Apache tests loadable modules by loading them (as is the only way).
     * This has the effect that all modules are loaded and initialised twice,
     * and we just want to initialise shared memory and mutexes when the
     * module loads for real!
     *
     * To accomplish this, we store a piece of data as userdata in the
     * process pool the first time the function is run. This data can be
     * detected on all subsequent runs, and then we know that this isn't the
     * first time this function runs.
     */
    apr_pool_userdata_get(&data, userdata_key, s->process->pool);
    if (!data) {
        /* This is the first time this function is run. */
        apr_pool_userdata_set((const void *)1, userdata_key,
                              apr_pool_cleanup_null, s->process->pool);
        return OK;
    } 

    mod = am_get_mod_cfg(s);

    /* If the session store is initialized then we can't change it. */
    if(mod->cache != NULL) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                     "auth_mellon session store already initialized -"
                     " reinitialization skipped.");
        return OK;
    }

    /* Copy from the variables set by the configuration file into variables
     * which will be set only once. We do this to avoid confusion if the user
     * tries to change the parameters of the session store after it is
     * initialized.
     */
    mod->init_cache_size = mod->cache_size;
    mod->init_lock_file = apr_pstrdup(conf, mod->lock_file);
    mod->init_entry_size = mod->entry_size;
    if (mod->init_entry_size < AM_CACHE_MIN_ENTRY_SIZE) {
        mod->init_entry_size = AM_CACHE_MIN_ENTRY_SIZE;
    }

    /* find out the memory size of the cache */
    mem_size = mod->init_entry_size * mod->init_cache_size;


    /* Create the shared memory, exit if it fails. */
    rv = apr_shm_create(&(mod->cache), mem_size, NULL, conf);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "shm_create: Error [%d] \"%s\"", rv,
                     apr_strerror(rv, buffer, sizeof(buffer)));
        return !OK;
    }

    /* Initialize the session table. */
    am_cache_init(mod);

    /* Now create the mutex that we need for locking the shared memory, then
     * test for success. we really need this, so we exit on failure. */
    rv = apr_global_mutex_create(&(mod->lock),
                                 mod->init_lock_file,
                                 APR_LOCK_DEFAULT,
                                 conf);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "mutex_create: Error [%d] \"%s\"", rv,
                     apr_strerror(rv, buffer, sizeof(buffer)));
        return !OK;
    }

#ifdef AP_NEED_SET_MUTEX_PERMS
    /* On some platforms the mutex is implemented as a file. To allow child
     * processes running as a different user to open it, it is necessary to
     * change the permissions on it. */
    rv = ap_unixd_set_global_mutex_perms(mod->lock);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     "Failed to set permissions on session table lock;"
                     " check User and Group directives");
        return rv;
    }
#endif

    return OK;
}


/* This function is run when each child process of apache starts.
 * apr_global_mutex_child_init must be run on the session data mutex for
 * every child process of apache.
 *
 * Parameters:
 *  apr_pool_t *p        This pool is for data associated with this
 *                       child process.
 *  server_rec *s        The server record for the current server.
 *
 * Returns:
 *  Nothing.
 */
static void am_child_init(apr_pool_t *p, server_rec *s)
{
    am_mod_cfg_rec *m = am_get_mod_cfg(s);
    apr_status_t rv;
    CURLcode curl_res;

    /* Reinitialize the mutex for the child process. */
    rv = apr_global_mutex_child_init(&(m->lock), m->init_lock_file, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "Child process could not connect to mutex");
    }

    /* lasso_init() must be run before any other lasso-functions. */
    lasso_init();

    /* curl_global_init() should be called before any other curl
     * function. Relying on curl_easy_init() to call curl_global_init()
     * isn't thread safe.
     */
    curl_res = curl_global_init(CURL_GLOBAL_SSL);
    if(curl_res != CURLE_OK) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "Failed to initialize curl library: %u", curl_res);
    }

    return;
}


static int am_create_request(request_rec *r)
{
    am_req_cfg_rec *req_cfg;

    req_cfg = apr_pcalloc(r->pool, sizeof(am_req_cfg_rec));

    req_cfg->cookie_value = NULL;
#ifdef HAVE_ECP
    req_cfg->ecp_authn_req = false;
#endif /* HAVE_ECP */
#ifdef ENABLE_DIAGNOSTICS
    req_cfg->diag_emitted = false;
#endif

    ap_set_module_config(r->request_config, &auth_mellon_module, req_cfg);

    return OK;
}


static void register_hooks(apr_pool_t *p)
{
    ap_hook_access_checker(am_auth_mellon_user, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_user_id(am_check_uid, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(am_global_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(am_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_create_request(am_create_request, NULL, NULL, APR_HOOK_MIDDLE);

    /* Add the hook to handle requests to the mod_auth_mellon endpoint.
     *
     * This is APR_HOOK_FIRST because we do not expect nor require users
     * to add a SetHandler option for the endpoint. Instead, simply
     * setting MellonEndpointPath should be enough.
     *
     * Therefore this hook must run before any handler that may check
     * r->handler and decide that it is the only handler for this URL.
     */
    ap_hook_handler(am_handler, NULL, NULL, APR_HOOK_FIRST);

#ifdef ENABLE_DIAGNOSTICS
    ap_hook_open_logs(am_diag_log_init,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_log_transaction(am_diag_finalize_request,NULL,NULL,APR_HOOK_REALLY_LAST);
#endif
}


module AP_MODULE_DECLARE_DATA auth_mellon_module =
{
    STANDARD20_MODULE_STUFF,
    auth_mellon_dir_config,
    auth_mellon_dir_merge,
    auth_mellon_server_config,
    auth_mellon_srv_merge,
    auth_mellon_commands,
    register_hooks
};

