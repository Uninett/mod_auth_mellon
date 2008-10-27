/*
 *
 *   auth_mellon.h: an authentication apache module
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

#ifndef MOD_AUTH_MELLON_H
#define MOD_AUTH_MELLON_H

#include <lasso/lasso.h>
#include <lasso/xml/saml-2.0/samlp2_authn_request.h>
#include <lasso/xml/saml-2.0/samlp2_logout_request.h>
#include <lasso/xml/saml-2.0/samlp2_response.h>
#include <lasso/xml/saml-2.0/saml2_assertion.h>
#include <lasso/xml/saml-2.0/saml2_attribute_statement.h>
#include <lasso/xml/saml-2.0/saml2_attribute.h>
#include <lasso/xml/saml-2.0/saml2_attribute_value.h>
#include <lasso/xml/saml-2.0/saml2_authn_statement.h>
#include <lasso/xml/misc_text_node.h>

/* The following are redefined in ap_config_auto.h */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#undef HAVE_TIMEGM              /* is redefined again in ap_config.h */

#include "apr_base64.h"
#include "apr_time.h"
#include "apr_strings.h"
#include "apr_shm.h"
#include "apr_md5.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"


/* Size definitions for the session cache.
 */
#define AM_CACHE_KEYSIZE 120
#define AM_CACHE_VARSIZE 128
#define AM_CACHE_VALSIZE 512-AM_CACHE_VARSIZE
#define AM_CACHE_ENVSIZE 128
#define AM_CACHE_USERSIZE 512
#define AM_CACHE_MAX_LASSO_IDENTITY_SIZE 1024
#define AM_CACHE_MAX_LASSO_SESSION_SIZE 8192


/* This is the length of the session id we use.
 */
#define AM_SESSION_ID_LENGTH 32


#define am_get_srv_cfg(s) (am_srv_cfg_rec *)ap_get_module_config((s)->module_config, &auth_mellon_module)

#define am_get_mod_cfg(s) (am_get_srv_cfg((s)))->mc

#define am_get_dir_cfg(r) (am_dir_cfg_rec *)ap_get_module_config((r)->per_dir_config, &auth_mellon_module)


typedef struct am_mod_cfg_rec {
    int cache_size;
    const char *lock_file;

    /* These variables can't be allowed to change after the session store
     * has been initialized. Therefore we copy them before initializing
     * the session store.
     */
    int init_cache_size;
    const char *init_lock_file;

    apr_shm_t *cache;
    apr_global_mutex_t *lock;
} am_mod_cfg_rec;


typedef struct am_srv_cfg_rec {
    am_mod_cfg_rec *mc;
} am_srv_cfg_rec;

typedef enum {
    am_enable_default,
    am_enable_off,
    am_enable_info,
    am_enable_auth
} am_enable_t;

typedef enum {
    am_decoder_default,
    am_decoder_none,
    am_decoder_feide,
} am_decoder_t;


typedef struct am_dir_cfg_rec {
    /* enable_mellon is used to enable auth_mellon for a location.
     */
    am_enable_t enable_mellon;

    /* The decoder attribute is used to specify which decoder we should use
     * when parsing attributes.
     */
    am_decoder_t decoder;

    const char *varname;
    apr_hash_t *require;
    apr_hash_t *envattr;
    const char *userattr;

    /* The "root directory" of our SAML2 endpoints. This path is relative
     * to the root of the web server.
     *
     * This path will always end with '/'.
     */
    const char *endpoint_path;

    /* Lasso configuration variables. */
    const char *sp_metadata_file;
    const char *sp_private_key_file;
    const char *sp_cert_file;
    const char *idp_metadata_file;
    const char *idp_public_key_file;
    const char *idp_ca_file;

    /* Maximum number of seconds a session is valid for. */
    int session_length;

    /* No cookie error page. */
    const char *no_cookie_error_page;

    /* Mutex to prevent us from creating several lasso server objects. */
    apr_thread_mutex_t *server_mutex;
    /* Cached lasso server object. */
    LassoServer *server;
} am_dir_cfg_rec;


typedef struct am_cache_env_t {
    char varname[AM_CACHE_VARSIZE];
    char value[AM_CACHE_VALSIZE];
} am_cache_env_t;

typedef struct am_cache_entry_t {
    char key[AM_CACHE_KEYSIZE];
    apr_time_t access;
    apr_time_t expires;
    int logged_in;
    unsigned short size;
    char user[AM_CACHE_USERSIZE];

    /* Variables used to store lasso state between login requests
     *and logout requests.
     */
    char lasso_identity[AM_CACHE_MAX_LASSO_IDENTITY_SIZE];
    char lasso_session[AM_CACHE_MAX_LASSO_SESSION_SIZE];

    am_cache_env_t env[AM_CACHE_ENVSIZE];
} am_cache_entry_t;



extern const command_rec auth_mellon_commands[];

void *auth_mellon_dir_config(apr_pool_t *p, char *d);
void *auth_mellon_dir_merge(apr_pool_t *p, void *base, void *add);
void *auth_mellon_server_config(apr_pool_t *p, server_rec *s);


const char *am_cookie_get(request_rec *r);
void am_cookie_set(request_rec *r, const char *id);
void am_cookie_delete(request_rec *r);


am_cache_entry_t *am_cache_lock(server_rec *s, const char *key);
am_cache_entry_t *am_cache_new(server_rec *s, const char *key);
void am_cache_unlock(server_rec *s, am_cache_entry_t *entry);

void am_cache_update_expires(am_cache_entry_t *t, apr_time_t expires);

void am_cache_env_populate(request_rec *r, am_cache_entry_t *session);
int am_cache_env_append(am_cache_entry_t *session,
                        const char *var, const char *val);
void am_cache_delete(server_rec *s, am_cache_entry_t *session);

int am_cache_set_lasso_state(am_cache_entry_t *session,
                             const char *lasso_identity,
                             const char *lasso_session);
const char *am_cache_get_lasso_identity(am_cache_entry_t *session);
const char *am_cache_get_lasso_session(am_cache_entry_t *session);


am_cache_entry_t *am_get_request_session(request_rec *r);
am_cache_entry_t *am_new_request_session(request_rec *r);
void am_release_request_session(request_rec *r, am_cache_entry_t *session);
void am_delete_request_session(request_rec *r, am_cache_entry_t *session);


const char *am_reconstruct_url(request_rec *r);
int am_check_permissions(request_rec *r, am_cache_entry_t *session);
void am_set_nocache(request_rec *r);
int am_read_post_data(request_rec *r, char **data, apr_size_t *length);
char *am_extract_query_parameter(apr_pool_t *pool,
                                 const char *query_string,
                                 const char *name);
char *am_urlencode(apr_pool_t *pool, const char *str);
int am_urldecode(char *data);
char *am_generate_session_id(request_rec *r);


int am_auth_mellon_user(request_rec *r);
int am_check_uid(request_rec *r);


int am_httpclient_get(request_rec *r, const char *uri,
                      void **buffer, apr_size_t *size);
int am_httpclient_post(request_rec *r, const char *uri,
                       const void *post_data, apr_size_t post_length,
                       const char *content_type,
                       void **buffer, apr_size_t *size);
int am_httpclient_post_str(request_rec *r, const char *uri,
                           const char *post_data,
                           const char *content_type,
                           void **buffer, apr_size_t *size);


extern module AP_MODULE_DECLARE_DATA auth_mellon_module;

#endif /* MOD_AUTH_MELLON_H */
