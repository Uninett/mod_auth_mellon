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

#include <stdbool.h>

#include <lasso/lasso.h>
#include <lasso/xml/saml-2.0/samlp2_authn_request.h>
#include <lasso/xml/saml-2.0/samlp2_logout_request.h>
#include <lasso/xml/saml-2.0/samlp2_response.h>
#include <lasso/xml/saml-2.0/saml2_assertion.h>
#include <lasso/xml/saml-2.0/saml2_attribute_statement.h>
#include <lasso/xml/saml-2.0/saml2_attribute.h>
#include <lasso/xml/saml-2.0/saml2_attribute_value.h>
#include <lasso/xml/saml-2.0/saml2_authn_statement.h>
#include <lasso/xml/saml-2.0/saml2_audience_restriction.h>
#include <lasso/xml/misc_text_node.h>
#include "lasso_compat.h"

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
#include "apr_file_info.h"
#include "apr_file_io.h"
#include "apr_xml.h"
#include "apr_lib.h"
#include "apr_fnmatch.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "mod_ssl.h"


/* Backwards-compatibility helpers. */
#include "auth_mellon_compat.h"


/* Size definitions for the session cache.
 */
#define AM_CACHE_KEYSIZE 120
#define AM_CACHE_ENVSIZE 2048
#define AM_CACHE_USERSIZE 512
#define AM_CACHE_DEFAULT_ENTRY_SIZE 196608
#define AM_CACHE_MIN_ENTRY_SIZE 65536


/* This is the length of the id we use (for session IDs and
 * replaying POST data).
 */
#define AM_ID_LENGTH 32

#define MEDIA_TYPE_PAOS "application/vnd.paos+xml"

#define am_get_srv_cfg(s) (am_srv_cfg_rec *)ap_get_module_config((s)->module_config, &auth_mellon_module)

#define am_get_mod_cfg(s) (am_get_srv_cfg((s)))->mc

#define am_get_dir_cfg(r) (am_dir_cfg_rec *)ap_get_module_config((r)->per_dir_config, &auth_mellon_module)

#define am_get_req_cfg(r) (am_req_cfg_rec *)ap_get_module_config((r)->request_config, &auth_mellon_module)


typedef struct am_mod_cfg_rec {
    int cache_size;
    const char *lock_file;
    const char *post_dir;
    apr_time_t post_ttl;
    int post_count;
    apr_size_t post_size;

    int entry_size;

    /* These variables can't be allowed to change after the session store
     * has been initialized. Therefore we copy them before initializing
     * the session store.
     */
    int init_cache_size;
    const char *init_lock_file;
    apr_size_t init_entry_size;

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
    AM_COND_FLAG_NULL = 0x000, /* No flags */
    AM_COND_FLAG_OR   = 0x001, /* Or with  next condition */
    AM_COND_FLAG_NOT  = 0x002, /* Negate this condition */
    AM_COND_FLAG_REG  = 0x004, /* Condition is regex */
    AM_COND_FLAG_NC   = 0x008, /* Case insensitive match */
    AM_COND_FLAG_MAP  = 0x010, /* Try to use attribute name from MellonSetEnv */
    AM_COND_FLAG_REF  = 0x020, /* Set regex backreferences */
    AM_COND_FLAG_SUB  = 0x040, /* Substring match */

    /* The other options are internally used */
    AM_COND_FLAG_IGN  = 0x1000, /* Condition is to be ignored */
    AM_COND_FLAG_REQ  = 0x2000, /* Condition was set using MellonRequire */
    AM_COND_FLAG_FSTR = 0x4000, /* Value contains a format string */
} am_cond_flag_t;

extern const char *am_cond_options[];

typedef struct {
    const char *varname;
    int flags;
    const char *str; 
    ap_regex_t *regex; 
    const char *directive;
} am_cond_t;

typedef struct am_metadata {
    const char *file;    /* Metadata file with one or many IdP */
    const char *chain;   /* Validating chain */
} am_metadata_t;

typedef struct am_dir_cfg_rec {
    /* enable_mellon is used to enable auth_mellon for a location.
     */
    am_enable_t enable_mellon;

    const char *varname;
    int secure;
    const char *merge_env_vars;
    int env_vars_index_start;
    int env_vars_count_in_n;
    const char *cookie_domain;
    const char *cookie_path;
    apr_array_header_t *cond;
    apr_hash_t *envattr;
    const char *userattr;
    const char *idpattr;
    int dump_session;
    int dump_saml_response;

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
    apr_array_header_t *idp_metadata;
    const char *idp_public_key_file;
    const char *idp_ca_file;
    GList *idp_ignore;

    /* metadata autogeneration helper */
    char *sp_entity_id;
    apr_hash_t *sp_org_name;
    apr_hash_t *sp_org_display_name;
    apr_hash_t *sp_org_url;

    /* Maximum number of seconds a session is valid for. */
    int session_length;

    /* No cookie error page. */
    const char *no_cookie_error_page;

    /* Authorization error page. */
    const char *no_success_error_page;

    /* Login path for IdP initiated logins */
    const char *login_path;

    /* IdP discovery service */
    const char *discovery_url;
    int probe_discovery_timeout;
    apr_table_t *probe_discovery_idp;

    /* The configuration record we "inherit" the lasso server object from. */
    struct am_dir_cfg_rec *inherit_server_from;
    /* Mutex to prevent us from creating several lasso server objects. */
    apr_thread_mutex_t *server_mutex;

    /* AuthnContextClassRef list */
    apr_array_header_t *authn_context_class_ref;
    /* Controls the checking of SubjectConfirmationData.Address attribute */
    int subject_confirmation_data_address_check;
    /* MellonDoNotVerifyLogoutSignature idp set */
    apr_hash_t *do_not_verify_logout_signature;

    /* Whether we should replay POST data after authentication. */
    int post_replay;

    /* Cached lasso server object. */
    LassoServer *server;

    /* Whether to send an ECP client a list of IdP's */
    int ecp_send_idplist;
} am_dir_cfg_rec;

typedef struct am_req_cfg_rec {
    char *cookie_value;
#ifdef HAVE_ECP
    bool ecp_authn_req;
#endif /* HAVE_ECP */
} am_req_cfg_rec;

typedef struct am_cache_storage_t {
    apr_size_t ptr;
} am_cache_storage_t;

typedef struct am_cache_env_t {
    am_cache_storage_t varname;
    am_cache_storage_t value;
} am_cache_env_t;

typedef struct am_cache_entry_t {
    char key[AM_CACHE_KEYSIZE];
    apr_time_t access;
    apr_time_t expires;
    int logged_in;
    unsigned short size;
    am_cache_storage_t user;

    /* Variables used to store lasso state between login requests
     *and logout requests.
     */
    am_cache_storage_t lasso_identity;
    am_cache_storage_t lasso_session;
    am_cache_storage_t lasso_saml_response;

    am_cache_env_t env[AM_CACHE_ENVSIZE];

    apr_size_t pool_size;
    apr_size_t pool_used;
    char pool[];
} am_cache_entry_t;

typedef enum { 
    AM_CACHE_SESSION, 
    AM_CACHE_NAMEID 
} am_cache_key_t;

/* Type for configuring environment variable names */
typedef struct am_envattr_conf_t {
    // Name of the variable
    const char *name;
    // Should a prefix be added
    int prefixed;
} am_envattr_conf_t;

extern const command_rec auth_mellon_commands[];

typedef struct am_error_map_t {
    int lasso_error;
    int http_error;
} am_error_map_t;

extern const am_error_map_t auth_mellon_errormap[];

/* When using a value from a directory configuration structure, a special value is used
 * to state "inherit" from parent, when reading a value and the value is still inherit from, it
 * means that no value has ever been set for this directive, in this case, we use the default
 * value.
 *
 * This macro expects that if your variable is called "name" there is a static const variable named
 * "default_name" which holds the default value for this variable.
 */
#define CFG_VALUE(container, name) \
	(container->name == inherit_##name ? default_##name : container->name)

#define CFG_MERGE(add_cfg, base_cfg, name) \
	(add_cfg->name == inherit_##name ? base_cfg->name : add_cfg->name)

/** Default and inherit value for SubjectConfirmationData Address check setting.
 */
static const int default_subject_confirmation_data_address_check = 1;
static const int inherit_subject_confirmation_data_address_check = -1;

/* Default and inherit values for MellonPostReplay option. */
static const int default_post_replay = 0;
static const int inherit_post_replay = -1;

/* Whether to send an ECP client a list of IdP's */
static const int default_ecp_send_idplist = 0;
static const int inherit_ecp_send_idplist = -1;


void *auth_mellon_dir_config(apr_pool_t *p, char *d);
void *auth_mellon_dir_merge(apr_pool_t *p, void *base, void *add);
void *auth_mellon_server_config(apr_pool_t *p, server_rec *s);


const char *am_cookie_get(request_rec *r);
void am_cookie_set(request_rec *r, const char *id);
void am_cookie_delete(request_rec *r);


void am_cache_init(am_mod_cfg_rec *mod_cfg);
am_cache_entry_t *am_cache_lock(server_rec *s, 
                                am_cache_key_t type, const char *key);
const char *am_cache_entry_get_string(am_cache_entry_t *e,
                                      am_cache_storage_t *slot);
am_cache_entry_t *am_cache_new(server_rec *s, const char *key);
void am_cache_unlock(server_rec *s, am_cache_entry_t *entry);

void am_cache_update_expires(am_cache_entry_t *t, apr_time_t expires);

void am_cache_env_populate(request_rec *r, am_cache_entry_t *session);
int am_cache_env_append(am_cache_entry_t *session,
                        const char *var, const char *val);
const char *am_cache_env_fetch_first(am_cache_entry_t *t,
                                     const char *var);
void am_cache_delete(server_rec *s, am_cache_entry_t *session);

int am_cache_set_lasso_state(am_cache_entry_t *session,
                             const char *lasso_identity,
                             const char *lasso_session,
                             const char *lasso_saml_response);
const char *am_cache_get_lasso_identity(am_cache_entry_t *session);
const char *am_cache_get_lasso_session(am_cache_entry_t *session);


am_cache_entry_t *am_get_request_session(request_rec *r);
am_cache_entry_t *am_get_request_session_by_nameid(request_rec *r, 
                                                   char *nameid);
am_cache_entry_t *am_new_request_session(request_rec *r);
void am_release_request_session(request_rec *r, am_cache_entry_t *session);
void am_delete_request_session(request_rec *r, am_cache_entry_t *session);


char *am_reconstruct_url(request_rec *r);
int am_check_permissions(request_rec *r, am_cache_entry_t *session);
void am_set_cache_control_headers(request_rec *r);
int am_read_post_data(request_rec *r, char **data, apr_size_t *length);
char *am_extract_query_parameter(apr_pool_t *pool,
                                 const char *query_string,
                                 const char *name);
char *am_urlencode(apr_pool_t *pool, const char *str);
int am_urldecode(char *data);
int am_check_url(request_rec *r, const char *url);
char *am_generate_id(request_rec *r);
char *am_getfile(apr_pool_t *conf, server_rec *s, const char *file);
char *am_get_endpoint_url(request_rec *r);
int am_postdir_cleanup(request_rec *s);
char *am_htmlencode(request_rec *r, const char *str);
int am_save_post(request_rec *r, const char **relay_state);
const char *am_filepath_dirname(apr_pool_t *p, const char *path);
const char *am_strip_cr(request_rec *r, const char *str);
const char *am_add_cr(request_rec *r, const char *str);
const char *am_xstrtok(request_rec *r, const char *str, 
                       const char *sep, char **last);
void am_strip_blank(const char **s);
const char *am_get_header_attr(request_rec *r, const char *h,
                               const char *v, const char *a);
int am_has_header(request_rec *r, const char *h, const char *v);
const char *am_get_mime_header(request_rec *r, const char *m, const char *h);
const char *am_get_mime_body(request_rec *r, const char *mime);
char *am_get_service_url(request_rec *r, 
                         LassoProfile *profile, char *service_name);
bool am_validate_paos_header(request_rec *r, const char *header);
bool am_header_has_media_type(request_rec *r, const char *header,
                              const char *media_type);
const char *am_get_config_langstring(apr_hash_t *h, const char *lang);
int am_get_boolean_query_parameter(request_rec *r, const char *name,
                                   int *return_value, int default_value);
char *am_get_assertion_consumer_service_by_binding(LassoProvider *provider, const char *binding);

#ifdef HAVE_ECP
bool am_is_paos_request(request_rec *r);
#endif /* HAVE_ECP */

int am_auth_mellon_user(request_rec *r);
int am_check_uid(request_rec *r);
int am_handler(request_rec *r);


int am_httpclient_get(request_rec *r, const char *uri, 
                      void **buffer, apr_size_t *size, 
                      apr_time_t timeout, long *status);
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
