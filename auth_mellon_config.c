/*
 *
 *   auth_mellon_config.c: an authentication apache module
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

/* This is the default endpoint path. Remember to update the description of
 * the MellonEndpointPath configuration directive if you change this.
 */
static const char *default_endpoint_path = "/mellon/";

/* This is the default name of the attribute we use as a username. Remember
 * to update the description of the MellonUser configuration directive if
 * you change this.
 */
static const char *default_user_attribute = "NAME_ID";

/* This is the default name of the cookie which mod_auth_mellon will set.
 * If you change this, then you should also update the description of the
 * MellonVar configuration directive.
 */
static const char *default_cookie_name = "cookie";

/* The default setting for cookie is to not enforce secure flag
 */
static const int default_secure_cookie = 0; 

/* The default setting for cookie is to not enforce HttpOnly flag
 */
static const int default_http_only_cookie = 0;

/* The default setting for setting MELLON_SESSION
 */
static const int default_dump_session = 0; 

/* The default setting for setting MELLON_SAML_RESPONSE
 */
static const int default_dump_saml_response = 0; 

/* This is the default IdP initiated login location
 * the MellonDefaultLoginPath configuration directive if you change this.
 */
static const char *default_login_path = "/";

/* saved POST session time to live
 * the MellonPostTTL configuration directive if you change this.
 */
static const apr_time_t post_ttl = 15 * 60;

/* saved POST session maximum size
 * the MellonPostSize configuration directive if you change this.
 */
static const apr_size_t post_size = 1024 * 1024;

/* maximum saved POST sessions
 * the MellonPostCount configuration directive if you change this.
 */
static const int post_count = 100;

/* whether to merge env. vars or not
 * the MellonMergeEnvVars configuration directive if you change this.
 */
static const char *default_merge_env_vars = NULL;

/* for env. vars with multiple values, the index start
 * the MellonEnvVarsIndexStart configuration directive if you change this.
 */
static const int default_env_vars_index_start = -1;

/* whether to also populate env. var _N with number of values
 * the MellonEnvVarsSetCount configuration directive if you change this.
 */
static const int default_env_vars_count_in_n = -1;

/* The default list of trusted redirect domains. */
static const char * const default_redirect_domains[] = { "[self]", NULL };

/* This function handles configuration directives which set a 
 * multivalued string slot in the module configuration (the destination
 * strucure is a hash).
 *
 * Parameters:
 *  cmd_parms *cmd       The command structure for this configuration
 *                       directive.
 *  void *struct_ptr     Pointer to the current directory configuration.
 *                       NULL if we are not in a directory configuration.
 *  const char *key      The string argument following this configuration
 *                       directive in the configuraion file.
 *  const char *value    Optional value to be stored in the hash.
 *
 * Returns:
 *  NULL on success or an error string on failure.
 */
static const char *am_set_hash_string_slot(cmd_parms *cmd,
                                          void *struct_ptr,
                                          const char *key,
                                          const char *value)
{
    server_rec *s = cmd->server;
    apr_pool_t *pconf = s->process->pconf;
    am_dir_cfg_rec *cfg = (am_dir_cfg_rec *)struct_ptr;
    int offset;
    apr_hash_t **hash;

    /*
     * If no value is given, we just store the key in the hash.
     */
    if (value == NULL || *value == '\0')
        value = key;

    offset = (int)(long)cmd->info;
    hash = (apr_hash_t **)((char *)cfg + offset);
    apr_hash_set(*hash, apr_pstrdup(pconf, key), APR_HASH_KEY_STRING, value);

    return NULL;
}

/* This function handles configuration directives which set a 
 * multivalued string slot in the module configuration (the destination
 * strucure is a table).
 *
 * Parameters:
 *  cmd_parms *cmd       The command structure for this configuration
 *                       directive.
 *  void *struct_ptr     Pointer to the current directory configuration.
 *                       NULL if we are not in a directory configuration.
 *  const char *key      The string argument following this configuration
 *                       directive in the configuraion file.
 *  const char *value    Optional value to be stored in the hash.
 *
 * Returns:
 *  NULL on success or an error string on failure.
 */
static const char *am_set_table_string_slot(cmd_parms *cmd,
                                          void *struct_ptr,
                                          const char *key,
                                          const char *value)
{
    server_rec *s = cmd->server;
    apr_pool_t *pconf = s->process->pconf;
    am_dir_cfg_rec *cfg = (am_dir_cfg_rec *)struct_ptr;
    int offset;
    apr_table_t **table;

    /*
     * If no value is given, we just store the key in the hash.
     */
    if (value == NULL || *value == '\0')
        value = key;

    offset = (int)(long)cmd->info;
    table = (apr_table_t **)((char *)cfg + offset);
    apr_table_set(*table, apr_pstrdup(pconf, key), value);

    return NULL;
}

/* This function handles configuration directives which set a file
 * slot in the module configuration. If lasso is recent enough, it
 * attempts to read the file immediatly.
 *
 * Parameters:
 *  cmd_parms *cmd       The command structure for this configuration
 *                       directive.
 *  void *struct_ptr     Pointer to the current directory configuration.
 *                       NULL if we are not in a directory configuration.
 *                       This value isn't used by this function.
 *  const char *arg      The string argument following this configuration
 *                       directive in the configuraion file.
 *
 * Returns:
 *  NULL on success or an error string on failure.
 */
static const char *am_set_filestring_slot(cmd_parms *cmd,
                                          void *struct_ptr,
                                          const char *arg)
{
    const char *data;
    const char *path;

    path = ap_server_root_relative(cmd->pool, arg);
    if (!path) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           ": Invalid file path ", arg, NULL);
    }

#ifdef HAVE_lasso_server_new_from_buffers
    data = am_getfile(cmd->pool, cmd->server, path);
    if (!data) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           ": Cannot read file ", path, NULL);
    }
#else
    apr_finfo_t finfo;
    apr_status_t rv;
    char error[64];

    rv = apr_stat(&finfo, path, APR_FINFO_SIZE, cmd->pool);
    if(rv != 0) {
        apr_strerror(rv, error, sizeof(error));
        return apr_psprintf(cmd->pool,
                            "%s - Cannot read file \"%s\" [%d] \"%s\"",
                            cmd->cmd->name, path, rv, error);
    }

    data = path;
#endif

    return ap_set_string_slot(cmd, struct_ptr, data);
}


/* This function handles configuration directives which use
 * a glob pattern, with a second optional argument
 *
 * Parameters:
 *  cmd_parms *cmd       The command structure for this configuration
 *                       directive.
 *  void *struct_ptr     Pointer to the current directory configuration.
 *                       NULL if we are not in a directory configuration.
 *  const char *glob_pat glob(3) pattern
 *  const char *option   Optional argument
 *
 * Returns:
 *  NULL on success or an error string on failure.
 */
static const char *am_set_glob_fn12(cmd_parms *cmd,
                                    void *struct_ptr,
                                    const char *glob_pat,
                                    const char *option)
{
    const char *(*take_argv)(cmd_parms *, void *, const char *, const char *);
    apr_array_header_t *files;
    const char *error;
    const char *directory;
    int i;

    take_argv = cmd->info;

    directory = am_filepath_dirname(cmd->pool, glob_pat);

    if (glob_pat == NULL || *glob_pat == '\0')
        return apr_psprintf(cmd->pool,
                            "%s takes one or two arguments",
                            cmd->cmd->name);

    if (apr_match_glob(glob_pat, &files, cmd->pool) != 0)
        return take_argv(cmd, struct_ptr, glob_pat, option);
    
    for (i = 0; i < files->nelts; i++) {
        const char *path;

        path = apr_pstrcat(cmd->pool, directory, "/", 
                           ((const char **)(files->elts))[i], NULL); 
                           
        error = take_argv(cmd, struct_ptr, path, option);

        if (error != NULL)
            return error;
    }
   
    return NULL;
}

/* This function handles configuration directives which set an 
 * idp related slot in the module configuration. 
 *
 * Parameters:
 *  cmd_parms *cmd       The command structure for this configuration
 *                       directive.
 *  void *struct_ptr     Pointer to the current directory configuration.
 *                       NULL if we are not in a directory configuration.
 *  const char *metadata Path to metadata file for one or multiple IdP
 *  const char *chain    Optional path to validating chain
 *
 * Returns:
 *  NULL on success or an error string on failure.
 */
static const char *am_set_idp_string_slot(cmd_parms *cmd,
                                          void *struct_ptr,
                                          const char *metadata,
                                          const char *chain)
{
    server_rec *s = cmd->server;
    apr_pool_t *pconf = s->process->pconf;
    am_dir_cfg_rec *cfg = (am_dir_cfg_rec *)struct_ptr;

#ifndef HAVE_lasso_server_load_metadata
    if (chain != NULL)
        return apr_psprintf(cmd->pool, "Cannot specify validating chain "
                            "for %s since lasso library lacks "
                            "lasso_server_load_metadata()", cmd->cmd->name);
#endif /* HAVE_lasso_server_load_metadata */

    am_metadata_t *idp_metadata = apr_array_push(cfg->idp_metadata);
    idp_metadata->file = apr_pstrdup(pconf, metadata);
    idp_metadata->chain = apr_pstrdup(pconf, chain);

    return NULL;
}


/* This function handles configuration directives which set an
 * idp federation blacklist slot in the module configuration.
 *
 * Parameters:
 *  cmd_parms *cmd       The command structure for this configuration
 *                       directive.
 *  void *struct_ptr     Pointer to the current directory configuration.
 *                       NULL if we are not in a directory configuration.
 *  int argc             Number of blacklisted providerId.
 *  char *const argv[]   List of blacklisted providerId.
 *
 * Returns:
 *  NULL on success, or errror string
 */
static const char *am_set_idp_ignore_slot(cmd_parms *cmd,
                                          void *struct_ptr,
                                          int argc,
                                          char *const argv[])
{
#ifdef HAVE_lasso_server_load_metadata
    server_rec *s = cmd->server;
    apr_pool_t *pconf = s->process->pconf;
    am_dir_cfg_rec *cfg = (am_dir_cfg_rec *)struct_ptr;
    GList *new_idp_ignore;
    int i;

    if (argc < 1)
        return apr_psprintf(cmd->pool, "%s takes at least one arguments",
                            cmd->cmd->name);

    for (i = 0; i < argc; i++) {
        new_idp_ignore = apr_palloc(pconf, sizeof(GList));
        new_idp_ignore->data = apr_pstrdup(pconf, argv[i]);

        /* Prepend it to the list. */
        new_idp_ignore->next = cfg->idp_ignore;
        if (cfg->idp_ignore != NULL)
            cfg->idp_ignore->prev = new_idp_ignore;
        cfg->idp_ignore = new_idp_ignore;
    }

    return NULL;

#else /* HAVE_lasso_server_load_metadata */

    return apr_psprintf(cmd->pool, "Cannot use %s since lasso library lacks "
                        "lasso_server_load_metadata()", cmd->cmd->name);

#endif /* HAVE_lasso_server_load_metadata */
}


/* This function handles configuration directives which set a file path
 * slot in the module configuration.
 *
 * Parameters:
 *  cmd_parms *cmd       The command structure for this configuration
 *                       directive.
 *  void *struct_ptr     Pointer to the current directory configuration.
 *                       NULL if we are not in a directory configuration.
 *                       This value isn't used by this function.
 *  const char *arg      The string argument following this configuration
 *                       directive in the configuraion file.
 *
 * Returns:
 *  NULL on success or an error string on failure.
 */
static const char *am_set_module_config_file_slot(cmd_parms *cmd,
                                                    void *struct_ptr,
                                                    const char *arg)
{
    return ap_set_file_slot(cmd, am_get_mod_cfg(cmd->server), arg);
}

/* This function handles configuration directives which set an int
 * slot in the module configuration.
 *
 * Parameters:
 *  cmd_parms *cmd       The command structure for this configuration
 *                       directive.
 *  void *struct_ptr     Pointer to the current directory configuration.
 *                       NULL if we are not in a directory configuration.
 *                       This value isn't used by this function.
 *  const char *arg      The string argument following this configuration
 *                       directive in the configuraion file.
 *
 * Returns:
 *  NULL on success or an error string on failure.
 */
static const char *am_set_module_config_int_slot(cmd_parms *cmd,
                                                 void *struct_ptr,
                                                 const char *arg)
{
    return ap_set_int_slot(cmd, am_get_mod_cfg(cmd->server), arg);
}

/* This function handles the MellonCookieSameSite configuration directive.
 * This directive can be set to "lax" or "strict"
 *
 * Parameters:
 *  cmd_parms *cmd       The command structure for this configuration
 *                       directive.
 *  void *struct_ptr     Pointer to the current directory configuration.
 *  const char *arg      The string argument following this configuration
 *                       directive in the configuraion file.
 *
 * Returns:
 *  NULL on success or an error string if the argument is wrong.
 */
static const char *am_set_samesite_slot(cmd_parms *cmd,
                                      void *struct_ptr,
                                      const char *arg)
{
    am_dir_cfg_rec *d = (am_dir_cfg_rec *)struct_ptr;

    if(!strcasecmp(arg, "lax")) {
        d->cookie_samesite = am_samesite_lax;
    } else if(!strcasecmp(arg, "strict")) {
        d->cookie_samesite = am_samesite_strict;
    } else {
        return "The MellonCookieSameSite parameter must be 'lax' or 'strict'";
    }

    return NULL;
}

/* This function handles the MellonEnable configuration directive.
 * This directive can be set to "off", "info" or "auth".
 *
 * Parameters:
 *  cmd_parms *cmd       The command structure for this configuration
 *                       directive.
 *  void *struct_ptr     Pointer to the current directory configuration.
 *  const char *arg      The string argument following this configuration
 *                       directive in the configuraion file.
 *
 * Returns:
 *  NULL on success or an error string if the argument is wrong.
 */
static const char *am_set_enable_slot(cmd_parms *cmd,
                                      void *struct_ptr,
                                      const char *arg)
{
    am_dir_cfg_rec *d = (am_dir_cfg_rec *)struct_ptr;

    if(!strcasecmp(arg, "auth")) {
        d->enable_mellon = am_enable_auth;
    } else if(!strcasecmp(arg, "info")) {
        d->enable_mellon = am_enable_info;
    } else if(!strcasecmp(arg, "off")) {
        d->enable_mellon = am_enable_off;
    } else {
        return "parameter must be 'off', 'info' or 'auth'";
    }

    return NULL;
}


/* This function handles the MellonSecureCookie configuration directive.
 * This directive can be set to "on", "off", "secure" or "httponly".
 *
 * Parameters:
 *  cmd_parms *cmd       The command structure for this configuration
 *                       directive.
 *  void *struct_ptr     Pointer to the current directory configuration.
 *  const char *arg      The string argument following this configuration
 *                       directive in the configuraion file.
 *
 * Returns:
 *  NULL on success or an error string if the argument is wrong.
 */
static const char *am_set_secure_slots(cmd_parms *cmd,
                                      void *struct_ptr,
                                      const char *arg)
{
    am_dir_cfg_rec *d = (am_dir_cfg_rec *)struct_ptr;

    if(!strcasecmp(arg, "on")) {
        d->secure = 1;
        d->http_only = 1;
    } else if(!strcasecmp(arg, "secure")) {
        d->secure = 1;
    } else if(!strcasecmp(arg, "httponly")) {
        d->http_only = 1;
    } else if(strcasecmp(arg, "off")) {
        return "parameter must be 'on', 'off', 'secure' or 'httponly'";
    }

    return NULL;
}

/* This function handles the obsolete MellonDecoder configuration directive.
 * It is a no-op.
 *
 * Parameters:
 *  cmd_parms *cmd       The command structure for this configuration
 *                       directive.
 *  void *struct_ptr     Pointer to the current directory configuration.
 *  const char *arg      The string argument following this configuration
 *                       directive in the configuraion file.
 *
 * Returns:
 *  NULL
 */
static const char *am_set_decoder_slot(cmd_parms *cmd,
                                       void *struct_ptr,
                                       const char *arg)
{
    return NULL;
}


/* This function handles the MellonEndpointPath configuration directive.
 * If the path doesn't end with a '/', then we will append one.
 *
 * Parameters:
 *  cmd_parms *cmd       The command structure for the MellonEndpointPath
 *                       configuration directive.
 *  void *struct_ptr     Pointer to the current directory configuration.
 *                       NULL if we are not in a directory configuration.
 *  const char *arg      The string argument containing the path of the
 *                       endpoint directory.
 *
 * Returns:
 *  This function will always return NULL.
 */
static const char *am_set_endpoint_path(cmd_parms *cmd,
                                        void *struct_ptr,
                                        const char *arg)
{
    am_dir_cfg_rec *d = (am_dir_cfg_rec *)struct_ptr;

    /* Make sure that the path ends with '/'. */
    if(strlen(arg) == 0 || arg[strlen(arg) - 1] != '/') {
        d->endpoint_path = apr_pstrcat(cmd->pool, arg, "/", NULL);
    } else {
        d->endpoint_path = arg;
    }

    return NULL;
}


/* This function handles the MellonSetEnv configuration directive.
 * This directive allows the user to change the name of attributes.
 *
 * Parameters:
 *  cmd_parms *cmd       The command structure for the MellonSetEnv
 *                       configuration directive.
 *  void *struct_ptr     Pointer to the current directory configuration.
 *  const char *newName  The new name of the attribute.
 *  const char *oldName  The old name of the attribute.
 *
 * Returns:
 *  This function will always return NULL.
 */
static const char *am_set_setenv_slot(cmd_parms *cmd,
                                      void *struct_ptr,
                                      const char *newName,
                                      const char *oldName)
{
    am_dir_cfg_rec *d = (am_dir_cfg_rec *)struct_ptr;
    /* Configure as prefixed attribute name */
    am_envattr_conf_t *envattr_conf = (am_envattr_conf_t *)apr_palloc(cmd->pool, sizeof(am_envattr_conf_t));
    envattr_conf->name = newName;
    envattr_conf->prefixed = 1;
    apr_hash_set(d->envattr, oldName, APR_HASH_KEY_STRING, envattr_conf);
    return NULL;
}

/* This function handles the MellonSetEnvNoPrefix configuration directive.
 * This directive allows the user to change the name of attributes without prefixing them with MELLON_.
 *
 * Parameters:
 *  cmd_parms *cmd       The command structure for the MellonSetEnv
 *                       configuration directive.
 *  void *struct_ptr     Pointer to the current directory configuration.
 *  const char *newName  The new name of the attribute.
 *  const char *oldName  The old name of the attribute.
 *
 * Returns:
 *  This function will always return NULL.
 */
static const char *am_set_setenv_no_prefix_slot(cmd_parms *cmd,
                                      void *struct_ptr,
                                      const char *newName,
                                      const char *oldName)
{
    am_dir_cfg_rec *d = (am_dir_cfg_rec *)struct_ptr;
    /* Configure as not prefixed attribute name */
    am_envattr_conf_t *envattr_conf = (am_envattr_conf_t *)apr_palloc(cmd->pool, sizeof(am_envattr_conf_t));
    envattr_conf->name = newName;
    envattr_conf->prefixed = 0;
    apr_hash_set(d->envattr, oldName, APR_HASH_KEY_STRING, envattr_conf);
    return NULL;
}


/* This function decodes MellonCond flags, such as [NOT,REG]
 *
 * Parameters:
 *  const char *arg      Pointer to the flags string
 *
 * Returns:
 *  flags, or -1 on error
 */
static int am_cond_flags(const char *arg)
{
    int flags = AM_COND_FLAG_NULL; 
    static const char const *options[] = { 
        "OR",  /* AM_EXPIRE_FLAG_OR */
        "NOT", /* AM_EXPIRE_FLAG_NOT */
        "REG", /* AM_EXPIRE_FLAG_REG */
        "NC",  /* AM_EXPIRE_FLAG_NC */
        "MAP", /* AM_EXPIRE_FLAG_MAP */
        "REF", /* AM_EXPIRE_FLAG_REF */
        "SUB", /* AM_EXPIRE_FLAG_SUB */
        /* The other options (IGN, REQ, FSTR, ...) are only internally used  */
    };
    apr_size_t options_count = sizeof(options) / sizeof(*options);
    
    /* Skip inital [ */
    if (arg[0] == '[')
        arg++;
    else
        return -1;
 
    do {
        apr_size_t i;

        for (i = 0; i < options_count; i++) {
            apr_size_t optlen = strlen(options[i]);

            if (strncmp(arg, options[i], optlen) == 0) {
                /* Make sure we have a separator next */
                if (arg[optlen] && !strchr("]\t ,", (int)arg[optlen]))
                       return -1;

                flags |= (1 << i); 
                arg += optlen;
                break;
            }
      
            /* no match */
            if (i == options_count)
                return -1;
    
            /* skip spaces, tabs and commas */
            arg += strspn(arg, " \t,");
    
            /*
             * End of option, but we fire an error if 
             * there is trailing garbage
             */
            if (*arg == ']') {
                arg++;
                return (*arg == '\0') ? flags : -1;
            }
         }
    } while (*arg);

    /* Missing trailing ] */
    return -1;
}

/* This function handles the MellonCond configuration directive, which
 * allows the user to restrict access based on attributes received from
 * the IdP.
 *
 * Parameters:
 *  cmd_parms *cmd       The command structure for the MellonCond
 *                       configuration directive.
 *  void *struct_ptr     Pointer to the current directory configuration.
 *  const char *attribute   Pointer to the attribute name
 *  const char *value       Pointer to the attribute value or regex
 *  const char *options     Pointer to options
 *
 * Returns:
 *  NULL on success or an error string on failure.
 */
static const char *am_set_cond_slot(cmd_parms *cmd,
                                    void *struct_ptr,
                                    const char *attribute,
                                    const char *value,
                                    const char *options)
{
    am_dir_cfg_rec *d = struct_ptr;
    int flags = AM_COND_FLAG_NULL;
    am_cond_t *element;

    if (attribute == NULL || *attribute == '\0' || 
        value == NULL || *value == '\0')
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           " takes at least two arguments", NULL);

    if (options != NULL && *options != '\0')
        flags = am_cond_flags(options);

    if (flags == -1)
         return apr_psprintf(cmd->pool, "%s - invalid flags %s",
                             cmd->cmd->name, options);
     
    element = (am_cond_t *)apr_array_push(d->cond);
    element->varname = attribute;
    element->flags = flags;
    element->str = NULL;
    element->regex = NULL;
    element->directive = apr_pstrcat(cmd->pool, cmd->directive->directive, 
                                     " ", cmd->directive->args, NULL);
    if (element->flags & AM_COND_FLAG_REG) {
        int regex_flags = AP_REG_EXTENDED|AP_REG_NOSUB;

        if (element->flags & AM_COND_FLAG_NC)
            regex_flags |= AP_REG_ICASE;

        element->regex = ap_pregcomp(cmd->pool, value, regex_flags);
        if (element->regex == NULL) 
             return apr_psprintf(cmd->pool, "%s - invalid regex %s",
                                 cmd->cmd->name, value);
    }

    /*
     * Flag values containing format strings to that we do 
     * not have to process the others at runtime.
     */ 
    if (strchr(value, '%') != NULL) 
        element->flags |= AM_COND_FLAG_FSTR;

    /*
     * We keep the string also for regex, so that we can 
     * print it for debug purpose and perform substitutions on it. 
     */
    element->str = value;
    
    return NULL;
}

/* This function handles the MellonRequire configuration directive, which
 * allows the user to restrict access based on attributes received from
 * the IdP.
 *
 * Parameters:
 *  cmd_parms *cmd       The command structure for the MellonRequire
 *                       configuration directive.
 *  void *struct_ptr     Pointer to the current directory configuration.
 *  const char *arg      Pointer to the configuration string.
 *
 * Returns:
 *  NULL on success or an error string on failure.
 */
static const char *am_set_require_slot(cmd_parms *cmd,
                                       void *struct_ptr,
                                       const char *arg)
{
    am_dir_cfg_rec *d = struct_ptr;
    char *attribute, *value;
    int i;
    am_cond_t *element;
    am_cond_t *first_element;

    attribute = ap_getword_conf(cmd->pool, &arg);
    value     = ap_getword_conf(cmd->pool, &arg);

    if (*attribute == '\0' || *value == '\0') {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           " takes at least two arguments", NULL);
    }

    /*
     * MellonRequire overwrites previous conditions on this attribute
     * We just tag the am_cond_t with the ignore flag, as it is 
     * easier (and probably faster) than to really remove it.
     */
    for (i = 0; i < d->cond->nelts; i++) {
        am_cond_t *ce = &((am_cond_t *)(d->cond->elts))[i];
 
        if ((strcmp(ce->varname, attribute) == 0) && 
            (ce->flags & AM_COND_FLAG_REQ))
            ce->flags |= AM_COND_FLAG_IGN;
    }
    
    first_element = NULL;
    do {
        element = (am_cond_t *)apr_array_push(d->cond);
        element->varname = attribute;
        element->flags = AM_COND_FLAG_OR|AM_COND_FLAG_REQ;
        element->str = value;
        element->regex = NULL;

        /*
         * When multiple values are given, we track the first one
         * in order to retreive the directive
         */ 
        if (first_element == NULL) {
            element->directive = apr_pstrcat(cmd->pool, 
                                             cmd->directive->directive, " ",
                                             cmd->directive->args, NULL);
            first_element = element;
        } else {
            element->directive = first_element->directive;
        }

    } while (*(value = ap_getword_conf(cmd->pool, &arg)) != '\0');

    /* 
     * Remove OR flag on last element 
     */
    element->flags &= ~AM_COND_FLAG_OR;

    return NULL;
}

/* This function handles the MellonOrganization* directives, which
 * which specify language-qualified strings
 *
 * Parameters:
 *  cmd_parms *cmd       The command structure for the MellonOrganization*
 *                       configuration directive.
 *  void *struct_ptr     Pointer to the current directory configuration.
 *  const char *lang     Pointer to the language string (optional)
 *  const char *value    Pointer to the data
 *
 * Returns:
 *  NULL on success or an error string on failure.
 */
static const char *am_set_langstring_slot(cmd_parms *cmd,
                                          void *struct_ptr,
                                          const char *lang,
                                          const char *value)
{
    apr_hash_t *h = *(apr_hash_t **)(struct_ptr + (apr_size_t)cmd->info);

    if (value == NULL || *value == '\0') {
        value = lang;
        lang = "";
    }

    apr_hash_set(h, lang, APR_HASH_KEY_STRING, 
		 apr_pstrdup(cmd->server->process->pconf, value));

    return NULL;
}

/* This function handles the MellonAuthnContextClassRef directive.
 *
 * Parameters:
 *  cmd_parms *cmd       The command structure for the MellonAuthnContextClassRef
 *                       configuration directive.
 *  void *struct_ptr     Pointer to the current directory configuration.
 *                       NULL if we are not in a directory configuration.
 *  const char *arg      An URI for an SAMLv2 AuthnContextClassRef
 *
 * Returns:
 *  This function will always return NULL.
 */
static const char *am_set_authn_context_class_ref(cmd_parms *cmd,
                                                  void *struct_ptr,
                                                  const char *arg)
{
    am_dir_cfg_rec *d = (am_dir_cfg_rec *)struct_ptr;
    apr_pool_t *p= cmd->pool;
    char **context_class_ref_p;

    if(strlen(arg) == 0) {
         return NULL;
    }
    context_class_ref_p = apr_array_push(d->authn_context_class_ref);
    *context_class_ref_p = apr_pstrdup(p, arg);
    return NULL;
}

/* This function handles the MellonDoNotVerifyLogoutSignature configuration directive, 
 * it is identical to the am_set_hash_string_slot function. You can refer to it.
 *
 * Parameters:
 *  cmd_parms *cmd       The command structure for this configuration
 *                       directive.
 *  void *struct_ptr     Pointer to the current directory configuration.
 *                       NULL if we are not in a directory configuration.
 *  const char *key      The string argument following this configuration
 *                       directive in the configuraion file.
 *
 * Returns:
 *  NULL on success or an error string on failure.
 */
static const char *am_set_do_not_verify_logout_signature(cmd_parms *cmd,
                                          void *struct_ptr,
                                          const char *key)
{
#ifdef HAVE_lasso_profile_set_signature_verify_hint
    return am_set_hash_string_slot(cmd, struct_ptr, key, NULL);
#else
    return apr_pstrcat(cmd->pool, cmd->cmd->name,
                       " is not usable as modmellon was compiled against "
                       "a version of the lasso library which miss the "
                       "function lasso_profile_set_signature_verify_hint.",
                       NULL);
#endif
}

/* This function handles the MellonMergeEnvVars configuration directive,
 * it sets merge_env_vars to nonempty separator (default semicolon),
 * or empty string to denote no merging.
 *
 * Parameters:
 *  cmd_parms *cmd       The command structure for this configuration
 *                       directive.
 *  void *struct_ptr     Pointer to the current directory configuration.
 *                       NULL if we are not in a directory configuration.
 *  const char *flag     On/Off flag
 *  const char *sep      Optional separator, should be only present with On
 *
 * Returns:
 *  NULL on success or an error string on failure.
 */
static const char *am_set_merge_env_vars(cmd_parms *cmd,
                                          void *struct_ptr,
                                          const char *flag,
                                          const char *sep)
{
    am_dir_cfg_rec *d = (am_dir_cfg_rec *)struct_ptr;
    apr_pool_t *p= cmd->pool;
    if (strcasecmp(flag, "on") == 0) {
        if (sep && *sep) {
            /*
             * TAKE12 will not give us the second argument if it is
             * empty string so we cannot complain about it, we will just
             * silently use semicolon
             */
            d->merge_env_vars = apr_pstrdup(p, sep);
        } else {
            d->merge_env_vars = ";";
        }
    } else if (strcasecmp(flag, "off") == 0) {
        if (sep) {
            return apr_pstrcat(cmd->pool, cmd->cmd->name,
                " separator should not be used with Off", NULL);
        }
        d->merge_env_vars = "";
    } else {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
            " first parameer must be On or Off", NULL);
    }
    return NULL;
}

/* Handle MellonRedirectDomains option.
 *
 * Parameters:
 *  cmd_parms *cmd       The command structure for this configuration
 *                       directive.
 *  void *struct_ptr     Pointer to the current directory configuration.
 *                       NULL if we are not in a directory configuration.
 *  int argc             Number of redirect domains.
 *  char *const argv[]   List of redirect domains.
 *
 * Returns:
 *  NULL on success, or errror string on failure.
 */
static const char *am_set_redirect_domains(cmd_parms *cmd,
                                          void *struct_ptr,
                                          int argc,
                                          char *const argv[])
{
    am_dir_cfg_rec *cfg = (am_dir_cfg_rec *)struct_ptr;
    const char **redirect_domains;
    int i;

    if (argc < 1)
        return apr_psprintf(cmd->pool, "%s takes at least one arguments",
                            cmd->cmd->name);

    redirect_domains = apr_palloc(cmd->pool, sizeof(const char *) * (argc + 1));
    for (i = 0; i < argc; i++) {
        redirect_domains[i] = argv[i];
    }
    redirect_domains[argc] = NULL;

    cfg->redirect_domains = redirect_domains;

    return NULL;
}

/* This array contains all the configuration directive which are handled
 * by auth_mellon.
 */    
const command_rec auth_mellon_commands[] = {

    /* Global configuration directives. */

    AP_INIT_TAKE1(
        "MellonCacheSize",
        am_set_module_config_int_slot,
        (void *)APR_OFFSETOF(am_mod_cfg_rec, cache_size),
        RSRC_CONF,
        "The number of sessions we can keep track of at once. You must"
        " restart the server before any changes to this directive will"
        " take effect. The default value is 100."
        ),
    AP_INIT_TAKE1(
        "MellonCacheEntrySize",
        am_set_module_config_int_slot,
        (void *)APR_OFFSETOF(am_mod_cfg_rec, entry_size),
        RSRC_CONF,
        "The maximum size for a single session entry. You must"
        " restart the server before any changes to this directive will"
        " take effect. The default value is 192KiB."
        ),
    AP_INIT_TAKE1(
        "MellonLockFile",
        am_set_module_config_file_slot,
        (void *)APR_OFFSETOF(am_mod_cfg_rec, lock_file),
        RSRC_CONF,
        "The lock file for session synchronization."
        " Default value is \"/var/run/mod_auth_mellon.lock\"."
        ), 
    AP_INIT_TAKE1(
        "MellonPostDirectory",
        am_set_module_config_file_slot,
        (void *)APR_OFFSETOF(am_mod_cfg_rec, post_dir),
        RSRC_CONF,
        "The directory for saving POST requests."
        " Not set by default."
        ), 
    AP_INIT_TAKE1(
        "MellonPostTTL",
        am_set_module_config_int_slot,
        (void *)APR_OFFSETOF(am_mod_cfg_rec, post_ttl),
        RSRC_CONF,
        "The time to live for saved POST requests in seconds."
        " Default value is 900 (15 minutes)."
        ), 
    AP_INIT_TAKE1(
        "MellonPostCount",
        am_set_module_config_int_slot,
        (void *)APR_OFFSETOF(am_mod_cfg_rec, post_count),
        RSRC_CONF,
        "The maximum saved POST sessions at once."
        " Default value is 100."
        ), 
    AP_INIT_TAKE1(
        "MellonPostSize",
        am_set_module_config_int_slot,
        (void *)APR_OFFSETOF(am_mod_cfg_rec, post_size),
        RSRC_CONF,
        "The maximum size of a saved POST, in bytes."
        " Default value is 1048576 (1 MB)."
        ), 


    /* Per-location configuration directives. */

    AP_INIT_TAKE1(
        "MellonEnable",
        am_set_enable_slot,
        NULL,
        OR_AUTHCFG,
        "Enable auth_mellon on a location. This can be set to 'off', 'info'"
        " and 'auth'. 'off' disables auth_mellon for a location, 'info'"
        " will only populate the environment with attributes if the user"
        " has logged in already. 'auth' will redirect the user to the IdP"
        " if he hasn't logged in yet, but otherwise behaves like 'info'."
        ),
    AP_INIT_TAKE1(
        "MellonDecoder",
        am_set_decoder_slot,
        NULL,
        OR_AUTHCFG,
        "Obsolete option, now a no-op for backwards compatibility."
        ),
    AP_INIT_TAKE1(
        "MellonVariable",
        ap_set_string_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, varname),
        OR_AUTHCFG,
        "The name of the cookie which auth_mellon will set. Defaults to"
        " 'cookie'. This string is appended to 'mellon-' to create the"
        " cookie name, and the default name of the cookie will therefore"
        " be 'mellon-cookie'."
        ),
    AP_INIT_TAKE1(
        "MellonSecureCookie",
        am_set_secure_slots,
        NULL,
        OR_AUTHCFG,
        "Whether the cookie set by auth_mellon should have HttpOnly and"
        " secure flags set. Default is 'off'. Once 'on' - both flags will"
        " be set. Values 'httponly' or 'secure' will respectively set only"
        " one flag."
        ),
    AP_INIT_TAKE1(
        "MellonCookieDomain",
        ap_set_string_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, cookie_domain),
        OR_AUTHCFG,
        "The domain of the cookie which auth_mellon will set. Defaults to"
        " the domain of the current request."
        ),
    AP_INIT_TAKE1(
        "MellonCookiePath",
        ap_set_string_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, cookie_path),
        OR_AUTHCFG,
        "The path of the cookie which auth_mellon will set. Defaults to"
        " '/'."
        ),
      AP_INIT_TAKE1(
        "MellonCookieSameSite",
        am_set_samesite_slot,
        NULL,
        OR_AUTHCFG,
        "The SameSite value for the auth_mellon cookie. Defaults to"
        " having no SameSite value. Accepts values of Lax or Strict."
        ), 
    AP_INIT_TAKE1(
        "MellonUser",
        ap_set_string_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, userattr),
        OR_AUTHCFG,
        "Attribute to set as r->user. Defaults to NAME_ID, which is the"
        " attribute we set to the identifier we receive from the IdP."
        ),
    AP_INIT_TAKE1(
        "MellonIdP",
        ap_set_string_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, idpattr),
        OR_AUTHCFG,
        "Attribute we set to the IdP ProviderId."
        ),
    AP_INIT_TAKE2(
        "MellonSetEnv",
        am_set_setenv_slot,
        NULL,
        OR_AUTHCFG,
        "Renames attributes received from the server while retaining prefix MELLON_. The format is"
        " MellonSetEnv <old name> <new name>."
        ),
     AP_INIT_TAKE2(
        "MellonSetEnvNoPrefix",
        am_set_setenv_no_prefix_slot,
        NULL,
        OR_AUTHCFG,
        "Renames attributes received from the server without adding prefix. The format is"
        " MellonSetEnvNoPrefix <old name> <new name>."
        ),
    AP_INIT_FLAG(
        "MellonSessionDump",
        ap_set_flag_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, dump_session),
        OR_AUTHCFG,
        "Dump session in environment. Default is off"
        ),
    AP_INIT_FLAG(
        "MellonSamlResponseDump",
        ap_set_flag_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, dump_saml_response),
        OR_AUTHCFG,
        "Dump SAML authentication response in environment. Default is off"
        ),
    AP_INIT_RAW_ARGS(
        "MellonRequire",
        am_set_require_slot,
        NULL,
        OR_AUTHCFG,
        "Attribute requirements for authorization. Allows you to restrict"
        " access based on attributes received from the IdP. If you list"
        " several MellonRequire configuration directives, then all of them"
        " must match. Every MellonRequire can list several allowed values"
        " for the attribute. The syntax is:"
        " MellonRequire <attribute> <value1> [value2....]."
        ),
    AP_INIT_TAKE23(
        "MellonCond",
        am_set_cond_slot,
        NULL,
        OR_AUTHCFG,
        "Attribute requirements for authorization. Allows you to restrict"
        " access based on attributes received from the IdP. The syntax is:"
        " MellonRequire <attribute> <value> [<options>]."
        ),
    AP_INIT_TAKE1(
        "MellonSessionLength",
        ap_set_int_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, session_length),
        OR_AUTHCFG,
        "Maximum number of seconds a session will be valid for. Defaults"
        " to 86400 seconds (1 day)."
        ),
    AP_INIT_TAKE1(
        "MellonNoCookieErrorPage",
        ap_set_string_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, no_cookie_error_page),
        OR_AUTHCFG,
        "Web page to display if the user has disabled cookies. We will"
        " return a 400 Bad Request error if this is unset and the user"
        " ha disabled cookies."
        ),
    AP_INIT_TAKE1(
        "MellonNoSuccessErrorPage",
        ap_set_string_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, no_success_error_page),
        OR_AUTHCFG,
        "Web page to display if the idp posts with a failed"
        " authentication error. We will return a 401 Unauthorized error"
        " if this is unset and the idp posts such assertion."
        ),
    AP_INIT_TAKE1(
        "MellonSPMetadataFile",
        am_set_filestring_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, sp_metadata_file),
        OR_AUTHCFG,
        "Full path to xml file with metadata for the SP."
        ),
    AP_INIT_TAKE1(
        "MellonSPPrivateKeyFile",
        am_set_filestring_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, sp_private_key_file),
        OR_AUTHCFG,
        "Full path to pem file with the private key for the SP."
        ),
    AP_INIT_TAKE1(
        "MellonSPCertFile",
        am_set_filestring_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, sp_cert_file),
        OR_AUTHCFG,
        "Full path to pem file with certificate for the SP."
        ),
    AP_INIT_TAKE12(
        "MellonIdPMetadataFile",
        am_set_idp_string_slot,
        NULL,
        OR_AUTHCFG,
        "Full path to xml metadata file for IdP, "
        "with optional validating chain."
        ),
    AP_INIT_TAKE12(
        "MellonIdPMetadataGlob",
        am_set_glob_fn12,
        am_set_idp_string_slot,
        OR_AUTHCFG,
        "Full path to xml metadata files for IdP, with glob(3) patterns. "
        "An optional validating chain can be supplied."
        ),
    AP_INIT_TAKE1(
        "MellonIdPPublicKeyFile",
        ap_set_file_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, idp_public_key_file),
        OR_AUTHCFG,
        "Full path to pem file with the public key for the IdP."
        ),
    AP_INIT_TAKE1(
        "MellonIdPCAFile",
        ap_set_file_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, idp_ca_file),
        OR_AUTHCFG,
        "Full path to pem file with CA chain for the IdP."
        ),
    AP_INIT_TAKE_ARGV(
        "MellonIdPIgnore",
        am_set_idp_ignore_slot,
        NULL,
        OR_AUTHCFG,
        "List of IdP entityId to ignore."
        ),
    AP_INIT_TAKE1(
        "MellonSPentityId",
        ap_set_string_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, sp_entity_id),
        OR_AUTHCFG,
        "SP entity Id to be used for metadata auto generation."
        ),
    AP_INIT_TAKE12(
        "MellonOrganizationName",
        am_set_langstring_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, sp_org_name),
        OR_AUTHCFG,
        "Language-qualified oranization name."
        ),
    AP_INIT_TAKE12(
        "MellonOrganizationDisplayName",
        am_set_langstring_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, sp_org_display_name),
        OR_AUTHCFG,
        "Language-qualified oranization name, human redable."
        ),
    AP_INIT_TAKE12(
        "MellonOrganizationURL",
        am_set_langstring_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, sp_org_url),
        OR_AUTHCFG,
        "Language-qualified oranization URL."
        ),
    AP_INIT_TAKE1(
        "MellonDefaultLoginPath",
        ap_set_string_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, login_path),
        OR_AUTHCFG,
        "The location where to redirect after IdP initiated login."
        " Default value is \"/\"."
        ),
    AP_INIT_TAKE1(
        "MellonDiscoveryURL",
        ap_set_string_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, discovery_url),
        OR_AUTHCFG,
        "The URL of IdP discovery service. Default is unset."
        ),
    AP_INIT_TAKE1(
        "MellonProbeDiscoveryTimeout",
        ap_set_int_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, probe_discovery_timeout),
        OR_AUTHCFG,
        "The timeout in seconds of IdP probe discovery service. "
        "The default is unset, which means that this feature is disabled."
        ),
    AP_INIT_TAKE12(
        "MellonProbeDiscoveryIdP",
        am_set_table_string_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, probe_discovery_idp),
        OR_AUTHCFG,
        "An IdP that can be used for IdP probe discovery."
        ),
    AP_INIT_TAKE1(
        "MellonEndpointPath",
        am_set_endpoint_path,
        NULL,
        OR_AUTHCFG,
        "The root directory of the SAML2 endpoints, relative to the root"
        " of the web server. Default value is \"/mellon/\", which will"
        " make mod_mellon to the handler for every request to"
        " \"http://<servername>/mellon/*\". The path you specify must"
        " be contained within the current Location directive."
        ),
    AP_INIT_TAKE1(
        "MellonAuthnContextClassRef",
        am_set_authn_context_class_ref,
        NULL,
        OR_AUTHCFG,
        "A list of AuthnContextClassRef to request in the AuthnRequest and "
        "to validate upon reception of an Assertion"
        ),
    AP_INIT_FLAG(
        "MellonSubjectConfirmationDataAddressCheck",
        ap_set_flag_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, subject_confirmation_data_address_check),
        OR_AUTHCFG,
        "Check address given in SubjectConfirmationData Address attribute. Default is on."
        ),
    AP_INIT_FLAG(
        "MellonSendCacheControlHeader",
        ap_set_flag_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, send_cache_control_header),
        OR_AUTHCFG,
        "Send the cache-control header on responses. Default is on."
        ),
    AP_INIT_TAKE1(
        "MellonDoNotVerifyLogoutSignature",
        am_set_do_not_verify_logout_signature,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, do_not_verify_logout_signature),
        OR_AUTHCFG,
        "A list of entity of IdP whose logout requests signatures will not "
        "be valided"
        ),
    AP_INIT_FLAG(
        "MellonPostReplay",
        ap_set_flag_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, post_replay),
        OR_AUTHCFG,
        "Whether we should replay POST requests that trigger authentication. Default is off."
        ),
    AP_INIT_TAKE12(
        "MellonMergeEnvVars",
        am_set_merge_env_vars,
        NULL,
        OR_AUTHCFG,
        "Whether to merge environment variables multi-values or not. Default is off."
        "When first parameter is on, optional second parameter is the separator, "
        "defaulting to semicolon."
        ),
    AP_INIT_TAKE1(
        "MellonEnvVarsIndexStart",
        ap_set_int_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, env_vars_index_start),
        OR_AUTHCFG,
        "Start indexing environment variables for multivalues with 0 or 1. Default is 0."
        ),
    AP_INIT_FLAG(
        "MellonEnvVarsSetCount",
        ap_set_flag_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, env_vars_count_in_n),
        OR_AUTHCFG,
        "Whether to also populate environment variable suffixed _N with number of values. Default is off."
        ),
    AP_INIT_FLAG(
        "MellonECPSendIDPList",
        ap_set_flag_slot,
        (void *)APR_OFFSETOF(am_dir_cfg_rec, ecp_send_idplist),
        OR_AUTHCFG,
        "Whether to send an ECP client a list of IdP's. Default is off."
        ),
    AP_INIT_TAKE_ARGV(
        "MellonRedirectDomains",
        am_set_redirect_domains,
        NULL,
        OR_AUTHCFG,
        "List of domains we can redirect to."
        ),
    {NULL}
};

const am_error_map_t auth_mellon_errormap[] = {
    { LASSO_PROFILE_ERROR_STATUS_NOT_SUCCESS, HTTP_UNAUTHORIZED },
#ifdef LASSO_PROFILE_ERROR_REQUEST_DENIED
    { LASSO_PROFILE_ERROR_REQUEST_DENIED, HTTP_UNAUTHORIZED },
#endif
    { 0, 0 }
};

/* Release a lasso_server object associated with this configuration.
 *
 * Parameters:
 *  void *data           The pointer to the configuration data.
 *
 * Returns:
 *  Always APR_SUCCESS.
 */
static apr_status_t auth_mellon_free_server(void *data)
{
    am_dir_cfg_rec *dir = data;

    if (dir->server != NULL) {
        lasso_server_destroy(dir->server);
        dir->server = NULL;
    }

    return APR_SUCCESS;
}


/* This function creates and initializes a directory configuration
 * object for auth_mellon.
 *
 * Parameters:
 *  apr_pool_t *p        The pool we should allocate memory from.
 *  char *d              Unused, always NULL.
 *
 * Returns:
 *  The new directory configuration object.
 */
void *auth_mellon_dir_config(apr_pool_t *p, char *d)
{
    am_dir_cfg_rec *dir = apr_palloc(p, sizeof(*dir));

    apr_pool_cleanup_register(p, dir, auth_mellon_free_server,
                              auth_mellon_free_server);

    dir->enable_mellon = am_enable_default;

    dir->varname = default_cookie_name;
    dir->secure = default_secure_cookie;
    dir->http_only = default_http_only_cookie;
    dir->merge_env_vars = default_merge_env_vars;
    dir->env_vars_index_start = default_env_vars_index_start;
    dir->env_vars_count_in_n = default_env_vars_count_in_n;
    dir->cond = apr_array_make(p, 0, sizeof(am_cond_t));
    dir->cookie_domain = NULL;
    dir->cookie_path = NULL;
    dir->cookie_samesite = am_samesite_default;
    dir->envattr   = apr_hash_make(p);
    dir->userattr  = default_user_attribute;
    dir->idpattr  = NULL;
    dir->dump_session = default_dump_session;
    dir->dump_saml_response = default_dump_saml_response;

    dir->endpoint_path = default_endpoint_path;

    dir->session_length = -1; /* -1 means use default. */

    dir->no_cookie_error_page = NULL;
    dir->no_success_error_page = NULL;

    dir->sp_metadata_file = NULL;
    dir->sp_private_key_file = NULL;
    dir->sp_cert_file = NULL;
    dir->idp_metadata = apr_array_make(p, 0, sizeof(am_metadata_t));
    dir->idp_public_key_file = NULL;
    dir->idp_ca_file = NULL;
    dir->idp_ignore = NULL;
    dir->login_path = default_login_path;
    dir->discovery_url = NULL;
    dir->probe_discovery_timeout = -1; /* -1 means no probe discovery */
    dir->probe_discovery_idp = apr_table_make(p, 0);

    dir->sp_entity_id = NULL;
    dir->sp_org_name = apr_hash_make(p);
    dir->sp_org_display_name = apr_hash_make(p);
    dir->sp_org_url = apr_hash_make(p);

    apr_thread_mutex_create(&dir->server_mutex, APR_THREAD_MUTEX_DEFAULT, p);
    dir->inherit_server_from = dir;
    dir->server = NULL;
    dir->authn_context_class_ref = apr_array_make(p, 0, sizeof(char *));
    dir->subject_confirmation_data_address_check = inherit_subject_confirmation_data_address_check;
    dir->send_cache_control_header = inherit_send_cache_control_header;
    dir->do_not_verify_logout_signature = apr_hash_make(p);
    dir->post_replay = inherit_post_replay;
    dir->redirect_domains = default_redirect_domains;

    dir->ecp_send_idplist = inherit_ecp_send_idplist;

    return dir;
}


/* Determine whether this configuration changes anything relevant to the
 * lasso_server configuration.
 *
 * Parameters:
 *  am_dir_cfg_rec *add_cfg   The new configuration.
 *
 * Returns:
 *  true if we can inherit the lasso_server object, false if not.
 */
static bool cfg_can_inherit_lasso_server(const am_dir_cfg_rec *add_cfg)
{
    if (add_cfg->endpoint_path != default_endpoint_path)
        return false;

    if (add_cfg->sp_metadata_file != NULL
        || add_cfg->sp_private_key_file != NULL
        || add_cfg->sp_cert_file != NULL)
        return false;
    if (add_cfg->idp_metadata->nelts > 0
        || add_cfg->idp_public_key_file != NULL
        || add_cfg->idp_ca_file != NULL
        || add_cfg->idp_ignore != NULL)
        return false;

    if (apr_hash_count(add_cfg->sp_org_name) > 0
        || apr_hash_count(add_cfg->sp_org_display_name) > 0
        || apr_hash_count(add_cfg->sp_org_url) > 0)
        return false;

    return true;
}


/* This function merges two am_dir_cfg_rec structures.
 * It will try to inherit from the base where possible.
 *
 * Parameters:
 *  apr_pool_t *p        The pool we should allocate memory from.
 *  void *base           The original structure.
 *  void *add            The structure we should add to base.
 *
 * Returns:
 *  The merged structure.
 */
void *auth_mellon_dir_merge(apr_pool_t *p, void *base, void *add)
{
    am_dir_cfg_rec *base_cfg = (am_dir_cfg_rec *)base;
    am_dir_cfg_rec *add_cfg = (am_dir_cfg_rec *)add;
    am_dir_cfg_rec *new_cfg;

    new_cfg = (am_dir_cfg_rec *)apr_palloc(p, sizeof(*new_cfg));

    apr_pool_cleanup_register(p, new_cfg, auth_mellon_free_server,
                              auth_mellon_free_server);


    new_cfg->enable_mellon = (add_cfg->enable_mellon != am_enable_default ?
                              add_cfg->enable_mellon :
                              base_cfg->enable_mellon);


    new_cfg->varname = (add_cfg->varname != default_cookie_name ?
                        add_cfg->varname :
                        base_cfg->varname);


    new_cfg->secure = (add_cfg->secure != default_secure_cookie ?
                        add_cfg->secure :
                        base_cfg->secure);

    new_cfg->http_only = (add_cfg->http_only != default_http_only_cookie ?
                        add_cfg->http_only :
                        base_cfg->http_only);

    new_cfg->merge_env_vars = (add_cfg->merge_env_vars != default_merge_env_vars ?
                               add_cfg->merge_env_vars :
                               base_cfg->merge_env_vars);

    new_cfg->env_vars_index_start = (add_cfg->env_vars_index_start != default_env_vars_index_start ?
                               add_cfg->env_vars_index_start :
                               base_cfg->env_vars_index_start);

    new_cfg->env_vars_count_in_n = (add_cfg->env_vars_count_in_n != default_env_vars_count_in_n ?
                               add_cfg->env_vars_count_in_n :
                               base_cfg->env_vars_count_in_n);

    new_cfg->cookie_domain = (add_cfg->cookie_domain != NULL ?
                        add_cfg->cookie_domain :
                        base_cfg->cookie_domain);

    new_cfg->cookie_path = (add_cfg->cookie_path != NULL ?
                        add_cfg->cookie_path :
                        base_cfg->cookie_path);

    new_cfg->cookie_samesite = (add_cfg->cookie_samesite != am_samesite_default ?
                              add_cfg->cookie_samesite :
                              base_cfg->cookie_samesite);

    new_cfg->cond = apr_array_copy(p,
                                   (!apr_is_empty_array(add_cfg->cond)) ?
                                   add_cfg->cond :
                                   base_cfg->cond);

    new_cfg->envattr = apr_hash_copy(p,
                                     (apr_hash_count(add_cfg->envattr) > 0) ?
                                     add_cfg->envattr :
                                     base_cfg->envattr);

    new_cfg->userattr = (add_cfg->userattr != default_user_attribute ?
                         add_cfg->userattr :
                         base_cfg->userattr);

    new_cfg->idpattr = (add_cfg->idpattr != NULL ?
                        add_cfg->idpattr :
                        base_cfg->idpattr);

    new_cfg->dump_session = (add_cfg->dump_session != default_dump_session ?
                             add_cfg->dump_session :
                             base_cfg->dump_session);

    new_cfg->dump_saml_response = 
        (add_cfg->dump_saml_response != default_dump_saml_response ?
         add_cfg->dump_saml_response :
         base_cfg->dump_saml_response);

    new_cfg->endpoint_path = (
        add_cfg->endpoint_path != default_endpoint_path ?
        add_cfg->endpoint_path :
        base_cfg->endpoint_path
        );

    new_cfg->session_length = (add_cfg->session_length != -1 ?
                               add_cfg->session_length :
                               base_cfg->session_length);

    new_cfg->no_cookie_error_page = (add_cfg->no_cookie_error_page != NULL ?
                                     add_cfg->no_cookie_error_page :
                                     base_cfg->no_cookie_error_page);

    new_cfg->no_success_error_page = (add_cfg->no_success_error_page != NULL ?
                                     add_cfg->no_success_error_page :
                                     base_cfg->no_success_error_page);


    new_cfg->sp_metadata_file = (add_cfg->sp_metadata_file ?
                                 add_cfg->sp_metadata_file :
                                 base_cfg->sp_metadata_file);

    new_cfg->sp_private_key_file = (add_cfg->sp_private_key_file ?
                                    add_cfg->sp_private_key_file :
                                    base_cfg->sp_private_key_file);

    new_cfg->sp_cert_file = (add_cfg->sp_cert_file ?
                             add_cfg->sp_cert_file :
                             base_cfg->sp_cert_file);

    new_cfg->idp_metadata = (add_cfg->idp_metadata->nelts ?
                             add_cfg->idp_metadata :
                             base_cfg->idp_metadata);

    new_cfg->idp_public_key_file = (add_cfg->idp_public_key_file ?
                                    add_cfg->idp_public_key_file :
                                    base_cfg->idp_public_key_file);

    new_cfg->idp_ca_file = (add_cfg->idp_ca_file ?
                            add_cfg->idp_ca_file :
                            base_cfg->idp_ca_file);

    new_cfg->idp_ignore = add_cfg->idp_ignore != NULL ?
                          add_cfg->idp_ignore :
                          base_cfg->idp_ignore;

    new_cfg->sp_entity_id = (add_cfg->sp_entity_id ?
                             add_cfg->sp_entity_id :
                             base_cfg->sp_entity_id);

    new_cfg->sp_org_name = apr_hash_copy(p,
                          (apr_hash_count(add_cfg->sp_org_name) > 0) ?
                           add_cfg->sp_org_name : 
                           base_cfg->sp_org_name);

    new_cfg->sp_org_display_name = apr_hash_copy(p,
                          (apr_hash_count(add_cfg->sp_org_display_name) > 0) ?
                           add_cfg->sp_org_display_name : 
                           base_cfg->sp_org_display_name);

    new_cfg->sp_org_url = apr_hash_copy(p,
                          (apr_hash_count(add_cfg->sp_org_url) > 0) ?
                           add_cfg->sp_org_url : 
                           base_cfg->sp_org_url);

    new_cfg->login_path = (add_cfg->login_path != default_login_path ?
                           add_cfg->login_path :
                           base_cfg->login_path);

    new_cfg->discovery_url = (add_cfg->discovery_url ?
                              add_cfg->discovery_url :
                              base_cfg->discovery_url);

    new_cfg->probe_discovery_timeout = 
                           (add_cfg->probe_discovery_timeout != -1 ?
                            add_cfg->probe_discovery_timeout :
                            base_cfg->probe_discovery_timeout);

    new_cfg->probe_discovery_idp = apr_table_copy(p,
                           (!apr_is_empty_table(add_cfg->probe_discovery_idp)) ?
                            add_cfg->probe_discovery_idp : 
                            base_cfg->probe_discovery_idp);


    if (cfg_can_inherit_lasso_server(add_cfg)) {
        new_cfg->inherit_server_from = base_cfg->inherit_server_from;
    } else {
        apr_thread_mutex_create(&new_cfg->server_mutex,
                                APR_THREAD_MUTEX_DEFAULT, p);
        new_cfg->inherit_server_from = new_cfg;
    }

    new_cfg->server = NULL;

    new_cfg->authn_context_class_ref = (add_cfg->authn_context_class_ref->nelts ?
                             add_cfg->authn_context_class_ref :
                             base_cfg->authn_context_class_ref);

    new_cfg->do_not_verify_logout_signature = apr_hash_copy(p, 
                             (apr_hash_count(add_cfg->do_not_verify_logout_signature) > 0) ?
                             add_cfg->do_not_verify_logout_signature :
                             base_cfg->do_not_verify_logout_signature);

    new_cfg->subject_confirmation_data_address_check =
        CFG_MERGE(add_cfg, base_cfg, subject_confirmation_data_address_check);

    new_cfg->send_cache_control_header =
        CFG_MERGE(add_cfg, base_cfg, send_cache_control_header);

    new_cfg->post_replay = CFG_MERGE(add_cfg, base_cfg, post_replay);

    new_cfg->ecp_send_idplist = CFG_MERGE(add_cfg, base_cfg, ecp_send_idplist);

    new_cfg->redirect_domains =
        (add_cfg->redirect_domains != default_redirect_domains ?
         add_cfg->redirect_domains :
         base_cfg->redirect_domains);

    return new_cfg;
}


/* This function creates a new per-server configuration.
 * auth_mellon uses the server configuration to store a pointer
 * to the global module configuration.
 *
 * Parameters:
 *  apr_pool_t *p        The pool we should allocate memory from.
 *  server_rec *s        The server we should add our configuration to.
 *
 * Returns:
 *  The new per-server configuration.
 */
void *auth_mellon_server_config(apr_pool_t *p, server_rec *s)
{
    am_srv_cfg_rec *srv;
    am_mod_cfg_rec *mod;
    const char key[] = "auth_mellon_server_config";

    srv = apr_palloc(p, sizeof(*srv));

    /* we want to keeep our global configuration of shared memory and
     * mutexes, so we try to find it in the userdata before doing anything
     * else */
    apr_pool_userdata_get((void **)&mod, key, p);
    if (mod) {
        srv->mc = mod;
        return srv;
    }

    /* the module has not been initiated at all */
    mod = apr_palloc(p, sizeof(*mod));

    mod->cache_size = 100;  /* ought to be enough for everybody */
    mod->lock_file  = "/var/run/mod_auth_mellon.lock";
    mod->post_dir   = NULL;
    mod->post_ttl   = post_ttl;
    mod->post_count = post_count;
    mod->post_size  = post_size;

    mod->entry_size = AM_CACHE_DEFAULT_ENTRY_SIZE;

    mod->init_cache_size = 0;
    mod->init_lock_file = NULL;
    mod->init_entry_size = 0;

    mod->cache      = NULL;
    mod->lock       = NULL;

    apr_pool_userdata_set(mod, key, apr_pool_cleanup_null, p);

    srv->mc = mod;
    return srv;
}

