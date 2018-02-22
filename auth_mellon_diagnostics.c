#include "auth_mellon.h"

#ifdef ENABLE_DIAGNOSTICS

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#if APR_HAVE_PROCESS_H
#include <process.h>            /* for getpid() on Win32 */
#endif

/*============================= Internal Static ==============================*/

/*------------------ Defines ------------------*/

#define AM_DIAG_ENABLED(diag_cfg)                                       \
    (diag_cfg && diag_cfg->fd && (diag_cfg->flags & AM_DIAG_FLAG_ENABLED))

/*------------------ Typedefs ------------------*/

typedef struct iter_callback_data {
    apr_file_t *diag_fd;
    int level;
} iter_callback_data;

/*------------------ Prototypes ------------------*/

static const char *
indent(int level);

static void
write_indented_text(apr_file_t *diag_fd, int level, const char* text);

static void
am_diag_format_line(apr_pool_t *pool, apr_file_t *diag_fd, int level,
                    const char *fmt, va_list ap);

static const char *
am_diag_cond_flag_str(request_rec *r, am_cond_flag_t flags);

static const char *
am_diag_enable_str(request_rec *r, am_enable_t enable);

static const char *
am_diag_samesite_str(request_rec *r, am_samesite_t samesite);

static const char *
am_diag_httpd_error_level_str(request_rec *r, int level);

static const char *
am_diag_signature_method_str(request_rec *r,
                             LassoSignatureMethod signature_method);
static apr_size_t
am_diag_time_t_to_8601_buf(char *buf, apr_size_t buf_size, apr_time_t t);

static int
am_diag_open_log(server_rec *s, apr_pool_t *p);

static int
am_table_count(void *rec, const char *key, const char *value);

static int
log_headers(void *rec, const char *key, const char *value);

static int
log_probe_discovery_idp(void *rec, const char *key, const char *value);

static void
am_diag_log_dir_cfg(request_rec *r, int level, am_dir_cfg_rec *cfg,
                    const char *fmt, ...)
    __attribute__((format(printf,4,5)));

static bool
am_diag_initialize_req(request_rec *r, am_diag_cfg_rec *diag_cfg,
                       am_req_cfg_rec *req_cfg);

/*------------------ Functions ------------------*/

static const char *
indent(int level)
{
    static const char * const indents[] = {
        "",                     /* 0 */
        "  ",                   /* 1 */
        "    ",                 /* 2 */
        "      ",               /* 3 */
        "        ",             /* 4 */
        "          ",           /* 5 */
        "            ",         /* 6 */
        "              ",       /* 7 */
        "                ",     /* 8 */
        "                  ",   /* 9 */
    };
    int n_indents = sizeof(indents)/sizeof(indents[0]);

    if (level < 0) {
        return "";
    }
    if (level < n_indents) {
        return indents[level];
    }
    return indents[n_indents-1];
}

static void
write_indented_text(apr_file_t *diag_fd, int level, const char* text)
{
    const char *start, *end, *prefix;
    size_t len, prefix_len;
    bool crlf = false;

    if (!text) return;

    prefix = indent(level);
    prefix_len = strlen(prefix);
    start = end = text;
    while (*end) {
         /* find end of line */
        for (; *end && *end != '\n'; end++);
        if (*end == '\n') {
            /* was this a crlf sequence? */
            if (end > text && end[-1] == '\r') crlf = true;
            /* advance past line ending */
            end += 1;
        }
        /* length of line including line ending */
        len = end - start;
        /* write indent prefix */
        apr_file_write_full(diag_fd, prefix, prefix_len, NULL);
        /* write line including line ending */
        apr_file_write_full(diag_fd, start, len, NULL);
        /* begin again where we left off */
        start = end;
    }
    /* always write a trailing line ending */
    if (end > text && end[-1] != '\n') {
        if (crlf) {
            apr_file_write_full(diag_fd, "\r\n", 2, NULL);
        } else {
            apr_file_write_full(diag_fd, "\n", 1, NULL);
        }
    }
}

static void
am_diag_format_line(apr_pool_t *pool, apr_file_t *diag_fd, int level,
                    const char *fmt, va_list ap)
{
    char * buf = NULL;
    apr_size_t buf_len;

    if (fmt) {
        buf = apr_pvsprintf(pool, fmt, ap);
        buf_len = strlen(buf);
        if (buf_len > 0) {
            const char *prefix = indent(level);
            apr_size_t prefix_len = strlen(prefix);
            apr_file_write_full(diag_fd, prefix, prefix_len, NULL);
            apr_file_write_full(diag_fd, buf, buf_len, NULL);
            apr_file_putc('\n', diag_fd);
        }

    }
}

static const char *
am_diag_cond_flag_str(request_rec *r, am_cond_flag_t flags)
{
    char *str;
    char *comma;

    str = apr_pstrcat(r->pool,
                      "[",
                      flags & AM_COND_FLAG_OR   ? "OR,"   : "",
                      flags & AM_COND_FLAG_NOT  ? "NOT,"  : "",
                      flags & AM_COND_FLAG_REG  ? "REG,"  : "",
                      flags & AM_COND_FLAG_NC   ? "NC,"   : "",
                      flags & AM_COND_FLAG_MAP  ? "MAP,"  : "",
                      flags & AM_COND_FLAG_REF  ? "REF,"  : "",
                      flags & AM_COND_FLAG_SUB  ? "SUB,"  : "",
                      flags & AM_COND_FLAG_IGN  ? "IGN,"  : "",
                      flags & AM_COND_FLAG_REQ  ? "REQ,"  : "",
                      flags & AM_COND_FLAG_FSTR ? "FSTR," : "",
                      "]",
                      NULL);

    /* replace trailing ",]" with "]" */
    comma = rindex(str, ',');
    if (comma) {
        *comma = ']';
        *(comma+1) = 0;
    }
    return str;
}

static const char *
am_diag_enable_str(request_rec *r, am_enable_t enable)
{
    switch(enable) {
    case am_enable_default: return "default";
    case am_enable_off:     return "off";
    case am_enable_info:    return "info";
    case am_enable_auth:    return "auth";
    default:
        return apr_psprintf(r->pool, "unknown (%d)", enable);
    }

}

static const char *
am_diag_samesite_str(request_rec *r, am_samesite_t samesite)
{
    switch(samesite) {
    case am_samesite_default: return "default";
    case am_samesite_lax:     return "lax";
    case am_samesite_strict:  return "strict";
    default:
        return apr_psprintf(r->pool, "unknown (%d)", samesite);
    }
}

static const char *
am_diag_httpd_error_level_str(request_rec *r, int level)
{
    switch(level) {
    case APLOG_EMERG:   return "APLOG_EMERG";
    case APLOG_ALERT:   return "APLOG_ALERT";
    case APLOG_CRIT:    return "APLOG_CRIT";
    case APLOG_ERR:     return "APLOG_ERR";
    case APLOG_WARNING: return "APLOG_WARNING";
    case APLOG_NOTICE:  return "APLOG_NOTICE";
    case APLOG_INFO:    return "APLOG_INFO";
    case APLOG_DEBUG:   return "APLOG_DEBUG";
    case APLOG_TRACE1:  return "APLOG_TRACE1";
    case APLOG_TRACE2:  return "APLOG_TRACE2";
    case APLOG_TRACE3:  return "APLOG_TRACE3";
    case APLOG_TRACE4:  return "APLOG_TRACE4";
    case APLOG_TRACE5:  return "APLOG_TRACE5";
    case APLOG_TRACE6:  return "APLOG_TRACE6";
    case APLOG_TRACE7:  return "APLOG_TRACE7";
    case APLOG_TRACE8:  return "APLOG_TRACE8";
    default:
        return apr_psprintf(r->pool, "APLOG_%d", level);
    }
}

static const char *
am_diag_signature_method_str(request_rec *r,
                             LassoSignatureMethod signature_method)
{
    switch(signature_method) {
    case LASSO_SIGNATURE_METHOD_RSA_SHA1:    return "rsa-sha1";
#if HAVE_DECL_LASSO_SIGNATURE_METHOD_RSA_SHA256
    case LASSO_SIGNATURE_METHOD_RSA_SHA256:  return "rsa-sha256";
#endif
#if HAVE_DECL_LASSO_SIGNATURE_METHOD_RSA_SHA384
    case LASSO_SIGNATURE_METHOD_RSA_SHA384:  return "rsa-sha384";
#endif
#if HAVE_DECL_LASSO_SIGNATURE_METHOD_RSA_SHA512
    case LASSO_SIGNATURE_METHOD_RSA_SHA512:  return "rsa-sha512";
#endif
    default:
        return apr_psprintf(r->pool, "unknown (%d)", signature_method);
    }
}

static apr_size_t
am_diag_time_t_to_8601_buf(char *buf, apr_size_t buf_size, apr_time_t t)
{
    apr_size_t ret_size;
    apr_time_exp_t tm;
    const char fmt[] = "%FT%TZ";

    apr_time_exp_gmt(&tm, t);
    apr_strftime(buf, &ret_size, buf_size, fmt, &tm);

    /* on errror assure string is null terminated */
    if (ret_size == 0) buf[0] = 0;
    return ret_size;
}

static int
am_diag_open_log(server_rec *s, apr_pool_t *p)
{
    const char *server_name = NULL;
    const char *server_desc = NULL;
    am_diag_cfg_rec *diag_cfg = am_get_diag_cfg(s);

    /* Build the ServerName as it would appear in the ServerName directive */
    if (s->server_scheme) {
        server_name = apr_psprintf(p, "%s://%s",
                                       s->server_scheme, s->server_hostname);
    } else {
        server_name = apr_psprintf(p, "%s", s->server_hostname);
    }
    if (s->port) {
        server_name = apr_psprintf(p, "%s:%u", server_name, s->port);
    }

    if (s->is_virtual) {
        server_desc = apr_psprintf(p, "virtual server %s:%d (%s:%u)"
                                   " ServerName=%s",
                                   s->addrs->virthost, s->addrs->host_port,
                                   s->defn_name, s->defn_line_number,
                                   server_name);
    } else {
        server_desc = apr_psprintf(p, "main server, ServerName=%s",
                                   server_name);
    }

    if (!(diag_cfg->flags & AM_DIAG_FLAG_ENABLED)) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                     "mellon diagnostics disabled for %s", server_desc);
        return 1;
    } else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                     "mellon diagnostics enabled for %s, "
                     "diagnostics filename=%s",
                     server_desc, diag_cfg->filename);
    }

    if (!diag_cfg->filename || diag_cfg->fd)
        return 1;

    if (*diag_cfg->filename == '|') {
        piped_log *pl;
        const char *pname = ap_server_root_relative(p, diag_cfg->filename + 1);

        pl = ap_open_piped_log(p, pname);
        if (pl == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "couldn't spawn mellon diagnostics log pipe %s",
                         diag_cfg->filename);
            return 0;
        }
        diag_cfg->fd = ap_piped_log_write_fd(pl);
    }
    else {
        const char *fname = ap_server_root_relative(p, diag_cfg->filename);
        apr_status_t rv;

        if ((rv = apr_file_open(&diag_cfg->fd, fname,
                                APR_WRITE | APR_APPEND | APR_CREATE,
                                APR_OS_DEFAULT, p)) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         "could not open mellon diagnostics log file %s.",
                         fname);
            return 0;
        }
    }

    return 1;
}

static int
am_table_count(void *rec, const char *key, const char *value)
{
    int *n_items = (int *)rec;

    (*n_items)++;

    return 1;
}

static int
log_headers(void *rec, const char *key, const char *value)
{
    iter_callback_data *iter_data = (iter_callback_data *)rec;

    apr_file_printf(iter_data->diag_fd, "%s%s: %s\n",
                    indent(iter_data->level), key, value);

    return 1;
}

static int
log_probe_discovery_idp(void *rec, const char *key, const char *value)
{
    iter_callback_data *iter_data = (iter_callback_data *)rec;

    apr_file_printf(iter_data->diag_fd,
                    "%s%s: %s\n", indent(iter_data->level), key, value);

    return 1;
}

static void
am_diag_log_dir_cfg(request_rec *r, int level, am_dir_cfg_rec *cfg,
                    const char *fmt, ...)
{
    va_list ap;
    am_diag_cfg_rec *diag_cfg = am_get_diag_cfg(r->server);
    am_req_cfg_rec *req_cfg = am_get_req_cfg(r);
    int i, n_items;
    apr_hash_index_t *hash_item;
    GList *list_item;
    iter_callback_data iter_data;

    if (!AM_DIAG_ENABLED(diag_cfg)) return;
    if (!am_diag_initialize_req(r, diag_cfg, req_cfg)) return;

    iter_data.diag_fd = diag_cfg->fd;
    iter_data.level = level+1;

    va_start(ap, fmt);
    am_diag_format_line(r->pool, diag_cfg->fd, level, fmt, ap);
    va_end(ap);

    if (!cfg) {
        apr_file_flush(diag_cfg->fd);
        return;
    }

    apr_file_printf(diag_cfg->fd,
                    "%sMellonEnable (enable): %s\n",
                    indent(level+1), am_diag_enable_str(r, cfg->enable_mellon));
    apr_file_printf(diag_cfg->fd,
                    "%sMellonVariable (varname): %s\n",
                    indent(level+1), cfg->varname);
    apr_file_printf(diag_cfg->fd,
                    "%sMellonSecureCookie (secure): %s\n",
                    indent(level+1), cfg->secure ? "On":"Off"); /* FIXME, should be combined? */
    apr_file_printf(diag_cfg->fd,
                    "%sMellonSecureCookie (httpd_only): %s\n",
                    indent(level+1), cfg->http_only ? "On":"Off");
    apr_file_printf(diag_cfg->fd,
                    "%sMellonMergeEnvVars (merge_env_vars): %s\n",
                    indent(level+1), cfg->merge_env_vars);
    apr_file_printf(diag_cfg->fd,
                    "%sMellonEnvVarsIndexStart (env_vars_index_start): %d\n",
                    indent(level+1), cfg->env_vars_index_start);
    apr_file_printf(diag_cfg->fd,
                    "%sMellonEnvVarsSetCount (env_vars_count_in_n): %s\n",
                    indent(level+1), cfg->env_vars_count_in_n ? "On":"Off");
    apr_file_printf(diag_cfg->fd,
                    "%sMellonCookieDomain (cookie_domain): %s\n",
                    indent(level+1), cfg->cookie_domain);
    apr_file_printf(diag_cfg->fd,
                    "%sMellonCookiePath (cookie_path): %s\n",
                    indent(level+1), cfg->cookie_path);
    apr_file_printf(diag_cfg->fd,
                    "%sMellonCookieSameSite (cookie_samesite): %s\n",
                    indent(level+1),
                    am_diag_samesite_str(r, cfg->cookie_samesite));

    apr_file_printf(diag_cfg->fd,
                    "%sMellonCond (cond): %d items\n",
                    indent(level+1), cfg->cond->nelts);
    for (i = 0; i < cfg->cond->nelts; i++) {
        const am_cond_t *cond = &((am_cond_t *)(cfg->cond->elts))[i];
        apr_file_printf(diag_cfg->fd,
                        "%s[%2d]: %s\n",
                        indent(level+2), i, am_diag_cond_str(r, cond));
    }

    apr_file_printf(diag_cfg->fd,
                    "%sMellonSetEnv (envattr): %u items\n",
                    indent(level+1), apr_hash_count(cfg->envattr));
    for (hash_item = apr_hash_first(r->pool, cfg->envattr);
         hash_item;
         hash_item = apr_hash_next(hash_item)) {
        const char *key;
        const am_envattr_conf_t *envattr_conf;
        const char *name;

        apr_hash_this(hash_item, (void *)&key, NULL, (void *)&envattr_conf);

        if (envattr_conf->prefixed) {
            name = apr_pstrcat(r->pool, "MELLON_",
                               envattr_conf->name, NULL);
        } else {
            name = envattr_conf->name;
        }

        apr_file_printf(diag_cfg->fd,
                        "%s%s ==> %s\n",
                        indent(level+2), key, name);
    }
    apr_file_printf(diag_cfg->fd,
                    "%sMellonUser (userattr): %s\n",
                    indent(level+1), cfg->userattr);
    apr_file_printf(diag_cfg->fd,
                    "%sMellonIdP (idpattr): %s\n",
                    indent(level+1), cfg->idpattr);
    apr_file_printf(diag_cfg->fd,
                    "%sMellonSessionDump (dump_session): %s\n",
                    indent(level+1), cfg->dump_session ? "On":"Off");
    apr_file_printf(diag_cfg->fd,
                    "%sMellonSamlResponseDump (dump_saml_response): %s\n",
                    indent(level+1), cfg->dump_saml_response ? "On":"Off");
    apr_file_printf(diag_cfg->fd,
                    "%sMellonEndpointPath (endpoint_path): %s\n",
                    indent(level+1), cfg->endpoint_path);
    am_diag_log_file_data(r, level+1, cfg->sp_metadata_file,
                          "MellonSPMetadataFile (sp_metadata_file):");
    am_diag_log_file_data(r, level+1, cfg->sp_private_key_file,
                          "MellonSPPrivateKeyFile (sp_private_key_file):");
    am_diag_log_file_data(r, level+1, cfg->sp_cert_file,
                          "MellonSPCertFile (sp_cert_file):");
    am_diag_log_file_data(r, level+1, cfg->idp_public_key_file,
                          "MellonIdPPublicKeyFile (idp_public_key_file):");
    am_diag_log_file_data(r, level+1, cfg->idp_ca_file,
                          "MellonIdPCAFile (idp_ca_file):");

    apr_file_printf(diag_cfg->fd,
                    "%sMellonIdPMetadataFile (idp_metadata): %d items\n",
                    indent(level+1), cfg->idp_metadata->nelts);
    for (i = 0; i < cfg->idp_metadata->nelts; i++) {
        const am_metadata_t *idp_metadata;
        idp_metadata = &(((const am_metadata_t*)cfg->idp_metadata->elts)[i]);

        am_diag_log_file_data(r, level+1, idp_metadata->metadata,
                              "[%2d] Metadata", i);
        am_diag_log_file_data(r, level+1, idp_metadata->chain,
                              "[%2d] Chain File", i);
    }

    apr_file_printf(diag_cfg->fd,
                    "%sMellonIdPIgnore (idp_ignore):\n",
                    indent(level+1));
    for (list_item = cfg->idp_ignore, i = 0;
         list_item;
         list_item = g_list_next(list_item), i++) {
        apr_file_printf(diag_cfg->fd,
                        "%s[%2d]: %s\n",
                        indent(level+2), i, (char *)list_item->data);
    }

    apr_file_printf(diag_cfg->fd,
                    "%sMellonSPentityId (sp_entity_id): %s\n",
                    indent(level+1), cfg->sp_entity_id);

    apr_file_printf(diag_cfg->fd,
                    "%sMellonOrganizationName (sp_org_name): %u items\n",
                    indent(level+1), apr_hash_count(cfg->sp_org_name));
    for (hash_item = apr_hash_first(r->pool, cfg->sp_org_name);
         hash_item;
         hash_item = apr_hash_next(hash_item)) {
        const char *lang;
        const char *value;

        apr_hash_this(hash_item, (void *)&lang, NULL, (void *)&value);
        apr_file_printf(diag_cfg->fd,
                        "%s(lang=%s): %s\n",
                        indent(level+2), lang, value);
    }

    apr_file_printf(diag_cfg->fd,
                    "%sMellonOrganizationDisplayName (sp_org_display_name):"
                    " %u items\n",
                    indent(level+1), apr_hash_count(cfg->sp_org_display_name));
    for (hash_item = apr_hash_first(r->pool, cfg->sp_org_display_name);
         hash_item;
         hash_item = apr_hash_next(hash_item)) {
        const char *lang;
        const char *value;

        apr_hash_this(hash_item, (void *)&lang, NULL, (void *)&value);
        apr_file_printf(diag_cfg->fd,
                        "%s(lang=%s): %s\n",
                        indent(level+2), lang, value);
    }

    apr_file_printf(diag_cfg->fd,
                    "%sMellonOrganizationURL (sp_org_url): %u items\n",
                    indent(level+1), apr_hash_count(cfg->sp_org_url));
    for (hash_item = apr_hash_first(r->pool, cfg->sp_org_url);
         hash_item;
         hash_item = apr_hash_next(hash_item)) {
        const char *lang;
        const char *value;

        apr_hash_this(hash_item, (void *)&lang, NULL, (void *)&value);
        apr_file_printf(diag_cfg->fd,
                        "%s(lang=%s): %s\n",
                        indent(level+2), lang, value);
    }

    apr_file_printf(diag_cfg->fd,
                    "%sMellonSessionLength (session_length): %d\n",
                    indent(level+1), cfg->session_length);
    apr_file_printf(diag_cfg->fd,
                    "%sMellonNoCookieErrorPage (no_cookie_error_page): %s\n",
                    indent(level+1), cfg->no_cookie_error_page);
    apr_file_printf(diag_cfg->fd,
                    "%sMellonNoSuccessErrorPage (no_success_error_page): %s\n",
                    indent(level+1), cfg->no_success_error_page);
    apr_file_printf(diag_cfg->fd,
                    "%sMellonDefaultLoginPath (login_path): %s\n",
                    indent(level+1), cfg->login_path);
    apr_file_printf(diag_cfg->fd,
                    "%sMellonDiscoveryURL (discovery_url): %s\n",
                    indent(level+1), cfg->discovery_url);
    apr_file_printf(diag_cfg->fd,
                    "%sMellonProbeDiscoveryTimeout (probe_discovery_timeout):"
                    " %d\n",
                    indent(level+1), cfg->probe_discovery_timeout);

    n_items = 0;
    apr_table_do(am_table_count, &n_items, cfg->probe_discovery_idp, NULL);
    apr_file_printf(diag_cfg->fd,
                    "%sMellonProbeDiscoveryIdP (probe_discovery_idp):"
                    " %d items\n",
                    indent(level+1), n_items);
    apr_table_do(log_probe_discovery_idp, &iter_data,
                 cfg->probe_discovery_idp, NULL);

    apr_file_printf(diag_cfg->fd,
                    "%sMellonAuthnContextClassRef (authn_context_class_ref):"
                    " %d items\n",
                    indent(level+1), cfg->authn_context_class_ref->nelts);
    for(i = 0; i < cfg->authn_context_class_ref->nelts; i++) {
        const char *context_class;

        context_class = APR_ARRAY_IDX(cfg->authn_context_class_ref, i, char *);
        apr_file_printf(diag_cfg->fd,
                        "%s[%2d]: %s\n",
                        indent(level+2), i, context_class);
    }

    apr_file_printf(diag_cfg->fd,
                    "%sMellonSubjectConfirmationDataAddressCheck"
                    " (subject_confirmation_data_address_check): %s\n",
                    indent(level+1),
                    CFG_VALUE(cfg, subject_confirmation_data_address_check) ? "On":"Off");

    apr_file_printf(diag_cfg->fd,
                    "%sMellonDoNotVerifyLogoutSignature"
                    " (do_not_verify_logout_signature): %u items\n",
                    indent(level+1),
                    apr_hash_count(cfg->do_not_verify_logout_signature));

    for (hash_item = apr_hash_first(r->pool,
                                    cfg->do_not_verify_logout_signature);
         hash_item;
         hash_item = apr_hash_next(hash_item)) {
        const char *entity_id;

        apr_hash_this(hash_item, (void *)&entity_id, NULL, NULL);

        apr_file_printf(diag_cfg->fd,
                        "%s%s\n",
                        indent(level+2), entity_id);
    }

    apr_file_printf(diag_cfg->fd,
                    "%sMellonSendCacheControlHeader"
                    " (send_cache_control_header): %s\n",
                    indent(level+1),
                    CFG_VALUE(cfg, send_cache_control_header) ? "On":"Off");
    apr_file_printf(diag_cfg->fd,
                    "%sMellonPostReplay (post_replay): %s\n",
                    indent(level+1), CFG_VALUE(cfg, post_replay) ? "On":"Off");
    apr_file_printf(diag_cfg->fd,
                    "%sMellonECPSendIDPList (ecp_send_idplist): %s\n",
                    indent(level+1), CFG_VALUE(cfg, ecp_send_idplist) ? "On":"Off");

    for (n_items = 0; cfg->redirect_domains[n_items] != NULL; n_items++);
    apr_file_printf(diag_cfg->fd,
                    "%sMellonRedirectDomains (redirect_domains): %d items\n",
                    indent(level+1), n_items);
    for (i = 0; cfg->redirect_domains[i] != NULL; i++) {
        apr_file_printf(diag_cfg->fd,
                        "%s%s\n",
                        indent(level+2), cfg->redirect_domains[i]);
    }

    apr_file_printf(diag_cfg->fd,
                    "%sMellonSignatureMethod (signature_method): %s\n",
                    indent(level+1),
                    am_diag_signature_method_str(r, CFG_VALUE(cfg, signature_method)));

    apr_file_flush(diag_cfg->fd);
}


static bool
am_diag_initialize_req(request_rec *r, am_diag_cfg_rec *diag_cfg,
                       am_req_cfg_rec *req_cfg)
{
    server_rec *s = r->server;
    am_dir_cfg_rec *dir_cfg;
    apr_os_thread_t tid = apr_os_thread_current();
    iter_callback_data iter_data;
    int level = 0;

    if (!diag_cfg) return false;
    if (!diag_cfg->fd) return false;
    if (!req_cfg) return false;

    if (req_cfg->diag_emitted) return true;

    iter_data.diag_fd = diag_cfg->fd;
    iter_data.level = level+1;

    apr_file_puts("---------------------------------- New Request"
                  " ---------------------------------\n", diag_cfg->fd);
    apr_file_printf(diag_cfg->fd, "%s - %s\n", r->method, r->uri);
    apr_file_printf(diag_cfg->fd, "log_id: %s\n", r->log_id);
    apr_file_printf(diag_cfg->fd, "server: scheme=%s hostname=%s port=%d\n",
                    s->server_scheme, s->server_hostname, s->port);
    apr_file_printf(diag_cfg->fd, "pid: %" APR_PID_T_FMT ", tid: %pT\n",
                    getpid(), &tid);
    apr_file_printf(diag_cfg->fd, "unparsed_uri: %s\n", r->unparsed_uri);
    apr_file_printf(diag_cfg->fd, "uri: %s\n", r->uri);
    apr_file_printf(diag_cfg->fd, "path_info: %s\n", r->path_info);
    apr_file_printf(diag_cfg->fd, "filename: %s\n", r->filename);
    apr_file_printf(diag_cfg->fd, "query args: %s\n", r->args);

    apr_file_printf(diag_cfg->fd, "Request Headers:\n");
    apr_table_do(log_headers, &iter_data, r->headers_in, NULL);

    req_cfg->diag_emitted = true;


    /* Only emit directory configuration once */
    if (!apr_table_get(diag_cfg->dir_cfg_emitted, r->uri)) {
        dir_cfg = am_get_dir_cfg(r);

        am_diag_log_dir_cfg(r, level, dir_cfg,
                            "Mellon Directory Configuration for URL: %s",
                            r->uri);
        apr_table_set(diag_cfg->dir_cfg_emitted, r->uri, "1");
    }
    return true;
}

/*=============================== Public API =================================*/

int
am_diag_log_init(apr_pool_t *pc, apr_pool_t *p, apr_pool_t *pt, server_rec *s)
{
    for ( ; s ; s = s->next) {
        if (!am_diag_open_log(s, p)) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return OK;
}

int
am_diag_finalize_request(request_rec *r)
{
    am_diag_cfg_rec *diag_cfg = am_get_diag_cfg(r->server);
    am_req_cfg_rec *req_cfg = am_get_req_cfg(r);
    int level = 0;
    iter_callback_data iter_data;

    if (!AM_DIAG_ENABLED(diag_cfg)) return OK;
    if (!req_cfg) return OK;

    if (!req_cfg->diag_emitted) return OK;

    iter_data.diag_fd = diag_cfg->fd;
    iter_data.level = level+1;

    apr_file_puts("\n=== Response ===\n", diag_cfg->fd);
    apr_file_printf(diag_cfg->fd,
                    "Status: %s(%d)\n",
                    r->status_line, r->status);
    apr_file_printf(diag_cfg->fd,
                    "user: %s auth_type=%s\n",
                    r->user, r->ap_auth_type);

    apr_file_printf(diag_cfg->fd,
                    "Response Headers:\n");
    apr_table_do(log_headers, &iter_data, r->headers_out, NULL);

    apr_file_printf(diag_cfg->fd,
                    "Response Error Headers:\n");
    apr_table_do(log_headers, &iter_data, r->err_headers_out, NULL);

    apr_file_printf(diag_cfg->fd,
                    "Environment:\n");
    apr_table_do(log_headers, &iter_data, r->subprocess_env, NULL);

    return OK;
}

char *
am_diag_time_t_to_8601(request_rec *r, apr_time_t t)
{
    char *buf;

    buf = apr_palloc(r->pool, ISO_8601_BUF_SIZE);
    if (!buf) return NULL;

    am_diag_time_t_to_8601_buf(buf, ISO_8601_BUF_SIZE, t);
    return buf;
}

const char *
am_diag_cond_str(request_rec *r, const am_cond_t *cond)
{
    return apr_psprintf(r->pool,
                        "varname=\"%s\" flags=%s str=\"%s\" directive=\"%s\"",
                        cond->varname, am_diag_cond_flag_str(r, cond->flags),
                        cond->str, cond->directive);
}

const char *
am_diag_cache_key_type_str(am_cache_key_t key_type)
{
    switch(key_type) {
    case AM_CACHE_SESSION: return "session";
    case AM_CACHE_NAMEID : return "name id";
    default:               return "unknown";
    }
}

const char *
am_diag_lasso_http_method_str(LassoHttpMethod http_method)
{
    switch(http_method) {
    case LASSO_HTTP_METHOD_NONE:          return "LASSO_HTTP_METHOD_NONE";
    case LASSO_HTTP_METHOD_ANY:           return "LASSO_HTTP_METHOD_ANY";
    case LASSO_HTTP_METHOD_IDP_INITIATED: return "LASSO_HTTP_METHOD_IDP_INITIATED";
    case LASSO_HTTP_METHOD_GET:           return "LASSO_HTTP_METHOD_GET";
    case LASSO_HTTP_METHOD_POST:          return "LASSO_HTTP_METHOD_POST";
    case LASSO_HTTP_METHOD_REDIRECT:      return "LASSO_HTTP_METHOD_REDIRECT";
    case LASSO_HTTP_METHOD_SOAP:          return "LASSO_HTTP_METHOD_SOAP";
    case LASSO_HTTP_METHOD_ARTIFACT_GET:  return "LASSO_HTTP_METHOD_ARTIFACT_GET";
    case LASSO_HTTP_METHOD_ARTIFACT_POST: return "LASSO_HTTP_METHOD_ARTIFACT_POST";
    case LASSO_HTTP_METHOD_PAOS:          return "LASSO_HTTP_METHOD_PAOS";
    default:                              return "unknown";
    }
}

void
am_diag_printf(request_rec *r, const char *fmt, ...)
{
    va_list ap;
    am_diag_cfg_rec *diag_cfg = am_get_diag_cfg(r->server);
    am_req_cfg_rec *req_cfg = am_get_req_cfg(r);
    char *buf;
    apr_size_t buf_len;

    if (!AM_DIAG_ENABLED(diag_cfg)) return;
    if (!am_diag_initialize_req(r, diag_cfg, req_cfg)) return;


    va_start(ap, fmt);
    buf = apr_pvsprintf(r->pool, fmt, ap);
    va_end(ap);
    buf_len = strlen(buf);
    if (buf_len > 0) {
        apr_file_write_full(diag_cfg->fd, buf, buf_len, NULL);
    }
    apr_file_flush(diag_cfg->fd);
}

void
am_diag_rerror(const char *file, int line, int module_index,
               int level, apr_status_t status,
               request_rec *r, const char *fmt, ...)
{
    va_list ap;
    am_diag_cfg_rec *diag_cfg = am_get_diag_cfg(r->server);
    am_req_cfg_rec *req_cfg = am_get_req_cfg(r);
    char *buf;

    if (!AM_DIAG_ENABLED(diag_cfg)) return;
    if (!am_diag_initialize_req(r, diag_cfg, req_cfg)) return;

    buf = apr_psprintf(r->pool, "[%s %s:%d] ",
                       am_diag_httpd_error_level_str(r, level), file, line);
    apr_file_puts(buf, diag_cfg->fd);

    va_start(ap, fmt);
    buf = apr_pvsprintf(r->pool, fmt, ap);
    va_end(ap);
    apr_file_puts(buf, diag_cfg->fd);

    apr_file_puts(APR_EOL_STR, diag_cfg->fd);
    apr_file_flush(diag_cfg->fd);
}

void
am_diag_log_lasso_node(request_rec *r, int level, LassoNode *node,
                       const char *fmt, ...)
{
    va_list ap;
    am_diag_cfg_rec *diag_cfg = am_get_diag_cfg(r->server);
    am_req_cfg_rec *req_cfg = am_get_req_cfg(r);
    gchar *xml = NULL;

    if (!AM_DIAG_ENABLED(diag_cfg)) return;
    if (!am_diag_initialize_req(r, diag_cfg, req_cfg)) return;

    va_start(ap, fmt);
    am_diag_format_line(r->pool, diag_cfg->fd, level, fmt, ap);
    va_end(ap);

    if (node) {
        xml = lasso_node_debug(node, 0);
        write_indented_text(diag_cfg->fd, level+1, xml);
        lasso_release_string(xml);
    } else {
        apr_file_printf(diag_cfg->fd,
                        "%snode is NULL\n",
                        indent(level+1));
    }
    apr_file_flush(diag_cfg->fd);
}

void
am_diag_log_file_data(request_rec *r, int level, am_file_data_t *file_data,
                      const char *fmt, ...)
{
    va_list ap;
    am_diag_cfg_rec *diag_cfg = am_get_diag_cfg(r->server);
    am_req_cfg_rec *req_cfg = am_get_req_cfg(r);

    if (!AM_DIAG_ENABLED(diag_cfg)) return;
    if (!am_diag_initialize_req(r, diag_cfg, req_cfg)) return;

    va_start(ap, fmt);
    am_diag_format_line(r->pool, diag_cfg->fd, level, fmt, ap);
    va_end(ap);

    if (file_data) {
        if (file_data->generated) {
            apr_file_printf(diag_cfg->fd,
                            "%sGenerated file contents:\n",
                            indent(level+1));
            write_indented_text(diag_cfg->fd,
                                level+2, file_data->contents);
        } else {
            apr_file_printf(diag_cfg->fd,
                            "%spathname: \"%s\"\n",
                            indent(level+1), file_data->path);
            if (!file_data->read_time) {
                am_file_read(file_data);
            }
            if (file_data->rv == APR_SUCCESS) {
                write_indented_text(diag_cfg->fd,
                                    level+2, file_data->contents);
            } else {
                apr_file_printf(diag_cfg->fd,
                                "%s%s\n",
                                indent(level+1), file_data->strerror);
            }
        }
    } else {
        apr_file_printf(diag_cfg->fd,
                        "%sfile_data: NULL\n",
                        indent(level+1));
    }

    apr_file_flush(diag_cfg->fd);
}

void
am_diag_log_saml_status_response(request_rec *r, int level, LassoNode *node,
                                 const char *fmt, ...)
{
    va_list ap;
    am_diag_cfg_rec *diag_cfg = am_get_diag_cfg(r->server);
    am_req_cfg_rec *req_cfg = am_get_req_cfg(r);

    LassoSamlp2StatusResponse *response = (LassoSamlp2StatusResponse*)node;
    LassoSamlp2Status *status = NULL;
    const char *status_code1 = NULL;
    const char *status_code2 = NULL;

    if (!AM_DIAG_ENABLED(diag_cfg)) return;
    if (!am_diag_initialize_req(r, diag_cfg, req_cfg)) return;

    va_start(ap, fmt);
    am_diag_format_line(r->pool, diag_cfg->fd, level, fmt, ap);
    va_end(ap);

    if (response == NULL) {
        apr_file_printf(diag_cfg->fd,
                        "%sresponse is NULL\n", indent(level+1));
        return;
    }


    if (!LASSO_IS_SAMLP2_STATUS_RESPONSE(response)) {
        apr_file_printf(diag_cfg->fd,
                        "%sERROR, expected LassoSamlp2StatusResponse "
                        "but got %s\n",
                        indent(level+1),
                        lasso_node_get_name((LassoNode*)response));
        return;
    }

    status = response->Status;
    if (status == NULL                  ||
        !LASSO_IS_SAMLP2_STATUS(status) ||
        status->StatusCode == NULL      ||
        status->StatusCode->Value == NULL) {
        apr_file_printf(diag_cfg->fd,
                        "%sStatus missing\n",
                        indent(level+1));
        return;
    }

    status_code1 = status->StatusCode->Value;
    if (status->StatusCode->StatusCode) {
        status_code2 = status->StatusCode->StatusCode->Value;
    }


    apr_file_printf(diag_cfg->fd,
                    "%sID: %s\n",
                    indent(level+1), response->ID);
    apr_file_printf(diag_cfg->fd,
                    "%sInResponseTo: %s\n",
                    indent(level+1), response->InResponseTo);
    apr_file_printf(diag_cfg->fd,
                    "%sVersion: %s\n",
                    indent(level+1), response->Version);
    apr_file_printf(diag_cfg->fd,
                    "%sIssueInstant: %s\n",
                    indent(level+1), response->IssueInstant);
    apr_file_printf(diag_cfg->fd,
                    "%sConsent: %s\n",
                    indent(level+1), response->Consent);
    apr_file_printf(diag_cfg->fd,
                    "%sIssuer: %s\n",
                    indent(level+1), response->Issuer->content);
    apr_file_printf(diag_cfg->fd,
                    "%sDestination: %s\n",
                    indent(level+1), response->Destination);

    apr_file_printf(diag_cfg->fd,
                    "%sStatus:\n", indent(level+1));
    apr_file_printf(diag_cfg->fd,
                    "%sTop Level Status code: %s\n",
                    indent(level+2), status_code1);
    apr_file_printf(diag_cfg->fd,
                    "%s2nd Level Status code: %s\n",
                    indent(level+2), status_code2);
    apr_file_printf(diag_cfg->fd,
                    "%sStatus Message: %s\n",
                    indent(level+2), status->StatusMessage);
    am_diag_log_lasso_node(r, level+2, (LassoNode*)status->StatusDetail,
                           "Status Detail:");

    return;

}

void
am_diag_log_profile(request_rec *r, int level, LassoProfile *profile,
                    const char *fmt, ...)
{
    va_list ap;
    am_diag_cfg_rec *diag_cfg = am_get_diag_cfg(r->server);
    am_req_cfg_rec *req_cfg = am_get_req_cfg(r);
    LassoSession *session = lasso_profile_get_session(profile);
    GList *assertions = lasso_session_get_assertions(session, NULL);
    GList *iter = NULL;
    int i;

    if (!AM_DIAG_ENABLED(diag_cfg)) return;
    if (!am_diag_initialize_req(r, diag_cfg, req_cfg)) return;

    va_start(ap, fmt);
    am_diag_format_line(r->pool, diag_cfg->fd, level, fmt, ap);
    va_end(ap);

    if (profile) {
        apr_file_printf(diag_cfg->fd,
                        "%sProfile Type: %s\n",
                        indent(level+1), G_OBJECT_TYPE_NAME(profile));

        for (iter = assertions, i=0;
             iter != NULL;
             iter = g_list_next(iter), i++) {
            LassoSaml2Assertion *assertion = NULL;

            assertion = LASSO_SAML2_ASSERTION(iter->data);
            if (!LASSO_IS_SAML2_ASSERTION(assertion)) {
                apr_file_printf(diag_cfg->fd,
                                "%sObject at index %d in session assertion"
                                " list is not LassoSaml2Assertion",
                                indent(level+1), i);
            } else {
                am_diag_log_lasso_node(r, level+1, &assertion->parent,
                                       "Assertion %d", i);
            }
        }
    } else {
        apr_file_printf(diag_cfg->fd,
                        "%sprofile is NULL\n",
                        indent(level+1));
    }

    apr_file_flush(diag_cfg->fd);
}

void
am_diag_log_cache_entry(request_rec *r, int level, am_cache_entry_t *entry,
                        const char *fmt, ...)
{
    va_list ap;
    am_diag_cfg_rec *diag_cfg = am_get_diag_cfg(r->server);
    am_req_cfg_rec *req_cfg = am_get_req_cfg(r);

    const char *name_id = NULL;

    if (!AM_DIAG_ENABLED(diag_cfg)) return;
    if (!am_diag_initialize_req(r, diag_cfg, req_cfg)) return;

    va_start(ap, fmt);
    am_diag_format_line(r->pool, diag_cfg->fd, level, fmt, ap);
    va_end(ap);

    if (entry) {
        name_id = am_cache_env_fetch_first(entry, "NAME_ID");

        apr_file_printf(diag_cfg->fd,
                        "%skey: %s\n",
                        indent(level+1), entry->key);
        apr_file_printf(diag_cfg->fd,
                        "%sname_id: %s\n",
                        indent(level+1), name_id);
        apr_file_printf(diag_cfg->fd,
                        "%sexpires: %s\n",
                        indent(level+1),
                        am_diag_time_t_to_8601(r, entry->expires));
        apr_file_printf(diag_cfg->fd,
                        "%saccess: %s\n",
                        indent(level+1),
                        am_diag_time_t_to_8601(r, entry->access));
        apr_file_printf(diag_cfg->fd,
                        "%slogged_in: %s\n",
                        indent(level+1), entry->logged_in ? "True" : "False");
    } else {
        apr_file_printf(diag_cfg->fd,
                        "%sentry is NULL\n",
                        indent(level+1));
    }
    apr_file_flush(diag_cfg->fd);
}


#endif /* ENABLE_DIAGNOSTICS */
