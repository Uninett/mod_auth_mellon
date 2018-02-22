/*
 *
 *   auth_mellon_handler.c: an authentication apache module
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

/*
 * Note:
 *
 * Information on PAOS ECP vs. Web SSO flow processing can be found in
 * the ECP.rst file.
 */


#ifdef HAVE_lasso_server_new_from_buffers
/* This function generates optional metadata for a given element
 *
 * Parameters:
 *  apr_pool_t *p        Pool to allocate memory from
 *  apr_hash_t *t        Hash of lang -> strings
 *  const char *e        Name of the element
 *
 * Returns:
 *  the metadata, or NULL if an error occured
 */
static char *am_optional_metadata_element(apr_pool_t *p,
                                          apr_hash_t *h,
                                          const char *e)
{
    apr_hash_index_t *index;
    char *data = "";

    for (index = apr_hash_first(p, h); index; index = apr_hash_next(index)) {
        char *lang;
        char *value;
        apr_ssize_t slen;
	char *xmllang = "";

        apr_hash_this(index, (const void **)&lang, &slen, (void *)&value);
        
        if (*lang != '\0')
            xmllang = apr_psprintf(p, " xml:lang=\"%s\"", lang);

        data = apr_psprintf(p, "%s<%s%s>%s</%s>",
                            data, e, xmllang, value, e);
    }

    return data;
}

/* This function generates optinal metadata
 *
 * Parameters:
 *  request_rec *r       The request we received.
 *
 * Returns:
 *  the metadata, or NULL if an error occured
 */
static char *am_optional_metadata(apr_pool_t *p, request_rec *r)
{
    am_dir_cfg_rec *cfg = am_get_dir_cfg(r);
    int count = 0;
    char *org_data = NULL;
    char *org_name = NULL;
    char *org_display_name = NULL;
    char *org_url = NULL;

    count += apr_hash_count(cfg->sp_org_name);
    count += apr_hash_count(cfg->sp_org_display_name);
    count += apr_hash_count(cfg->sp_org_url);

    if (count == 0) 
        return "";

    org_name = am_optional_metadata_element(p, cfg->sp_org_name,
                                            "OrganizationName");
    org_display_name = am_optional_metadata_element(p, cfg->sp_org_display_name,
                                                    "OrganizationDisplayName");
    org_url = am_optional_metadata_element(p, cfg->sp_org_url,
                                           "OrganizationURL");
    org_data = apr_psprintf(p, "<Organization>%s%s%s</Organization>",
                            org_name, org_display_name, org_url);

    return org_data;
}


/* This function generates metadata
 *
 * Parameters:
 *  request_rec *r       The request we received.
 *
 * Returns:
 *  the metadata, or NULL if an error occured
 */
static char *am_generate_metadata(apr_pool_t *p, request_rec *r)
{
    am_dir_cfg_rec *cfg = am_get_dir_cfg(r);
    char *url = am_get_endpoint_url(r);
    char *cert = "";
    const char *sp_entity_id;

    am_diag_printf(r, "Generating SP metadata\n");

    sp_entity_id = cfg->sp_entity_id ? cfg->sp_entity_id : url;

    if (cfg->sp_cert_file && cfg->sp_cert_file->contents) {
	char *sp_cert_file;
        char *cp;
        char *bp;
        const char *begin = "-----BEGIN CERTIFICATE-----";
        const char *end = "-----END CERTIFICATE-----";

        /* 
         * Try to remove leading and trailing garbage, as it can
         * wreak havoc XML parser if it contains [<>&]
         */
	sp_cert_file = apr_pstrdup(p, cfg->sp_cert_file->contents);

        cp = strstr(sp_cert_file, begin);
        if (cp != NULL) 
            sp_cert_file = cp + strlen(begin);

        cp = strstr(sp_cert_file, end);
        if (cp != NULL)
            *cp = '\0';
        
	/* 
	 * And remove any non printing char (CR, spaces...)
	 */
	bp = sp_cert_file;
	for (cp = sp_cert_file; *cp; cp++) {
		if (apr_isgraph(*cp))
			*bp++ = *cp;
	}
	*bp = '\0';

        cert = apr_psprintf(p,
          "<KeyDescriptor use=\"signing\">"
            "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
              "<ds:X509Data>"
                "<ds:X509Certificate>%s</ds:X509Certificate>"
              "</ds:X509Data>"
            "</ds:KeyInfo>"
          "</KeyDescriptor>"
          "<KeyDescriptor use=\"encryption\">"
            "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
              "<ds:X509Data>"
                "<ds:X509Certificate>%s</ds:X509Certificate>"
              "</ds:X509Data>"
            "</ds:KeyInfo>"
          "</KeyDescriptor>",
          sp_cert_file,
          sp_cert_file);
    }

    return apr_psprintf(p,
      "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
<EntityDescriptor\n\
 entityID=\"%s%s\"\n\
 xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\">\n\
 <SPSSODescriptor\n\
   AuthnRequestsSigned=\"true\"\n\
   WantAssertionsSigned=\"true\"\n\
   protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n\
   %s\
   <SingleLogoutService\n\
     Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:SOAP\"\n\
     Location=\"%slogout\" />\n\
   <SingleLogoutService\n\
     Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\"\n\
     Location=\"%slogout\" />\n\
   <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>\n\
   <AssertionConsumerService\n\
     index=\"0\"\n\
     isDefault=\"true\"\n\
     Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"\n\
     Location=\"%spostResponse\" />\n\
   <AssertionConsumerService\n\
     index=\"1\"\n\
     Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\"\n\
     Location=\"%sartifactResponse\" />\n\
   <AssertionConsumerService\n\
     index=\"2\"\n\
     Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:PAOS\"\n\
     Location=\"%spaosResponse\" />\n\
 </SPSSODescriptor>\n\
 %s\n\
</EntityDescriptor>",
      sp_entity_id, cfg->sp_entity_id ? "" : "metadata", 
      cert, url, url, url, url, url, am_optional_metadata(p, r));
}
#endif /* HAVE_lasso_server_new_from_buffers */


/*
 * This function loads all IdP metadata in a lasso server
 *
 * Parameters:
 *  am_dir_cfg_rec *cfg  The server configuration.
 *  request_rec *r       The request we received.
 *
 * Returns:
 *  number of loaded providers
 */
static guint am_server_add_providers(am_dir_cfg_rec *cfg, request_rec *r)
{
    apr_size_t index;

#ifndef HAVE_lasso_server_load_metadata
    const char *idp_public_key_file;

    if (cfg->idp_metadata->nelts == 1)
        idp_public_key_file = cfg->idp_public_key_file ?
            cfg->idp_public_key_file->path : NULL;
    else
        idp_public_key_file = NULL;
#endif /* ! HAVE_lasso_server_load_metadata */

    if (cfg->idp_metadata->nelts == 0) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Error, URI \"%s\" has no IdP's defined", r->uri);
            return 0;
    }

    for (index = 0; index < cfg->idp_metadata->nelts; index++) {
        const am_metadata_t *idp_metadata;
        int error;
#ifdef HAVE_lasso_server_load_metadata
        GList *loaded_idp = NULL;
#endif /* HAVE_lasso_server_load_metadata */

        idp_metadata = &( ((const am_metadata_t*)cfg->idp_metadata->elts) [index] );

        am_diag_log_file_data(r, 0, idp_metadata->metadata,
                              "Loading IdP Metadata");
        if (idp_metadata->chain) {
            am_diag_log_file_data(r, 0, idp_metadata->chain,
                                  "Loading IdP metadata chain");
        }

#ifdef HAVE_lasso_server_load_metadata
        error = lasso_server_load_metadata(cfg->server,
                                           LASSO_PROVIDER_ROLE_IDP,
                                           idp_metadata->metadata->path,
                                           idp_metadata->chain ?
                                           idp_metadata->chain->path : NULL,
                                           cfg->idp_ignore,
                                           &loaded_idp,
                                           LASSO_SERVER_LOAD_METADATA_FLAG_DEFAULT);
        if (error == 0) {
            GList *idx;

            for (idx = loaded_idp; idx != NULL; idx = idx->next) {
                 AM_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r,
                               "loaded IdP \"%s\" from \"%s\".",
                               (char *)idx->data, idp_metadata->metadata->path);
            }
        }

        if (loaded_idp != NULL) {
            for (GList *idx = loaded_idp; idx != NULL; idx = idx->next) {
                g_free(idx->data);
            }
            g_list_free(loaded_idp);
        }

#else /* HAVE_lasso_server_load_metadata */
        error = lasso_server_add_provider(cfg->server,
                                          LASSO_PROVIDER_ROLE_IDP,
                                          idp_metadata->metadata->path,
                                          idp_public_key_file,
                                          cfg->idp_ca_file ?
                                          cfg->idp_ca_file->path : NULL);
#endif /* HAVE_lasso_server_load_metadata */

        if (error != 0) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Error adding metadata \"%s\" to "
                          "lasso server objects. Lasso error: [%i] %s",
                          idp_metadata->metadata->path, error, lasso_strerror(error));
        }
    }

    return g_hash_table_size(cfg->server->providers);
}


static LassoServer *am_get_lasso_server(request_rec *r)
{
    am_dir_cfg_rec *cfg = am_get_dir_cfg(r);

    cfg = cfg->inherit_server_from;

    apr_thread_mutex_lock(cfg->server_mutex);
    if(cfg->server == NULL) {
        if(cfg->sp_metadata_file == NULL) {

#ifdef HAVE_lasso_server_new_from_buffers
            /*
             * Try to generate missing metadata
             */
            apr_pool_t *pool = r->server->process->pconf;
            cfg->sp_metadata_file = am_file_data_new(pool, NULL);
            cfg->sp_metadata_file->rv = APR_SUCCESS;
            cfg->sp_metadata_file->generated = true;
            cfg->sp_metadata_file->contents = am_generate_metadata(pool, r);
#else
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Missing MellonSPMetadataFile option.");
            apr_thread_mutex_unlock(cfg->server_mutex);
            return NULL;
#endif /* HAVE_lasso_server_new_from_buffers */
        }

#ifdef HAVE_lasso_server_new_from_buffers
        cfg->server = lasso_server_new_from_buffers(cfg->sp_metadata_file->contents,
                                                    cfg->sp_private_key_file ?
                                                    cfg->sp_private_key_file->contents : NULL,
                                                    NULL,
                                                    cfg->sp_cert_file ?
                                                    cfg->sp_cert_file->contents : NULL);
#else
        cfg->server = lasso_server_new(cfg->sp_metadata_file->path,
                                       cfg->sp_private_key_file ?
                                       cfg->sp_private_key_file->path : NULL,
                                       NULL,
                                       cfg->sp_cert_file ?
                                       cfg->sp_cert_file->path : NULL);
#endif
        if (cfg->server == NULL) {
	    AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
			  "Error initializing lasso server object. Please"
			  " verify the following configuration directives:"
			  " MellonSPMetadataFile and MellonSPPrivateKeyFile.");

	    apr_thread_mutex_unlock(cfg->server_mutex);
	    return NULL;
	}

        if (am_server_add_providers(cfg, r) == 0) {
	    AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
			  "Error adding IdP to lasso server object. Please"
			  " verify the following configuration directives:"
			  " MellonIdPMetadataFile and"
                          " MellonIdPPublicKeyFile.");

	    lasso_server_destroy(cfg->server);
	    cfg->server = NULL;

	    apr_thread_mutex_unlock(cfg->server_mutex);
	    return NULL;
	}

        cfg->server->signature_method = CFG_VALUE(cfg, signature_method);
    }

    apr_thread_mutex_unlock(cfg->server_mutex);

    return cfg->server;
}


/* Redirect to discovery service.
 *
 * Parameters:
 *  request_rec *r         The request we received.
 *  const char *return_to  The URL the user should be returned to after login.
 *
 * Returns:
 *  HTTP_SEE_OTHER on success, an error otherwise.
 */
static int am_start_disco(request_rec *r, const char *return_to)
{
    am_dir_cfg_rec *cfg = am_get_dir_cfg(r);
    const char *endpoint = am_get_endpoint_url(r);
    LassoServer *server;
    const char *sp_entity_id;
    const char *sep;
    const char *login_url;
    const char *discovery_url;

    server = am_get_lasso_server(r);
    if(server == NULL) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    sp_entity_id = LASSO_PROVIDER(server)->ProviderID;

    login_url = apr_psprintf(r->pool, "%slogin?ReturnTo=%s",
                             endpoint,
                             am_urlencode(r->pool, return_to));
    AM_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "login_url = %s", login_url);

    /* If discovery URL already has a ? we append a & */
    sep = (strchr(cfg->discovery_url, '?')) ? "&" : "?";

    discovery_url = apr_psprintf(r->pool, "%s%sentityID=%s&"
                                 "return=%s&returnIDParam=IdP",
                                 cfg->discovery_url, sep,
                                 am_urlencode(r->pool, sp_entity_id),
                                 am_urlencode(r->pool, login_url));

    AM_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "discovery_url = %s", discovery_url);
    apr_table_setn(r->headers_out, "Location", discovery_url);
    return HTTP_SEE_OTHER;
}


/* This function returns the first configured IdP
 *
 * Parameters:
 *  request_rec *r       The request we received.
 *
 * Returns:
 *  the providerID, or NULL if an error occured
 */
static const char *am_first_idp(request_rec *r)
{
    LassoServer *server;
    GList *idp_list;
    const char *idp_providerid;

    server = am_get_lasso_server(r);
    if (server == NULL)
        return NULL;

    idp_list = g_hash_table_get_keys(server->providers);
    if (idp_list == NULL)
      return NULL;

    idp_providerid = idp_list->data;

    g_list_free(idp_list);

    return idp_providerid;
}


/* This function selects an IdP and returns its provider_id
 *
 * Parameters:
 *  request_rec *r       The request we received.
 *
 * Returns:
 *  the provider_id, or NULL if an error occured
 */
static const char *am_get_idp(request_rec *r)
{
    LassoServer *server;
    const char *idp_provider_id;

    server = am_get_lasso_server(r);
    if (server == NULL)
        return NULL;

    /*
     * If we have a single IdP, return that one.
     */
    if (g_hash_table_size(server->providers) == 1)
        return am_first_idp(r);

    /*
     * If IdP discovery handed us an IdP, try to use it.
     */
    idp_provider_id = am_extract_query_parameter(r->pool, r->args, "IdP");
    if (idp_provider_id != NULL) {
        int rc;

        rc = am_urldecode((char *)idp_provider_id);
        if (rc != OK) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, rc, r,
                          "Could not urldecode IdP discovery value.");
            idp_provider_id = NULL;
        } else {
            if (g_hash_table_lookup(server->providers, idp_provider_id) == NULL)
                idp_provider_id = NULL;
        }

        /*
         * If we do not know about it, fall back to default.
         */
        if (idp_provider_id == NULL) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_WARNING, 0, r,
                          "IdP discovery returned unknown or inexistant IdP");
            idp_provider_id = am_first_idp(r);
        }

        return idp_provider_id;
    }

    /*
     * No IdP answered, use default
     * Perhaps we should redirect to an error page instead.
     */
    return am_first_idp(r);
}


/* This function stores dumps of the LassoIdentity and LassoSession objects
 * for the given LassoProfile object. The dumps are stored in the session
 * belonging to the current request.
 *
 * Parameters:
 *  request_rec *r             The current request.
 *  am_cache_entry_t *session  The session we are creating.
 *  LassoProfile *profile      The profile object.
 *  char *saml_response        The full SAML 2.0 response message.
 *
 * Returns:
 *  OK on success or HTTP_INTERNAL_SERVER_ERROR on failure.
 */
static int am_save_lasso_profile_state(request_rec *r,
                                       am_cache_entry_t *session,
                                       LassoProfile *profile,
                                       char *saml_response)
{
    LassoIdentity *lasso_identity;
    LassoSession *lasso_session;
    gchar *identity_dump;
    gchar *session_dump;
    int ret;

    lasso_identity = lasso_profile_get_identity(profile);
    if(lasso_identity == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "The current LassoProfile object doesn't contain a"
                      " LassoIdentity object.");
        identity_dump = NULL;
    } else {
        identity_dump = lasso_identity_dump(lasso_identity);
        if(identity_dump == NULL) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Could not create a identity dump from the"
                          " LassoIdentity object.");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    lasso_session = lasso_profile_get_session(profile);
    if(lasso_session == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "The current LassoProfile object doesn't contain a"
                      " LassoSession object.");
        session_dump = NULL;
    } else {
        session_dump = lasso_session_dump(lasso_session);
        if(session_dump == NULL) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Could not create a session dump from the"
                          " LassoSession object.");
            if(identity_dump != NULL) {
                g_free(identity_dump);
            }
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }


    /* Save the profile state. */
    ret = am_cache_set_lasso_state(session,
                                   identity_dump,
                                   session_dump,
                                   saml_response);

    if(identity_dump != NULL) {
        g_free(identity_dump);
    }

    if(session_dump != NULL) {
        g_free(session_dump);
    }

    return ret;
}


/* Returns a SAML response
 *
 * Parameters:
 *  request_rec *r         The current request.
 *  LassoProfile *profile  The profile object.
 *
 * Returns:
 *  HTTP_INTERNAL_SERVER_ERROR if an error occurs, HTTP_SEE_OTHER for the
 *  Redirect binding and OK for the SOAP binding.
 */
static int am_return_logout_response(request_rec *r,
                              LassoProfile *profile)
{
    if (profile->msg_url && profile->msg_body) {
        /* POST binding response */
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error building logout response message."
                      " POST binding is unsupported.");
        return HTTP_INTERNAL_SERVER_ERROR;
    } else if (profile->msg_url) {
        /* HTTP-Redirect binding response */
        apr_table_setn(r->headers_out, "Location",
                       apr_pstrdup(r->pool, profile->msg_url));
        return HTTP_SEE_OTHER;
    } else if (profile->msg_body) {
        /* SOAP binding response */
        ap_set_content_type(r, "text/xml");
        ap_rputs(profile->msg_body, r);
        return OK;
    } else {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error building logout response message."
                      " There is no content to return.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
}


/* This function restores dumps of a LassoIdentity object and a LassoSession
 * object. The dumps are fetched from the session belonging to the current
 * request and restored to the given LassoProfile object.
 *
 * Parameters:
 *  request_rec *r         The current request.
 *  LassoProfile *profile  The profile object.
 *  am_cache_entry_t *am_session The session structure.
 *
 * Returns:
 *  OK on success or HTTP_INTERNAL_SERVER_ERROR on failure.
 */
static void am_restore_lasso_profile_state(request_rec *r, 
                                           LassoProfile *profile,
                                           am_cache_entry_t *am_session)
{
    const char *identity_dump;
    const char *session_dump;
    int rc;


    if(am_session == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Could not get auth_mellon session while attempting"
                      " to restore the lasso profile state.");
        return;
    }

    identity_dump = am_cache_get_lasso_identity(am_session);
    if(identity_dump != NULL) {
        rc = lasso_profile_set_identity_from_dump(profile, identity_dump);
        if(rc != 0) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Could not restore identity from dump."
                          " Lasso error: [%i] %s", rc, lasso_strerror(rc));
            am_release_request_session(r, am_session);
        }
    }

    session_dump = am_cache_get_lasso_session(am_session);
    if(session_dump != NULL) {
        rc = lasso_profile_set_session_from_dump(profile, session_dump);
        if(rc != 0) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Could not restore session from dump."
                          " Lasso error: [%i] %s", rc, lasso_strerror(rc));
            am_release_request_session(r, am_session);
        }
    }
    am_diag_log_cache_entry(r, 0, am_session, "%s: Session Cache Entry", __func__);

    am_diag_log_profile(r, 0, profile,  "%s: Restored Profile", __func__);
}

/* This function handles an IdP initiated logout request.
 *
 * Parameters:
 *  request_rec *r       The logout request.
 *  LassoLogout *logout  A LassoLogout object initiated with
 *                       the current session.
 *
 * Returns:
 *  OK on success, or an error if any of the steps fail.
 */
static int am_handle_logout_request(request_rec *r, 
                                    LassoLogout *logout, char *msg)
{
    gint res = 0, rc = HTTP_OK;
    am_cache_entry_t *session = NULL;
    am_dir_cfg_rec *cfg = am_get_dir_cfg(r);

    am_diag_printf(r, "enter function %s\n", __func__);

    /* Process the logout message. Ignore missing signature. */
    res = lasso_logout_process_request_msg(logout, msg);
#ifdef HAVE_lasso_profile_set_signature_verify_hint
    if(res != 0 && res != LASSO_DS_ERROR_SIGNATURE_NOT_FOUND &&
       logout->parent.remote_providerID != NULL) {
        if (apr_hash_get(cfg->do_not_verify_logout_signature,
                         logout->parent.remote_providerID,
                         APR_HASH_KEY_STRING)) {
            lasso_profile_set_signature_verify_hint(&logout->parent,
                LASSO_PROFILE_SIGNATURE_VERIFY_HINT_IGNORE);
            res = lasso_logout_process_request_msg(logout, msg);
        }
    }
#endif
    if(res != 0 && res != LASSO_DS_ERROR_SIGNATURE_NOT_FOUND) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error processing logout request message."
                      " Lasso error: [%i] %s", res, lasso_strerror(res));

        rc = HTTP_BAD_REQUEST;
        goto exit;
    }

    /* Search session using NameID */
    if (! LASSO_IS_SAML2_NAME_ID(logout->parent.nameIdentifier)) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error processing logout request message."
                      " No NameID found");
        rc = HTTP_BAD_REQUEST;
        goto exit;
    }

    am_diag_printf(r, "%s name id %s\n", __func__,
                   ((LassoSaml2NameID*)logout->parent.nameIdentifier)->content);

    session = am_get_request_session_by_nameid(r,
                    ((LassoSaml2NameID*)logout->parent.nameIdentifier)->content);
    if (session == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error processing logout request message."
                      " No session found for NameID %s",
                      ((LassoSaml2NameID*)logout->parent.nameIdentifier)->content);

    }

    am_diag_log_cache_entry(r, 0, session, "%s", __func__);

    if (session == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error processing logout request message."
                      " No session found.");

    } else {
        am_restore_lasso_profile_state(r, &logout->parent, session);
    }

    /* Validate the logout message. Ignore missing signature. */
    res = lasso_logout_validate_request(logout);
    if(res != 0 && 
       res != LASSO_DS_ERROR_SIGNATURE_NOT_FOUND &&
       res != LASSO_PROFILE_ERROR_SESSION_NOT_FOUND) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_WARNING, 0, r,
                      "Error validating logout request."
                      " Lasso error: [%i] %s", res, lasso_strerror(res));
        rc = HTTP_INTERNAL_SERVER_ERROR;
        goto exit;
    }
    /* We continue with the logout despite those errors. They could be
     * caused by the IdP believing that we are logged in when we are not.
     */

    if (session != NULL && res != LASSO_PROFILE_ERROR_SESSION_NOT_FOUND) {
        /* We found a matching session -- delete it. */
        am_delete_request_session(r, session);
        session = NULL;
    }

    /* Create response message. */
    res = lasso_logout_build_response_msg(logout);
    if(res != 0) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error building logout response message."
                      " Lasso error: [%i] %s", res, lasso_strerror(res));

        rc = HTTP_INTERNAL_SERVER_ERROR;
        goto exit;
    }
    rc = am_return_logout_response(r, &logout->parent);

exit:
    if (session != NULL) {
        am_release_request_session(r, session);
    }

    lasso_logout_destroy(logout);
    return rc;
}


/* This function handles a logout response message from the IdP. We get
 * this message after we have sent a logout request to the IdP.
 *
 * Parameters:
 *  request_rec *r       The logout response request.
 *  LassoLogout *logout  A LassoLogout object initiated with
 *                       the current session.
 *
 * Returns:
 *  OK on success, or an error if any of the steps fail.
 */
static int am_handle_logout_response(request_rec *r, LassoLogout *logout)
{
    gint res;
    int rc;
    am_cache_entry_t *session;
    char *return_to;
    am_dir_cfg_rec *cfg = am_get_dir_cfg(r);

    res = lasso_logout_process_response_msg(logout, r->args);
    am_diag_log_lasso_node(r, 0, LASSO_PROFILE(logout)->response,
                           "SAML Response (%s):", __func__);
#ifdef HAVE_lasso_profile_set_signature_verify_hint
    if(res != 0 && res != LASSO_DS_ERROR_SIGNATURE_NOT_FOUND &&
       logout->parent.remote_providerID != NULL) {
        if (apr_hash_get(cfg->do_not_verify_logout_signature,
                         logout->parent.remote_providerID,
                         APR_HASH_KEY_STRING)) {
            lasso_profile_set_signature_verify_hint(&logout->parent,
                LASSO_PROFILE_SIGNATURE_VERIFY_HINT_IGNORE);
            res = lasso_logout_process_response_msg(logout, r->args);
        }
    }
#endif
    if(res != 0) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Unable to process logout response."
                      " Lasso error: [%i] %s, SAML Response: %s",
                      res, lasso_strerror(res),
                      am_saml_response_status_str(r,
                        LASSO_PROFILE(logout)->response));

        lasso_logout_destroy(logout);
        return HTTP_BAD_REQUEST;
    }

    lasso_logout_destroy(logout);

    /* Delete the session. */
    session = am_get_request_session(r);

    am_diag_log_cache_entry(r, 0, session, "%s\n", __func__);

    if(session != NULL) {
        am_delete_request_session(r, session);
    }

    return_to = am_extract_query_parameter(r->pool, r->args, "RelayState");
    if(return_to == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "No RelayState parameter to logout response handler."
                      " It is possible that your IdP doesn't support the"
                      " RelayState parameter.");
        return HTTP_BAD_REQUEST;
    }

    rc = am_urldecode(return_to);
    if(rc != OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, rc, r,
                      "Could not urldecode RelayState value in logout"
                      " response.");
        return HTTP_BAD_REQUEST;
    }

    /* Check for bad characters in RelayState. */
    rc = am_check_url(r, return_to);
    if (rc != OK) {
        return rc;
    }

    /* Make sure that it is a valid redirect URL. */
    rc = am_validate_redirect_url(r, return_to);
    if (rc != OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Invalid target domain in logout response RelayState parameter.");
        return rc;
    }

    apr_table_setn(r->headers_out, "Location", return_to);
    return HTTP_SEE_OTHER;
}


/* This function initiates a logout request and sends it to the IdP.
 *
 * Parameters:
 *  request_rec *r       The logout response request.
 *  LassoLogout *logout  A LassoLogout object initiated with
 *                       the current session.
 *
 * Returns:
 *  OK on success, or an error if any of the steps fail.
 */
static int am_init_logout_request(request_rec *r, LassoLogout *logout)
{
    char *return_to;
    int rc;
    am_cache_entry_t *mellon_session;
    gint res;
    char *redirect_to;
    LassoProfile *profile;
    LassoSession *session;
    GList *assertion_list;
    LassoNode *assertion_n;
    LassoSaml2Assertion *assertion;
    LassoSaml2AuthnStatement *authnStatement;
    LassoSamlp2LogoutRequest *request;

    return_to = am_extract_query_parameter(r->pool, r->args, "ReturnTo");
    rc = am_urldecode(return_to);
    if (rc != OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, rc, r,
                      "Could not urldecode ReturnTo value.");
        return HTTP_BAD_REQUEST;
    }

    rc = am_validate_redirect_url(r, return_to);
    if (rc != OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Invalid target domain in logout request ReturnTo parameter.");
        return rc;
    }

    /* Disable the the local session (in case the IdP doesn't respond). */
    mellon_session = am_get_request_session(r);
    if(mellon_session != NULL) {
        am_restore_lasso_profile_state(r, &logout->parent, mellon_session);
        mellon_session->logged_in = 0;
        am_release_request_session(r, mellon_session);
    }

    /* Create the logout request message. */
    res = lasso_logout_init_request(logout, NULL, LASSO_HTTP_METHOD_REDIRECT);
    /* Early non failing return. */
    if (res != 0) {
        if(res == LASSO_PROFILE_ERROR_SESSION_NOT_FOUND) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_WARNING, 0, r,
                          "User attempted to initiate logout without being"
                          " loggged in.");
        } else if (res == LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE || res == LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_WARNING, 0, r, "Current identity provider "
                            "does not support single logout. Destroying local session only.");

        } else if(res != 0) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Unable to create logout request."
                          " Lasso error: [%i] %s", res, lasso_strerror(res));

            lasso_logout_destroy(logout);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        lasso_logout_destroy(logout);
        /* Check for bad characters in ReturnTo. */
        rc = am_check_url(r, return_to);
        if (rc != OK) {
            return rc;
        }
        /* Redirect to the page the user should be sent to after logout. */
        apr_table_setn(r->headers_out, "Location", return_to);
        return HTTP_SEE_OTHER;
    }

    profile = LASSO_PROFILE(logout);

    /* We need to set the SessionIndex in the LogoutRequest to the SessionIndex
     * we received during the login operation. This is not needed since release
     * 2.3.0.
     */
    if (lasso_check_version(2, 3, 0, LASSO_CHECK_VERSION_NUMERIC) == 0) {
        session = lasso_profile_get_session(profile);
        assertion_list = lasso_session_get_assertions(
            session, profile->remote_providerID);
        if(! assertion_list ||
                        LASSO_IS_SAML2_ASSERTION(assertion_list->data) == FALSE) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "No assertions found for the current session.");
            lasso_logout_destroy(logout);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        /* We currently only look at the first assertion in the list
         * lasso_session_get_assertions returns.
         */
        assertion_n = assertion_list->data;

        assertion = LASSO_SAML2_ASSERTION(assertion_n);

        /* We assume that the first authnStatement contains the data we want. */
        authnStatement = LASSO_SAML2_AUTHN_STATEMENT(assertion->AuthnStatement->data);

        if(!authnStatement) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "No AuthnStatement found in the current assertion.");
            lasso_logout_destroy(logout);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        if(authnStatement->SessionIndex) {
            request = LASSO_SAMLP2_LOGOUT_REQUEST(profile->request);
            request->SessionIndex = g_strdup(authnStatement->SessionIndex);
        }
    }


    /* Set the RelayState parameter to the return url (if we have one). */
    if(return_to) {
        profile->msg_relayState = g_strdup(return_to);
    }

    /* Serialize the request message into a url which we can redirect to. */
    res = lasso_logout_build_request_msg(logout);
    if(res != 0) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Unable to serialize lasso logout message."
                      " Lasso error: [%i] %s", res, lasso_strerror(res));

        lasso_logout_destroy(logout);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Set the redirect url. */
    redirect_to = apr_pstrdup(r->pool, LASSO_PROFILE(logout)->msg_url);

    /* Check if the lasso library added the RelayState. If lasso didn't add
     * a RelayState parameter, then we add one ourself. This should hopefully
     * be removed in the future.
     */
    if(return_to != NULL
       && strstr(redirect_to, "&RelayState=") == NULL
       && strstr(redirect_to, "?RelayState=") == NULL) {
        /* The url didn't contain the relaystate parameter. */
        redirect_to = apr_pstrcat(
            r->pool, redirect_to, "&RelayState=",
            am_urlencode(r->pool, return_to),
            NULL
            );
    }

    apr_table_setn(r->headers_out, "Location", redirect_to);

    lasso_logout_destroy(logout);

    /* Redirect (without including POST data if this was a POST request. */
    return HTTP_SEE_OTHER;
}


/* This function handles requests to the logout handler.
 *
 * Parameters:
 *  request_rec *r       The request.
 *
 * Returns:
 *  OK on success, or an error if any of the steps fail.
 */
static int am_handle_logout(request_rec *r)
{
    LassoServer *server;
    LassoLogout *logout;

    server = am_get_lasso_server(r);
    if(server == NULL) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    logout = lasso_logout_new(server);
    if(logout == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error creating lasso logout object.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Check which type of request to the logout handler this is.
     * We have three types:
     * - logout requests: The IdP sends a logout request to this service.
     *                    it can be either through HTTP-Redirect or SOAP.
     * - logout responses: We have sent a logout request to the IdP, and
     *   are receiving a response.
     * - We want to initiate a logout request.
     */

    /* First check for IdP-initiated SOAP logout request */
    if ((r->args == NULL) && (r->method_number == M_POST)) {
        int rc;
        char *post_data;

        rc = am_read_post_data(r, &post_data, NULL);
        if (rc != OK) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, rc, r,
                          "Error reading POST data.");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        return am_handle_logout_request(r, logout, post_data);

    } else if(am_extract_query_parameter(r->pool, r->args, 
                                         "SAMLRequest") != NULL) {
        /* SAMLRequest - logout request from the IdP. */
        return am_handle_logout_request(r, logout, r->args);

    } else if(am_extract_query_parameter(r->pool, r->args, 
                                         "SAMLResponse") != NULL) {
        /* SAMLResponse - logout response from the IdP. */
        return am_handle_logout_response(r, logout);

    } else if(am_extract_query_parameter(r->pool, r->args, 
                                         "ReturnTo") != NULL) {
        /* RedirectTo - SP initiated logout. */
        return am_init_logout_request(r, logout);

    } else {
        /* Unknown request to the logout handler. */
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "No known parameters passed to the logout"
                      " handler. Query string was \"%s\". To initiate"
                      " a logout, you need to pass a \"ReturnTo\""
                      " parameter with a url to the web page the user should"
                      " be redirected to after a successful logout.",
                      r->args);
        return HTTP_BAD_REQUEST;
    }
}


/* This function parses a timestamp for a SAML 2.0 condition.
 *
 * Parameters:
 *  request_rec *r          The current request. Used for logging of errors.
 *  const char *timestamp   The timestamp we should parse. Must be on
 *                          the following format: "YYYY-MM-DDThh:mm:ssZ"
 *
 * Returns:
 *  An apr_time_t value with the timestamp, or 0 on error.
 */
static apr_time_t am_parse_timestamp(request_rec *r, const char *timestamp)
{
    size_t len;
    int i;
    char c;
    const char *expected;
    apr_time_exp_t time_exp;
    apr_time_t res;
    apr_status_t rc;

    len = strlen(timestamp);

    /* Verify length of timestamp. */
    if(len < 20){
        AM_LOG_RERROR(APLOG_MARK, APLOG_WARNING, 0, r,
                      "Invalid length of timestamp: \"%s\".", timestamp);
    }

    /* Verify components of timestamp. */
    for(i = 0; i < len - 1; i++) {
        c = timestamp[i];

        expected = NULL;

        switch(i) {

        case 4:
        case 7:
            /* Matches "    -  -            " */
            if(c != '-') {
                expected = "'-'";
            }
            break;

        case 10:
            /* Matches "          T         " */
            if(c != 'T') {
                expected = "'T'";
            }
            break;

        case 13:
        case 16:
            /* Matches "             :  :   " */
            if(c != ':') {
                expected = "':'";
            }
            break;

        case 19:
            /* Matches "                   ." */
            if (c != '.') {
                expected = "'.'";
            }
            break;

        default:
            /* Matches "YYYY MM DD hh mm ss uuuuuu" */
            if(c < '0' || c > '9') {
                expected = "a digit";
            }
            break;
        }

        if(expected != NULL) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Invalid character in timestamp at position %i."
                          " Expected %s, got '%c'. Full timestamp: \"%s\"",
                          i, expected, c, timestamp);
            return 0;
        }
    }

    if (timestamp[len - 1] != 'Z') {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Timestamp wasn't in UTC (did not end with 'Z')."
                      " Full timestamp: \"%s\"",
                      timestamp);
        return 0;
    }


    time_exp.tm_usec = 0;
    if (len > 20) {
        /* Subsecond precision. */
        if (len > 27) {
            /* Timestamp has more than microsecond precision. Just clip it to
             * microseconds.
             */
            len = 27;
        }
        len -= 1; /* Drop the 'Z' off the end. */
        for (i = 20; i < len; i++) {
            time_exp.tm_usec = time_exp.tm_usec * 10 + timestamp[i] - '0';
        }
        for (i = len; i < 26; i++) {
            time_exp.tm_usec *= 10;
        }
    }

    time_exp.tm_sec = (timestamp[17] - '0') * 10 + (timestamp[18] - '0');
    time_exp.tm_min = (timestamp[14] - '0') * 10 + (timestamp[15] - '0');
    time_exp.tm_hour = (timestamp[11] - '0') * 10 + (timestamp[12] - '0');
    time_exp.tm_mday = (timestamp[8] - '0') * 10 + (timestamp[9] - '0');
    time_exp.tm_mon = (timestamp[5] - '0') * 10 + (timestamp[6] - '0') - 1;
    time_exp.tm_year = (timestamp[0] - '0') * 1000 +
        (timestamp[1] - '0') * 100 + (timestamp[2] - '0') * 10 +
        (timestamp[3] - '0') - 1900;

    time_exp.tm_wday = 0; /* Unknown. */
    time_exp.tm_yday = 0; /* Unknown. */

    time_exp.tm_isdst = 0; /* UTC, no daylight savings time. */
    time_exp.tm_gmtoff = 0; /* UTC, no offset from UTC. */

    rc = apr_time_exp_gmt_get(&res, &time_exp);
    if(rc != APR_SUCCESS) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, rc, r,
                      "Error converting timestamp \"%s\".",
                      timestamp);
        return 0;
    }

    return res;
}


/* Validate the subject on an Assertion.
 *
 *  request_rec *r                   The current request. Used to log
 *                                   errors.
 *  LassoSaml2Assertion *assertion   The assertion we will validate.
 *  const char *url                  The current URL.
 *
 * Returns:
 *  OK on success, HTTP_BAD_REQUEST on failure.
 */
static int am_validate_subject(request_rec *r, LassoSaml2Assertion *assertion,
                               const char *url)
{
    apr_time_t now;
    apr_time_t t;
    LassoSaml2SubjectConfirmation *sc;
    LassoSaml2SubjectConfirmationData *scd;
    am_dir_cfg_rec *cfg = am_get_dir_cfg(r);

    if (assertion->Subject == NULL) {
        /* No Subject to validate. */
        return OK;
    } else if (!LASSO_IS_SAML2_SUBJECT(assertion->Subject)) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Wrong type of Subject node.");
        return HTTP_BAD_REQUEST;
    }

    if (assertion->Subject->SubjectConfirmation == NULL) {
        /* No SubjectConfirmation. */
        return OK;
    } else if (!LASSO_IS_SAML2_SUBJECT_CONFIRMATION(assertion->Subject->SubjectConfirmation)) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Wrong type of SubjectConfirmation node.");
        return HTTP_BAD_REQUEST;
    }

    sc = assertion->Subject->SubjectConfirmation;
    if (sc->Method == NULL ||
        strcmp(sc->Method, "urn:oasis:names:tc:SAML:2.0:cm:bearer")) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Invalid Method in SubjectConfirmation.");
        return HTTP_BAD_REQUEST;
    }

    scd = sc->SubjectConfirmationData;
    if (scd == NULL) {
        /* Nothing to verify. */
        return OK;
    } else if (!LASSO_IS_SAML2_SUBJECT_CONFIRMATION_DATA(scd)) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Wrong type of SubjectConfirmationData node.");
        return HTTP_BAD_REQUEST;
    }

    now = apr_time_now();

    if (scd->NotBefore) {
        t = am_parse_timestamp(r, scd->NotBefore);
        if (t == 0) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Invalid timestamp in NotBefore in SubjectConfirmationData.");
            return HTTP_BAD_REQUEST;
        }
        if (t - 60000000 > now) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "NotBefore in SubjectConfirmationData was in the future.");
            return HTTP_BAD_REQUEST;
        }
    }

    if (scd->NotOnOrAfter) {
        t = am_parse_timestamp(r, scd->NotOnOrAfter);
        if (t == 0) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Invalid timestamp in NotOnOrAfter in SubjectConfirmationData.");
            return HTTP_BAD_REQUEST;
        }
        if (now >= t + 60000000) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "NotOnOrAfter in SubjectConfirmationData was in the past.");
            return HTTP_BAD_REQUEST;
        }
    }

    if (scd->Recipient) {
        if (strcmp(scd->Recipient, url)) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Wrong Recipient in SubjectConfirmationData. Current URL is: %s, Recipient is %s",
                          url, scd->Recipient);
            return HTTP_BAD_REQUEST;
        }
    }

    if (scd->Address && CFG_VALUE(cfg, subject_confirmation_data_address_check)) {
        if (strcasecmp(scd->Address, am_compat_request_ip(r))) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Wrong Address in SubjectConfirmationData."
                          "Current address is \"%s\", but should have been \"%s\".",
                          am_compat_request_ip(r), scd->Address);
            return HTTP_BAD_REQUEST;
        }
    }

    return OK;
}


/* Validate the conditions on an Assertion.
 *
 * Parameters:
 *  request_rec *r                   The current request. Used to log
 *                                   errors.
 *  LassoSaml2Assertion *assertion   The assertion we will validate.
 *  const char *providerID           The providerID of the SP.
 *
 * Returns:
 *  OK on success, HTTP_BAD_REQUEST on failure.
 */
static int am_validate_conditions(request_rec *r,
                                  LassoSaml2Assertion *assertion,
                                  const char *providerID)
{
    LassoSaml2Conditions *conditions;
    apr_time_t now;
    apr_time_t t;
    GList *i;
    LassoSaml2AudienceRestriction *ar;

    conditions = assertion->Conditions;
    if (conditions == NULL) {
        /* An assertion without conditions -- nothing to validate. */
        return OK;
    }
    if (!LASSO_IS_SAML2_CONDITIONS(conditions)) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Wrong type of Conditions node.");
        return HTTP_BAD_REQUEST;
    }

    if (conditions->Condition != NULL) {
        /* This is a list of LassoSaml2ConditionAbstract - if it
         * isn't empty, we have an unsupported condition.
         */
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Unsupported condition in Assertion.");
        return HTTP_BAD_REQUEST;
    }


    now = apr_time_now();

    if (conditions->NotBefore) {
        t = am_parse_timestamp(r, conditions->NotBefore);
        if (t == 0) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Invalid timestamp in NotBefore in Condition.");
            return HTTP_BAD_REQUEST;
        }
        if (t - 60000000 > now) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "NotBefore in Condition was in the future.");
            return HTTP_BAD_REQUEST;
        }
    }

    if (conditions->NotOnOrAfter) {
        t = am_parse_timestamp(r, conditions->NotOnOrAfter);
        if (t == 0) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Invalid timestamp in NotOnOrAfter in Condition.");
            return HTTP_BAD_REQUEST;
        }
        if (now >= t + 60000000) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "NotOnOrAfter in Condition was in the past.");
            return HTTP_BAD_REQUEST;
        }
    }

    for (i = g_list_first(conditions->AudienceRestriction); i != NULL;
         i = g_list_next(i)) {
        ar = i->data;
        if (!LASSO_IS_SAML2_AUDIENCE_RESTRICTION(ar)) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Wrong type of AudienceRestriction node.");
            return HTTP_BAD_REQUEST;
        }

        if (ar->Audience == NULL || strcmp(ar->Audience, providerID)) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Invalid Audience in Conditions. Should be '%s', but was '%s'",
                          providerID, ar->Audience ? ar->Audience : "");
            return HTTP_BAD_REQUEST;
        }
    }

    return OK;
}



/* This function sets the session expire timestamp based on NotOnOrAfter
 * attribute of a condition element.
 *
 * Parameters:
 *  request_rec *r                   The current request. Used to log
 *                                   errors.
 *  am_cache_entry_t *session        The current session.
 *  LassoSaml2Assertion *assertion   The assertion which we will extract
 *                                   the conditions from.
 *
 * Returns:
 *  Nothing.
 */
static void am_handle_session_expire(request_rec *r, am_cache_entry_t *session,
                                LassoSaml2Assertion *assertion)
{
    GList *authn_itr;
    LassoSaml2AuthnStatement *authn;
    const char *not_on_or_after;
    apr_time_t t;

    for(authn_itr = g_list_first(assertion->AuthnStatement); authn_itr != NULL;
        authn_itr = g_list_next(authn_itr)) {

        authn = authn_itr->data;
        if (!LASSO_IS_SAML2_AUTHN_STATEMENT(authn)) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Wrong type of AuthnStatement node.");
            continue;
        }

        /* Find timestamp. */
        not_on_or_after = authn->SessionNotOnOrAfter;
        if(not_on_or_after == NULL) {
            am_diag_printf(r, "%s failed to find"
                           " Assertion.AuthnStatement.SessionNotOnOrAfter\n",
                           __func__);
            continue;
        }


        /* Parse timestamp. */
        t = am_parse_timestamp(r, not_on_or_after);
        if(t == 0) {
            continue;
        }

        am_diag_printf(r, "%s Assertion.AuthnStatement.SessionNotOnOrAfter:"
                       " %s\n",
                       __func__, am_diag_time_t_to_8601(r, t));

        /* Updates the expires timestamp if this one is earlier than the
         * previous timestamp.
         */
        am_cache_update_expires(r, session, t);
    }
}

/* Add all the attributes from an assertion to the session data for the
 * current user.
 *
 * Parameters:
 *  am_cache_entry_t *s             The current session.
 *  request_rec *r                  The current request.
 *  const char *name_id             The name identifier we received from
 *                                  the IdP.
 *  LassoSaml2Assertion *assertion  The assertion.
 *
 * Returns:
 *  HTTP_BAD_REQUEST if we couldn't find the session id of the user, or
 *  OK if no error occured.
 */
static int add_attributes(am_cache_entry_t *session, request_rec *r,
                          const char *name_id, LassoSaml2Assertion *assertion)
{
    am_dir_cfg_rec *dir_cfg;
    GList *atr_stmt_itr;
    LassoSaml2AttributeStatement *atr_stmt;
    GList *atr_itr;
    LassoSaml2Attribute *attribute;
    GList *value_itr;
    LassoSaml2AttributeValue *value;
    GList *any_itr;
    char *content;
    char *dump;
    int ret;

    dir_cfg = am_get_dir_cfg(r);

    /* Set expires to whatever is set by MellonSessionLength. */
    if(dir_cfg->session_length == -1) {
        /* -1 means "use default. The current default is 86400 seconds. */
        am_cache_update_expires(r, session, apr_time_now()
                                + apr_time_make(86400, 0));
    } else {
        am_cache_update_expires(r, session, apr_time_now()
                                + apr_time_make(dir_cfg->session_length, 0));
    }

    /* Save session information. */
    ret = am_cache_env_append(session, "NAME_ID", name_id);
    if(ret != OK) {
        return ret;
    }

    /* Update expires timestamp of session. */
    am_handle_session_expire(r, session, assertion);

    /* assertion->AttributeStatement is a list of
     * LassoSaml2AttributeStatement objects.
     */
    for(atr_stmt_itr = g_list_first(assertion->AttributeStatement);
        atr_stmt_itr != NULL;
        atr_stmt_itr = g_list_next(atr_stmt_itr)) {

        atr_stmt = atr_stmt_itr->data;
        if (!LASSO_IS_SAML2_ATTRIBUTE_STATEMENT(atr_stmt)) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Wrong type of AttributeStatement node.");
            continue;
        }

        /* atr_stmt->Attribute is list of LassoSaml2Attribute objects. */
        for(atr_itr = g_list_first(atr_stmt->Attribute);
            atr_itr != NULL;
            atr_itr = g_list_next(atr_itr)) {

            attribute = atr_itr->data;
            if (!LASSO_IS_SAML2_ATTRIBUTE(attribute)) {
                AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                              "Wrong type of Attribute node.");
                continue;
            }

            if (attribute->Name == NULL) {
                AM_LOG_RERROR(APLOG_MARK, APLOG_WARNING, 0, r,
                              "SAML 2.0 attribute without name.");
                continue;
            }

            /* attribute->AttributeValue is a list of
             * LassoSaml2AttributeValue objects.
             */
            for(value_itr = g_list_first(attribute->AttributeValue);
                value_itr != NULL;
                value_itr = g_list_next(value_itr)) {


                value = value_itr->data;
                if (!LASSO_IS_SAML2_ATTRIBUTE_VALUE(value)) {
                    AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                                  "Wrong type of AttributeValue node.");
                    continue;
                }

                /* value->any is a list with the child nodes of the
                 * AttributeValue element.
                 *
                 * We assume that the list contains a single text node.
                 */
                if(value->any == NULL) {
                    AM_LOG_RERROR(APLOG_MARK, APLOG_WARNING, 0, r,
                                  "AttributeValue element was empty.");
                    continue;
                }

                content = "";
                for (any_itr = g_list_first(value->any);
                     any_itr != NULL;
                     any_itr = g_list_next(any_itr)) {
                        /* Verify that this is a LassoNode object. */
                        if(!LASSO_NODE(any_itr->data)) {
                            AM_LOG_RERROR(APLOG_MARK, APLOG_WARNING, 0, r,
                                          "AttributeValue element contained an "
                                          " element which wasn't a Node.");
                            continue;
                        }
                        dump = lasso_node_dump(LASSO_NODE(any_itr->data));
                        if (!dump) {
                            AM_LOG_RERROR(APLOG_MARK, APLOG_WARNING, 0, r,
                                          "AttributeValue content dump failed.");
                            continue;
                        }
                        /* Use the request pool, no need to free results */
                        content = apr_pstrcat(r->pool, content, dump, NULL);
                        g_free(dump);
                }
                /* Decode and save the attribute. */

                am_diag_printf(r, "%s name=%s value=%s\n",
                               __func__, attribute->Name, content);

                ret = am_cache_env_append(session, attribute->Name, content);
                if(ret != OK) {
                    return ret;
                }
            }
        }
    }

    return OK;
}

/* This function validates that the received assertion verify the security level configured by
 * MellonAuthnContextClassRef directives
 */
static int am_validate_authn_context_class_ref(request_rec *r,
        LassoSaml2Assertion *assertion) {
    int i = 0;
    LassoSaml2AuthnStatement *authn_statement = NULL;
    LassoSaml2AuthnContext *authn_context = NULL;
    am_dir_cfg_rec *dir_cfg;
    apr_array_header_t *refs;

    dir_cfg = am_get_dir_cfg(r);
    refs = dir_cfg->authn_context_class_ref;
    if (! refs->nelts)
        return OK;

    if (! assertion->AuthnStatement) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Missing AuthnStatement in assertion, returning BadRequest.");
        return HTTP_BAD_REQUEST;
    }
    /* we only consider the first AuthnStatement, I do not know of any idp
     * sending more than one. */
    authn_statement = g_list_first(assertion->AuthnStatement)->data;
    if (! authn_statement->AuthnContext) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Missing AuthnContext in assertion, returning BadRequest.");
        return HTTP_BAD_REQUEST;
    }
    authn_context = authn_statement->AuthnContext;
    if (! authn_context->AuthnContextClassRef) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Missing AuthnContextClassRef in assertion, returning Forbidden.");
        return HTTP_FORBIDDEN;
    }
    for (i = 0; i < refs->nelts; i++) {
        const char *ref = ((char **)refs->elts)[i];
        if (strcmp(ref, authn_context->AuthnContextClassRef) == 0) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "AuthnContextClassRef (%s) matches the "
                          "MellonAuthnContextClassRef directive, "
                          "access can be granted.",
                          authn_context->AuthnContextClassRef);
            return OK;
        }
    }
    AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                  "AuthnContextClassRef (%s) does not match the "
                  "MellonAuthnContextClassRef directive, returning "
                  "Forbidden.",
                  authn_context->AuthnContextClassRef);
    return HTTP_FORBIDDEN;
}

/* This function finishes handling of a login response after it has been parsed
 * by the HTTP-POST or HTTP-Artifact handler.
 *
 * Parameters:
 *  request_rec *r       The current request.
 *  LassoLogin *login    The login object which has been initialized with the
 *                       data we have received from the IdP.
 *  char *relay_state    The RelayState parameter from the POST data or from
 *                       the request url. This parameter is urlencoded, and
 *                       this function will urldecode it in-place. Therefore it
 *                       must be possible to overwrite the data.
 *  is_paos              If true then flow is PAOS ECP.
 *
 * Returns:
 *  A HTTP status code which should be returned to the client.
 */
static int am_handle_reply_common(request_rec *r, LassoLogin *login,
                                  char *relay_state, char *saml_response,
                                  bool is_paos)
{
    char *url;
    char *chr;
    const char *name_id;
    LassoSamlp2Response *response;
    LassoSaml2Assertion *assertion;
    const char *in_response_to;
    am_dir_cfg_rec *dir_cfg;
    am_cache_entry_t *session;
    int rc;
    const char *idp;

    url = am_reconstruct_url(r);
    chr = strchr(url, '?');
    if (! chr) {
        chr = strchr(url, ';');
    }
    if (chr) {
        *chr = '\0';
    }


    dir_cfg = am_get_dir_cfg(r);

    if(LASSO_PROFILE(login)->nameIdentifier == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "No acceptable name identifier found in"
                      " SAML 2.0 response.");
        lasso_login_destroy(login);
        return HTTP_BAD_REQUEST;
    }

    name_id = LASSO_SAML2_NAME_ID(LASSO_PROFILE(login)->nameIdentifier)
        ->content;

    response = LASSO_SAMLP2_RESPONSE(LASSO_PROFILE(login)->response);

    if (response->parent.Destination) {
        if (strcmp(response->parent.Destination, url)) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Invalid Destination on Response. Should be '%s', but was '%s'",
                          url, response->parent.Destination);
            lasso_login_destroy(login);
            return HTTP_BAD_REQUEST;
        }
    }

    if (g_list_length(response->Assertion) == 0) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "No Assertion in response.");
        lasso_login_destroy(login);
        return HTTP_BAD_REQUEST;
    }
    if (g_list_length(response->Assertion) > 1) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "More than one Assertion in response.");
        lasso_login_destroy(login);
        return HTTP_BAD_REQUEST;
    }
    assertion = g_list_first(response->Assertion)->data;
    if (!LASSO_IS_SAML2_ASSERTION(assertion)) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Wrong type of Assertion node.");
        lasso_login_destroy(login);
        return HTTP_BAD_REQUEST;
    }

    rc = am_validate_subject(r, assertion, url);
    if (rc != OK) {
        lasso_login_destroy(login);
        return rc;
    }

    rc = am_validate_conditions(r, assertion,
        LASSO_PROVIDER(LASSO_PROFILE(login)->server)->ProviderID);

    if (rc != OK) {
        lasso_login_destroy(login);
        return rc;
    }

    in_response_to = response->parent.InResponseTo;


    if (!is_paos) {
        if(in_response_to != NULL) {
            /* This is SP-initiated login. Check that we have a cookie. */
            if(am_cookie_get(r) == NULL) {
                /* Missing cookie. */
                AM_LOG_RERROR(APLOG_MARK, APLOG_WARNING, 0, r,
                              "User has disabled cookies, or has lost"
                              " the cookie before returning from the SAML2"
                              " login server.");
                if(dir_cfg->no_cookie_error_page != NULL) {
                    apr_table_setn(r->headers_out, "Location",
                                   dir_cfg->no_cookie_error_page);
                    lasso_login_destroy(login);
                    return HTTP_SEE_OTHER;
                } else {
                    /* Return 400 Bad Request when the user hasn't set a
                     * no-cookie error page.
                     */
                    lasso_login_destroy(login);
                    return HTTP_BAD_REQUEST;
                }
            }
        }
    }

    /* Check AuthnContextClassRef */
    rc = am_validate_authn_context_class_ref(r, assertion);
    if (rc != OK) {
        lasso_login_destroy(login);
        return rc;
    }

    /* Create a new session. */
    session = am_new_request_session(r);
    if(session == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                    "am_new_request_session() failed");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = add_attributes(session, r, name_id, assertion);
    if(rc != OK) {
        am_release_request_session(r, session);
        lasso_login_destroy(login);
        return rc;
    }

    /* If requested, save the IdP ProviderId */
    if(dir_cfg->idpattr != NULL) {
        idp = LASSO_PROFILE(login)->remote_providerID;
        if(idp != NULL) {
            rc = am_cache_env_append(session, dir_cfg->idpattr, idp);
            if(rc != OK) {
                am_release_request_session(r, session);
                lasso_login_destroy(login);
                return rc;
            }
        }
    }

    rc = lasso_login_accept_sso(login);
    if(rc != 0) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Unable to accept SSO message."
                      " Lasso error: [%i] %s", rc, lasso_strerror(rc));
        am_release_request_session(r, session);
        lasso_login_destroy(login);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Save the profile state. */
    rc = am_save_lasso_profile_state(r, session, LASSO_PROFILE(login),
                                     saml_response);
    if(rc != OK) {
        am_release_request_session(r, session);
        lasso_login_destroy(login);
        return rc;
    }

    /* Mark user as logged in. */
    session->logged_in = 1;

    am_release_request_session(r, session);
    lasso_login_destroy(login);


    /* No RelayState - we don't know what to do. Use default login path. */
    if(relay_state == NULL || strlen(relay_state) == 0) {
       dir_cfg = am_get_dir_cfg(r);
       apr_table_setn(r->headers_out, "Location", dir_cfg->login_path);
       return HTTP_SEE_OTHER;
    }

    rc = am_urldecode(relay_state);
    if (rc != OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, rc, r,
                      "Could not urldecode RelayState value.");
        return HTTP_BAD_REQUEST;
    }

    /* Check for bad characters in RelayState. */
    rc = am_check_url(r, relay_state);
    if (rc != OK) {
        return rc;
    }

    rc = am_validate_redirect_url(r, relay_state);
    if (rc != OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Invalid target domain in logout response RelayState parameter.");
        return rc;
    }

    apr_table_setn(r->headers_out, "Location",
                   relay_state);

    /* HTTP_SEE_OTHER should be a redirect where the browser doesn't repeat
     * the POST data to the new page.
     */
    return HTTP_SEE_OTHER;
}


/* This function handles responses to login requests received with the
 * HTTP-POST binding.
 *
 * Parameters:
 *  request_rec *r       The request we received.
 *
 * Returns:
 *  HTTP_SEE_OTHER on success, or an error on failure.
 */
static int am_handle_post_reply(request_rec *r)
{
    int rc;
    char *post_data;
    char *saml_response;
    LassoServer *server;
    LassoLogin *login;
    char *relay_state;
    am_dir_cfg_rec *dir_cfg = am_get_dir_cfg(r);
    int i, err;

    am_diag_printf(r, "enter function %s\n", __func__);

    /* Make sure that this is a POST request. */
    if(r->method_number != M_POST) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Expected POST request for HTTP-POST endpoint."
                      " Got a %s request instead.", r->method);

        /* According to the documentation for request_rec, a handler which
         * doesn't handle a request method, should set r->allowed to the
         * methods it handles, and return DECLINED.
         * However, the default handler handles GET-requests, so for GET
         * requests the handler should return HTTP_METHOD_NOT_ALLOWED.
         */
        r->allowed = M_POST;

        if(r->method_number == M_GET) {
            return HTTP_METHOD_NOT_ALLOWED;
        } else {
            return DECLINED;
        }
    }

    /* Read POST-data. */
    rc = am_read_post_data(r, &post_data, NULL);
    if (rc != OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, rc, r,
                      "Error reading POST data.");
        return rc;
    }

    /* Extract the SAMLResponse-field from the data. */
    saml_response = am_extract_query_parameter(r->pool, post_data,
                                            "SAMLResponse");
    if (saml_response == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, rc, r,
                      "Could not find SAMLResponse field in POST data.");
        return HTTP_BAD_REQUEST;
    }

    rc = am_urldecode(saml_response);
    if (rc != OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, rc, r,
                      "Could not urldecode SAMLResponse value.");
        return rc;
    }

    server = am_get_lasso_server(r);
    if(server == NULL) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    login = lasso_login_new(server);
    if (login == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to initialize LassoLogin object.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Process login responce. */
    rc = lasso_login_process_authn_response_msg(login, saml_response);
    am_diag_log_lasso_node(r, 0, LASSO_PROFILE(login)->response,
                           "SAML Response (%s):", __func__);
    if (rc != 0) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error processing authn response."
                      " Lasso error: [%i] %s, SAML Response: %s",
                      rc, lasso_strerror(rc),
                      am_saml_response_status_str(r,
                        LASSO_PROFILE(login)->response));

        lasso_login_destroy(login);
        err = HTTP_BAD_REQUEST;
        for (i = 0; auth_mellon_errormap[i].lasso_error != 0; i++) {
            if (auth_mellon_errormap[i].lasso_error == rc) {
                err = auth_mellon_errormap[i].http_error;
                break;
            }
        }
        if (err == HTTP_UNAUTHORIZED) {
            if (dir_cfg->no_success_error_page != NULL) {
                apr_table_setn(r->headers_out, "Location",
                               dir_cfg->no_success_error_page);
                return HTTP_SEE_OTHER;
            }
        }
        return err;
    }

    /* Extract RelayState parameter. */
    relay_state = am_extract_query_parameter(r->pool, post_data,
                                               "RelayState");

    /* Finish handling the reply with the common handler. */
    return am_handle_reply_common(r, login, relay_state, saml_response, false);
}


/* This function handles responses to login requests received with the
 * PAOS binding.
 *
 * Parameters:
 *  request_rec *r       The request we received.
 *
 * Returns:
 *  HTTP_SEE_OTHER on success, or an error on failure.
 */
static int am_handle_paos_reply(request_rec *r)
{
    int rc;
    char *post_data;
    LassoServer *server;
    LassoLogin *login;
    char *relay_state = NULL;
    int i, err;

    am_diag_printf(r, "enter function %s\n", __func__);

    /* Make sure that this is a POST request. */
    if(r->method_number != M_POST) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Expected POST request for paosResponse endpoint."
                      " Got a %s request instead.", r->method);

        /* According to the documentation for request_rec, a handler which
         * doesn't handle a request method, should set r->allowed to the
         * methods it handles, and return DECLINED.
         * However, the default handler handles GET-requests, so for GET
         * requests the handler should return HTTP_METHOD_NOT_ALLOWED.
         */
        r->allowed = M_POST;

        if(r->method_number == M_GET) {
            return HTTP_METHOD_NOT_ALLOWED;
        } else {
            return DECLINED;
        }
    }

    /* Read POST-data. */
    rc = am_read_post_data(r, &post_data, NULL);
    if (rc != OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, rc, r,
                      "Error reading POST data.");
        return rc;
    }

    server = am_get_lasso_server(r);
    if(server == NULL) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    login = lasso_login_new(server);
    if (login == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to initialize LassoLogin object.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Process login response. */
    rc = lasso_login_process_paos_response_msg(login, post_data);
    am_diag_log_lasso_node(r, 0, LASSO_PROFILE(login)->response,
                           "SAML Response (%s):", __func__);
    if (rc != 0) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error processing ECP authn response."
                      " Lasso error: [%i] %s, SAML Response: %s",
                      rc, lasso_strerror(rc),
                      am_saml_response_status_str(r,
                        LASSO_PROFILE(login)->response));

        lasso_login_destroy(login);
        err = HTTP_BAD_REQUEST;
        for (i = 0; auth_mellon_errormap[i].lasso_error != 0; i++) {
            if (auth_mellon_errormap[i].lasso_error == rc) {
                err = auth_mellon_errormap[i].http_error;
                break;
            }
        }
        return err;
    }

    /* Extract RelayState parameter. */
    if (LASSO_PROFILE(login)->msg_relayState) {
        relay_state = apr_pstrdup(r->pool, LASSO_PROFILE(login)->msg_relayState);
    }

    /* Finish handling the reply with the common handler. */
    return am_handle_reply_common(r, login, relay_state, post_data, true);
}

/* This function handles responses to login requests which use the
 * HTTP-Artifact binding.
 *
 * Parameters:
 *  request_rec *r       The request we received.
 *
 * Returns:
 *  HTTP_SEE_OTHER on success, or an error on failure.
 */
static int am_handle_artifact_reply(request_rec *r)
{
    int rc;
    LassoServer *server;
    LassoLogin *login;
    char *response;
    char *relay_state;
    char *saml_art;
    char *post_data;

    am_diag_printf(r, "enter function %s\n", __func__);

    /* Make sure that this is a GET request. */
    if(r->method_number != M_GET && r->method_number != M_POST) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Expected GET or POST request for the HTTP-Artifact endpoint."
                      " Got a %s request instead.", r->method);

        /* According to the documentation for request_rec, a handler which
         * doesn't handle a request method, should set r->allowed to the
         * methods it handles, and return DECLINED.
         * However, the default handler handles GET-requests, so for GET
         * requests the handler should return HTTP_METHOD_NOT_ALLOWED.
         * This endpoints handles GET requests, so it isn't necessary to
         * check for method_number == M_GET.
         */
        r->allowed = M_GET;

        return DECLINED;
    }

    server = am_get_lasso_server(r);
    if(server == NULL) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    login = lasso_login_new(server);
    if (login == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to initialize LassoLogin object.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Parse artifact url. */
    if (r->method_number == M_GET) {
        rc = lasso_login_init_request(login, r->args,
                                  LASSO_HTTP_METHOD_ARTIFACT_GET);

        if(rc != 0) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Failed to handle login response."
                          " Lasso error: [%i] %s", rc, lasso_strerror(rc));
            lasso_login_destroy(login);
            return HTTP_BAD_REQUEST;
        }
    } else {
        rc = am_read_post_data(r, &post_data, NULL);
        if (rc != OK) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, rc, r,
                    "Error reading POST data.");
            return HTTP_BAD_REQUEST;
        }

        saml_art = am_extract_query_parameter(r->pool, post_data, "SAMLart");
        if (saml_art == NULL) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, rc, r,
                    "Error reading POST data missing SAMLart form parameter.");
            return HTTP_BAD_REQUEST;
        }
        ap_unescape_url(saml_art);

        rc = lasso_login_init_request(login, saml_art, LASSO_HTTP_METHOD_ARTIFACT_POST);
        if(rc != 0) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Failed to handle login response."
                          " Lasso error: [%i] %s", rc, lasso_strerror(rc));
            lasso_login_destroy(login);
            return HTTP_BAD_REQUEST;
        }
    }

    /* Prepare SOAP request. */
    rc = lasso_login_build_request_msg(login);
    if(rc != 0) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to prepare SOAP message for HTTP-Artifact"
                      " resolution."
                      " Lasso error: [%i] %s", rc, lasso_strerror(rc));
        lasso_login_destroy(login);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Do the SOAP request. */
    rc = am_httpclient_post_str(
        r,
        LASSO_PROFILE(login)->msg_url,
        LASSO_PROFILE(login)->msg_body,
        "text/xml",
        (void**)&response,
        NULL
        );
    if(rc != OK) {
        lasso_login_destroy(login);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = lasso_login_process_response_msg(login, response);
    am_diag_log_lasso_node(r, 0, LASSO_PROFILE(login)->response,
                           "SAML Response (%s):", __func__);
    if(rc != 0) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to handle HTTP-Artifact response data."
                      " Lasso error: [%i] %s, SAML Response: %s",
                      rc, lasso_strerror(rc),
                      am_saml_response_status_str(r,
                        LASSO_PROFILE(login)->response));

        lasso_login_destroy(login);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Extract the RelayState parameter. */
    if (r->method_number == M_GET) {
        relay_state = am_extract_query_parameter(r->pool, r->args,
                                                   "RelayState");
    } else {
        relay_state = am_extract_query_parameter(r->pool, post_data,
                                                   "RelayState");
    }

    /* Finish handling the reply with the common handler. */
    return am_handle_reply_common(r, login, relay_state, "", false);
}



/* This function builds web form inputs for a saved POST request, 
 * in multipart/form-data format.
 *
 * Parameters:
 *  request_rec *r        The request
 *  const char *post_data The savec POST request
 *
 * Returns:
 *  The web form fragment, or NULL on failure.
 */
const char *am_post_mkform_multipart(request_rec *r, const char *post_data)
{
    const char *mime_part;
    const char *boundary;
    char *l1;
    char *post_form = "";

    /* Replace CRLF by LF */
    post_data = am_strip_cr(r, post_data);

    if ((boundary = am_xstrtok(r, post_data, "\n", &l1)) == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                     "Cannot figure initial boundary");
        return NULL;
    }

    for (mime_part = am_xstrtok(r, post_data, boundary, &l1); mime_part;
         mime_part = am_xstrtok(r, NULL, boundary, &l1)) {
        const char *hdr;
        const char *name = NULL;
        const char *value = NULL;
        const char *input_item;

        /* End of MIME data */
        if (strcmp(mime_part, "--\n") == 0)
            break;

        /* Remove leading CRLF */
        if (strstr(mime_part, "\n") == mime_part)
            mime_part += 1;

        /* Empty part */
        if (*mime_part == '\0')
            continue;

        /* Find Content-Disposition header 
         * Looking for 
         * Content-Disposition: form-data; name="the_name"\n 
         */
        hdr = am_get_mime_header(r, mime_part, "Content-Disposition");
        if (hdr == NULL) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                         "No Content-Disposition header in MIME section,");
            continue;
        }

        name = am_get_header_attr(r, hdr, "form-data", "name");
        if (name == NULL) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                         "Unexpected Content-Disposition header: \"%s\"", hdr);
            continue;
        }

        if ((value = am_get_mime_body(r, mime_part)) == NULL)
            value = "";

        input_item = apr_psprintf(r->pool, 
                    "    <input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
                    am_htmlencode(r, name), am_htmlencode(r, value));
        post_form = apr_pstrcat(r->pool, post_form, input_item, NULL);
    }

    return post_form;
}

/* This function builds web form inputs for a saved POST request, 
 * in application/x-www-form-urlencoded format
 *
 * Parameters:
 *  request_rec *r        The request
 *  const char *post_data The savec POST request
 *
 * Returns:
 *  The web form fragment, or NULL on failure.
 */
const char *am_post_mkform_urlencoded(request_rec *r, const char *post_data)
{
    const char *item;
    char *last;
    char *post_form = "";
    char empty_value[] = "";

    for (item = am_xstrtok(r, post_data, "&", &last); item; 
         item = am_xstrtok(r, NULL, "&", &last)) {
        char *l1;
        char *name;
        char *value;
        const char *input_item;

        name = (char *)am_xstrtok(r, item, "=", &l1);  
        value = (char *)am_xstrtok(r, NULL, "=", &l1);

        if (name == NULL)
            continue;

        if (value == NULL)
            value = empty_value;

        if (am_urldecode(name) != OK) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                         "urldecode(\"%s\") failed", name);
            return NULL;
        }

        if (am_urldecode(value) != OK) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                         "urldecode(\"%s\") failed", value);
            return NULL;
        }

        input_item = apr_psprintf(r->pool, 
                    "    <input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
                    am_htmlencode(r, name), am_htmlencode(r, value));
        post_form = apr_pstrcat(r->pool, post_form, input_item, NULL);
    }
    return post_form;
}


/* This function handles responses to repost request
 *
 * Parameters:
 *  request_rec *r       The request we received.
 *
 * Returns:
 *  OK on success, or an error on failure.
 */
static int am_handle_repost(request_rec *r)
{
    am_mod_cfg_rec *mod_cfg;
    const char *query;
    const char *enctype;
    char *charset;
    char *psf_id;
    char *cp;
    am_file_data_t *file_data;
    const char *post_data;
    const char *post_form;
    char *output;
    char *return_url;
    const char *(*post_mkform)(request_rec *, const char *);
    int rc;

    am_diag_printf(r, "enter function %s\n", __func__);

    if (am_cookie_get(r) == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Repost query without a session");
        return HTTP_FORBIDDEN;
    }

    mod_cfg = am_get_mod_cfg(r->server);

    if (!mod_cfg->post_dir) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Repost query without MellonPostDirectory.");
        return HTTP_NOT_FOUND;
    }

    query = r->parsed_uri.query;

    enctype = am_extract_query_parameter(r->pool, query, "enctype");
    if (enctype == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Bad repost query: missing enctype");
        return HTTP_BAD_REQUEST;
    }
    if (strcmp(enctype, "urlencoded") == 0) {
        enctype = "application/x-www-form-urlencoded";
        post_mkform = am_post_mkform_urlencoded;
    } else if (strcmp(enctype, "multipart") == 0) {
        enctype = "multipart/form-data";
        post_mkform = am_post_mkform_multipart;
    } else {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Bad repost query: invalid enctype \"%s\".", enctype);
        return HTTP_BAD_REQUEST;
    }

    charset = am_extract_query_parameter(r->pool, query, "charset");
    if (charset != NULL) {
        if (am_urldecode(charset) != OK) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Bad repost query: invalid charset \"%s\"", charset);
            return HTTP_BAD_REQUEST;
        }
    
        /* Check that charset is sane */
        for (cp = charset; *cp; cp++) {
            if (!apr_isalnum(*cp) && (*cp != '-') && (*cp != '_')) {
                AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                              "Bad repost query: invalid charset \"%s\"", charset);
                return HTTP_BAD_REQUEST;
            }
        }
    }

    psf_id = am_extract_query_parameter(r->pool, query, "id");
    if (psf_id == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Bad repost query: missing id");
        return HTTP_BAD_REQUEST;
    }

    /* Check that Id is sane */
    for (cp = psf_id; *cp; cp++) {
        if (!apr_isalnum(*cp)) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Bad repost query: invalid id \"%s\"", psf_id);
            return HTTP_BAD_REQUEST;
        }
    }
    
    
    return_url = am_extract_query_parameter(r->pool, query, "ReturnTo");
    if (return_url == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Invalid or missing query ReturnTo parameter.");
        return HTTP_BAD_REQUEST;
    }

    if (am_urldecode(return_url) != OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r, "Bad repost query: return");
        return HTTP_BAD_REQUEST;
    }

    rc = am_validate_redirect_url(r, return_url);
    if (rc != OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Invalid target domain in repost request ReturnTo parameter.");
        return rc;
    }

    if ((file_data = am_file_data_new(r->pool, NULL)) == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_WARNING, 0, r,
                      "Bad repost query: cannot allocate file_data");
        apr_table_setn(r->headers_out, "Location", return_url);
        return HTTP_SEE_OTHER;
    }

    file_data->path = apr_psprintf(file_data->pool, "%s/%s",
                                   mod_cfg->post_dir, psf_id);
    rc = am_file_read(file_data);
    if (rc != APR_SUCCESS) {
        /* Unable to load repost data. Just redirect us instead. */
        AM_LOG_RERROR(APLOG_MARK, APLOG_WARNING, 0, r,
                      "Bad repost query: %s", file_data->strerror);
        apr_table_setn(r->headers_out, "Location", return_url);
        return HTTP_SEE_OTHER;
    } else {
        post_data = file_data->contents;
    }

    if ((post_form = (*post_mkform)(r, post_data)) == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r, "am_post_mkform() failed");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (charset != NULL) {
         ap_set_content_type(r, apr_psprintf(r->pool,
                             "text/html; charset=\"%s\"", charset));
         charset = apr_psprintf(r->pool, " accept-charset=\"%s\"", charset);
    } else {
         ap_set_content_type(r, "text/html");
         charset = (char *)"";
    }

    output = apr_psprintf(r->pool,
      "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\n"
      "<html>\n"
      " <head>\n" 
      "  <title>SAML rePOST request</title>\n" 
      " </head>\n" 
      " <body onload=\"document.getElementById('form').submit();\">\n" 
      "  <noscript>\n"
      "   Your browser does not support Javascript, \n"
      "   you must click the button below to proceed.\n"
      "  </noscript>\n"
      "   <form id=\"form\" method=\"POST\" action=\"%s\" enctype=\"%s\"%s>\n%s"
      "    <noscript>\n"
      "     <input type=\"submit\">\n"
      "    </noscript>\n"
      "   </form>\n"
      " </body>\n" 
      "</html>\n",
      am_htmlencode(r, return_url), enctype, charset, post_form);

    ap_rputs(output, r);
    return OK;
}


/* This function handles responses to metadata request
 *
 * Parameters:
 *  request_rec *r       The request we received.
 *
 * Returns:
 *  OK on success, or an error on failure.
 */
static int am_handle_metadata(request_rec *r)
{
#ifdef HAVE_lasso_server_new_from_buffers
    am_dir_cfg_rec *cfg = am_get_dir_cfg(r);
    LassoServer *server;
    const char *data;

    am_diag_printf(r, "enter function %s\n", __func__);

    server = am_get_lasso_server(r);
    if(server == NULL)
        return HTTP_INTERNAL_SERVER_ERROR;

    cfg = cfg->inherit_server_from;

    data = cfg->sp_metadata_file ? cfg->sp_metadata_file->contents : NULL;
    if (data == NULL)
        return HTTP_INTERNAL_SERVER_ERROR;

    ap_set_content_type(r, "application/samlmetadata+xml");

    ap_rputs(data, r);

    return OK;
#else  /* ! HAVE_lasso_server_new_from_buffers */

    AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                  "metadata publishing require lasso 2.2.2 or higher");
    return HTTP_NOT_FOUND;
#endif
}


/* Use Lasso Login to set the HTTP content & headers for HTTP-Redirect binding.
 *
 * Parameters:
 *  request_rec *r
 *  LassoLogin *login
 *
 * Returns:
 *  HTTP_SEE_OTHER on success, or an error on failure.
 */
static int am_set_authn_request_redirect_content(request_rec *r, LassoLogin *login)
{
    char *redirect_to;

    /* The URL we should send the message to. */
    redirect_to = apr_pstrdup(r->pool, LASSO_PROFILE(login)->msg_url);

    /* Check if the lasso library added the RelayState. If lasso didn't add
     * a RelayState parameter, then we add one ourself. This should hopefully
     * be removed in the future.
     */
    if(strstr(redirect_to, "&RelayState=") == NULL
       && strstr(redirect_to, "?RelayState=") == NULL) {
        /* The url didn't contain the relaystate parameter. */
        redirect_to = apr_pstrcat(
            r->pool, redirect_to, "&RelayState=",
            am_urlencode(r->pool, LASSO_PROFILE(login)->msg_relayState),
            NULL
            );
    }
    apr_table_setn(r->headers_out, "Location", redirect_to);

    /* We don't want to include POST data (in case this was a POST request). */
    return HTTP_SEE_OTHER;
}

/* Use Lasso Login to set the HTTP content & headers for HTTP-POST binding.
 *
 * Parameters:
 *  request_rec *r         The request we are processing.
 *  LassoLogin *login      The login message.
 *
 * Returns:
 *  OK on success, or an error on failure.
 */
static int am_set_authn_request_post_content(request_rec *r, LassoLogin *login)
{
    char *url;
    char *message;
    char *relay_state;
    char *output;

    url = am_htmlencode(r, LASSO_PROFILE(login)->msg_url);
    message = am_htmlencode(r, LASSO_PROFILE(login)->msg_body);
    relay_state = am_htmlencode(r, LASSO_PROFILE(login)->msg_relayState);

    output = apr_psprintf(r->pool,
      "<!DOCTYPE html>\n"
      "<html>\n"
      " <head>\n"
      "  <meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">\n"
      "  <title>POST data</title>\n"
      " </head>\n"
      " <body onload=\"document.forms[0].submit()\">\n"
      "  <noscript><p>\n"
      "   <strong>Note:</strong> Since your browser does not support JavaScript, you must press the button below once to proceed.\n"
      "  </p></noscript>\n"
      "  <form method=\"POST\" action=\"%s\">\n"
      "    <input type=\"hidden\" name=\"SAMLRequest\" value=\"%s\">\n"
      "    <input type=\"hidden\" name=\"RelayState\" value=\"%s\">\n"
      "    <noscript>\n"
      "     <input type=\"submit\">\n"
      "    </noscript>\n"
      "  </form>\n"
      " </body>\n"
      "</html>\n",
      url, message, relay_state);

    ap_set_content_type(r, "text/html");
    ap_rputs(output, r);

    return OK;
}

/* Use Lasso Login to set the HTTP content & headers for PAOS binding.
 *
 * Parameters:
 *  request_rec *r         The request we are processing.
 *  LassoLogin *login      The login message.
 *
 * Returns:
 *  OK on success, or an error on failure.
 */
static int am_set_authn_request_paos_content(request_rec *r, LassoLogin *login)
{
    ap_set_content_type(r, MEDIA_TYPE_PAOS);
    ap_rputs(LASSO_PROFILE(login)->msg_body, r);

    return OK;
}

/*
 * Create and initialize LassoLogin object
 *
 * This function creates a LassoLogin object and initializes it to the
 * greatest extent possible to allow it to be shared by multiple
 * callers. There are two return values. The function return is an
 * error code, the login_return parameter is a pointer in which to
 * receive the LassoLogin object. The caller MUST free the returned
 * login object using lasso_login_destroy() in all cases (even when
 * this function returns an error), the only execption is if the
 * returned LassoLogin is NULL.
 *
 * Parameters:
 *  r                The request we are processing.
 *  login_return     The returned LassoLogin object (caller must free)
 *  idp              The provider id of remote Idp
 *                   [optional, may be NULL]
 *  http_method      Specifies the SAML profile to use
 *  destination_url  If the idp parameter is non-NULL this should be
 *                   the URL of the IdP endpoint the message is being sent to
 *                   [optional, may be NULL]
 *  assertion_consumer_service_url
 *                   The URL of this SP's endpoint which will receive the
 *                   SAML assertion
 *  return_to_url    Used to initialize the RelayState value
 *  is_passive       The SAML IsPassive flag
 *
 * Returns:
 *  OK on success, HTTP error code otherwise
 *
 */
static int am_init_authn_request_common(request_rec *r,
                                        LassoLogin **login_return,
                                        const char *idp,
                                        LassoHttpMethod http_method,
                                        const char *destination_url,
                                        const char *assertion_consumer_service_url,
                                        const char *return_to_url,
                                        int is_passive)
{
    gint ret;
    am_dir_cfg_rec *dir_cfg;
    LassoServer *server;
    LassoLogin *login;
    LassoSamlp2AuthnRequest *request;
    const char *sp_name;

    *login_return = NULL;

    dir_cfg = am_get_dir_cfg(r);

    server = am_get_lasso_server(r);
    if (server == NULL) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    login = lasso_login_new(server);
    if(login == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
		      "Error creating LassoLogin object from LassoServer.");
	return HTTP_INTERNAL_SERVER_ERROR;
    }
    *login_return = login;

    ret = lasso_login_init_authn_request(login, idp, http_method);
    if(ret != 0) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error creating login request."
                      " Lasso error: [%i] %s", ret, lasso_strerror(ret));
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    request = LASSO_SAMLP2_AUTHN_REQUEST(LASSO_PROFILE(login)->request);
    if (request->NameIDPolicy == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error creating login request. Please verify the "
                      "MellonSPMetadataFile directive.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * Make sure the Destination attribute is set to the IdP
     * SingleSignOnService endpoint. This is required for
     * Shibboleth 2 interoperability, and older versions of
     * lasso (at least up to 2.2.91) did not do it.
     */
    if (destination_url &&
        LASSO_SAMLP2_REQUEST_ABSTRACT(request)->Destination == NULL) {
        lasso_assign_string(LASSO_SAMLP2_REQUEST_ABSTRACT(request)->Destination,
                            destination_url);
    }

    if (assertion_consumer_service_url) {
        lasso_assign_string(request->AssertionConsumerServiceURL,
                            assertion_consumer_service_url);
        /* Can't set request->ProtocolBinding (which is usually set along side
         * AssertionConsumerServiceURL) as there is no immediate function
         * like lasso_provider_get_assertion_consumer_service_url to get them.
         * So leave that empty for now, it is not strictly required */
    }

    request->ForceAuthn = FALSE;
    request->IsPassive = is_passive;
    request->NameIDPolicy->AllowCreate = TRUE;

    sp_name = am_get_config_langstring(dir_cfg->sp_org_display_name, NULL);
    if (sp_name) {
        lasso_assign_string(request->ProviderName, sp_name);
    }


    LASSO_SAMLP2_REQUEST_ABSTRACT(request)->Consent
      = g_strdup(LASSO_SAML2_CONSENT_IMPLICIT);

    /* Add AuthnContextClassRef */
    if (dir_cfg->authn_context_class_ref->nelts) {
        apr_array_header_t *refs = dir_cfg->authn_context_class_ref;
        int i = 0;
        LassoSamlp2RequestedAuthnContext *req_authn_context;

        req_authn_context = (LassoSamlp2RequestedAuthnContext*)
            lasso_samlp2_requested_authn_context_new();

        request->RequestedAuthnContext = req_authn_context;

        for (i = 0; i < refs->nelts; i++) {
            const char *ref = ((char **)refs->elts)[i];
            req_authn_context->AuthnContextClassRef =
                    g_list_append(req_authn_context->AuthnContextClassRef,
                                    g_strdup(ref));
            AM_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "adding AuthnContextClassRef %s to the "
                          "AuthnRequest", ref);
        }
    }

    LASSO_PROFILE(login)->msg_relayState = g_strdup(return_to_url);

#ifdef HAVE_ECP
    {
        am_req_cfg_rec *req_cfg;
        ECPServiceOptions unsupported_ecp_options;
        req_cfg = am_get_req_cfg(r);

        /*
         * Currently we only support the WANT_AUTHN_SIGNED ECP option,
         * if a client sends us anything else let them know it's not
         * implemented.
         *
         * We do test for CHANNEL_BINDING below but that's because if
         * and when we support it we don't want to forget channel
         * bindings require the authn request to be signed.
         */
        unsupported_ecp_options =
            req_cfg->ecp_service_options &
            ~ECP_SERVICE_OPTION_WANT_AUTHN_SIGNED;
        if (unsupported_ecp_options) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Unsupported ECP service options [%s]",
                          am_ecp_service_options_str(r->pool,
                                                     unsupported_ecp_options));
            return HTTP_NOT_IMPLEMENTED;
        }

        /*
         * The signature hint must be set prior to calling
         * lasso_login_build_authn_request_msg
         */
        if (req_cfg->ecp_service_options &
            (ECP_SERVICE_OPTION_WANT_AUTHN_SIGNED |
             ECP_SERVICE_OPTION_CHANNEL_BINDING)) {
            /*
             * authnRequest should be signed if the client requested it
             * or if channel bindings are enabled.
             */
            lasso_profile_set_signature_hint(LASSO_PROFILE(login),
                                             LASSO_PROFILE_SIGNATURE_HINT_FORCE);
        }
    }
#endif

    ret = lasso_login_build_authn_request_msg(login);
    if (ret != 0) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error building login request."
                      " Lasso error: [%i] %s", ret, lasso_strerror(ret));
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    return OK;
}

/* Use Lasso Login to set the HTTP content & headers for selected binding.
 *
 * Parameters:
 *  request_rec *r         The request we are processing.
 *  LassoLogin *login      The login message.
 *
 * Returns:
 *  HTTP response code
 */
static int am_set_authn_request_content(request_rec *r, LassoLogin *login)

{

    am_diag_log_lasso_node(r, 0, LASSO_PROFILE(login)->request,
                           "SAML AuthnRequest: http_method=%s URL=%s",
                           am_diag_lasso_http_method_str(login->http_method),
                           LASSO_PROFILE(login)->msg_url);

    switch (login->http_method) {
    case LASSO_HTTP_METHOD_REDIRECT:
        return am_set_authn_request_redirect_content(r, login);
    case LASSO_HTTP_METHOD_POST:
        return am_set_authn_request_post_content(r, login);
    case LASSO_HTTP_METHOD_PAOS:
        return am_set_authn_request_paos_content(r, login);
    default:
        /* We should never get here. */
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Unsupported http_method.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
}

#ifdef HAVE_ECP
/* Build an IDPList whose members have an endpoint supporing
 * the protocol_type and http_method.
 */
static LassoNode *
am_get_idp_list(const LassoServer *server, LassoMdProtocolType protocol_type, LassoHttpMethod http_method)
{
    GList *idp_entity_ids = NULL;
    GList *entity_id = NULL;
    GList *idp_entries = NULL;
    LassoSamlp2IDPList *idp_list;
    LassoSamlp2IDPEntry *idp_entry;

    idp_list = LASSO_SAMLP2_IDP_LIST(lasso_samlp2_idp_list_new());

    idp_entity_ids =
        lasso_server_get_filtered_provider_list(server,
                                                LASSO_PROVIDER_ROLE_IDP,
                                                protocol_type, http_method);

    for (entity_id = g_list_first(idp_entity_ids); entity_id != NULL;
         entity_id = g_list_next(entity_id)) {
        idp_entry = LASSO_SAMLP2_IDP_ENTRY(lasso_samlp2_idp_entry_new());
        idp_entry->ProviderID = g_strdup(entity_id->data);

        /* RFE: we should have a mechanism to obtain these values */
        idp_entry->Name = NULL;
        idp_entry->Loc = NULL;

        idp_entries = g_list_append(idp_entries, idp_entry);
    }
    lasso_release_list_of_strings(idp_entity_ids);

    idp_list->IDPEntry = idp_entries;
    return LASSO_NODE(idp_list);
}

/* Send AuthnRequest using PAOS binding.
 *
 * Parameters:
 *  request_rec *r
 *
 * Returns:
 *  OK on success, or an error on failure.
 */
static int am_send_paos_authn_request(request_rec *r)
{
    gint ret;
    am_dir_cfg_rec *dir_cfg;
    LassoServer *server;
    LassoLogin *login;
    const char *relay_state = NULL;
    char *assertion_consumer_service_url;
    int is_passive = FALSE;

    dir_cfg = am_get_dir_cfg(r);

    server = am_get_lasso_server(r);
    if(server == NULL) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    relay_state = am_reconstruct_url(r);

    assertion_consumer_service_url =
        am_get_assertion_consumer_service_by_binding(LASSO_PROVIDER(server),
                                                     "PAOS");

    ret = am_init_authn_request_common(r, &login,
                                       NULL, LASSO_HTTP_METHOD_PAOS, NULL,
                                       assertion_consumer_service_url,
                                       relay_state, is_passive);
    g_free(assertion_consumer_service_url);

    if (ret != OK) {
        if (login) {
            lasso_login_destroy(login);
        }
        return ret;
    }

    if (CFG_VALUE(dir_cfg, ecp_send_idplist)) {
        lasso_profile_set_idp_list(LASSO_PROFILE(login),
                                   am_get_idp_list(LASSO_PROFILE(login)->server,
                                                   LASSO_MD_PROTOCOL_TYPE_SINGLE_SIGN_ON,
                                                   LASSO_HTTP_METHOD_SOAP));
    }

    ret = am_set_authn_request_content(r, login);
    lasso_login_destroy(login);

    return ret;
}
#endif /* HAVE_ECP */

/* Create and send an authentication request.
 *
 * Parameters:
 *  request_rec *r         The request we are processing.
 *  const char *idp        The entityID of the IdP.
 *  const char *return_to  The URL we should redirect to when receiving the request.
 *  int is_passive         The value of the IsPassive flag in <AuthnRequest>
 *
 * Returns:
 *  HTTP response code indicating success or failure.
 */
static int am_send_login_authn_request(request_rec *r, const char *idp,
                                 const char *return_to_url,
                                 int is_passive)
{
    int ret;
    LassoServer *server;
    LassoProvider *provider;
    LassoHttpMethod http_method;
    char *destination_url;
    char *assertion_consumer_service_url;
    LassoLogin *login;

    /* Add cookie for cookie test. We know that we should have
     * a valid cookie when we return from the IdP after SP-initiated
     * login.
     */
    am_cookie_set(r, "cookietest");

    server = am_get_lasso_server(r);
    if(server == NULL) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Find our IdP. */
    provider = lasso_server_get_provider(server, idp);
    if (provider == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Could not find metadata for the IdP \"%s\".",
                      idp);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Determine what binding and endpoint we should use when
     * sending the request.
     */
    http_method = LASSO_HTTP_METHOD_REDIRECT;
    destination_url = lasso_provider_get_metadata_one(
        provider, "SingleSignOnService HTTP-Redirect");
    if (destination_url == NULL) {
        /* HTTP-Redirect unsupported - try HTTP-POST. */
        http_method = LASSO_HTTP_METHOD_POST;
        destination_url = lasso_provider_get_metadata_one(
            provider, "SingleSignOnService HTTP-POST");
    }
    if (destination_url == NULL) {
        /* Both HTTP-Redirect and HTTP-POST unsupported - give up. */
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Could not find a supported SingleSignOnService endpoint"
                      " for the IdP \"%s\".", idp);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    assertion_consumer_service_url =
        lasso_provider_get_assertion_consumer_service_url(
            LASSO_PROVIDER(server), NULL);

    ret = am_init_authn_request_common(r, &login, idp, http_method,
                                       destination_url,
                                       assertion_consumer_service_url,
                                       return_to_url, is_passive);

    g_free(destination_url);
    g_free(assertion_consumer_service_url);

    if (ret != OK) {
        if (login) {
            lasso_login_destroy(login);
        }
        return ret;
    }

    ret = am_set_authn_request_content(r, login);
    lasso_login_destroy(login);

    return ret;
}


/* Handle the "auth" endpoint.
 *
 * This endpoint is included for backwards-compatibility.
 *
 * Parameters:
 *  request_rec *r       The request we received.
 *
 * Returns:
 *  OK or HTTP_SEE_OTHER on success, an error on failure.
 */
static int am_handle_auth(request_rec *r)
{
    am_dir_cfg_rec *cfg = am_get_dir_cfg(r);
    const char *relay_state;

    am_diag_printf(r, "enter function %s\n", __func__);

    relay_state = am_reconstruct_url(r);

    /* Check if IdP discovery is in use and no IdP was selected yet */
    if ((cfg->discovery_url != NULL) &&
        (am_extract_query_parameter(r->pool, r->args, "IdP") == NULL)) {
        return am_start_disco(r, relay_state);
    }

    /* If IdP discovery is in use and we have an IdP selected,
     * set the relay_state
     */
    if (cfg->discovery_url != NULL) {
        char *return_url;

        return_url = am_extract_query_parameter(r->pool, r->args, "ReturnTo");
        if ((return_url != NULL) && am_urldecode((char *)return_url) == 0)
            relay_state = return_url;
    }

    return am_send_login_authn_request(r, am_get_idp(r), relay_state, FALSE);
}

/* This function handles requests to the login handler.
 *
 * Parameters:
 *  request_rec *r       The request.
 *
 * Returns:
 *  OK on success, or an error if any of the steps fail.
 */
static int am_handle_login(request_rec *r)
{
    am_dir_cfg_rec *cfg = am_get_dir_cfg(r);
    char *idp_param;
    const char *idp;
    char *return_to;
    int is_passive;
    int ret;

    am_diag_printf(r, "enter function %s\n", __func__);

    return_to = am_extract_query_parameter(r->pool, r->args, "ReturnTo");
    if(return_to == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Missing required ReturnTo parameter.");
        return HTTP_BAD_REQUEST;
    }

    ret = am_urldecode(return_to);
    if(ret != OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error urldecoding ReturnTo parameter.");
        return ret;
    }

    ret = am_validate_redirect_url(r, return_to);
    if(ret != OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Invalid target domain in login request ReturnTo parameter.");
        return ret;
    }

    idp_param = am_extract_query_parameter(r->pool, r->args, "IdP");
    if(idp_param != NULL) {
        ret = am_urldecode(idp_param);
        if(ret != OK) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Error urldecoding IdP parameter.");
            return ret;
        }
    }

    ret = am_get_boolean_query_parameter(r, "IsPassive", &is_passive, FALSE);
    if (ret != OK) {
        return ret;
    }

    if(idp_param != NULL) {
        idp = idp_param;
    } else if(cfg->discovery_url) {
        if(is_passive) {
            /* We cannot currently do discovery with passive authentication requests. */
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Discovery service with passive authentication request unsupported.");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        return am_start_disco(r, return_to);
    } else {
        /* No discovery service -- just use the default IdP. */
        idp = am_get_idp(r);
    }

    return am_send_login_authn_request(r, idp, return_to, is_passive);
}

/* This function probes an URL (HTTP GET)
 *
 * Parameters:
 *  request_rec *r       The request.
 *  const char *url      The URL
 *  int timeout          Timeout in seconds
 *
 * Returns:
 *  OK on success, or an error if any of the steps fail.
 */
static int am_probe_url(request_rec *r, const char *url, int timeout)
{
    void *dontcare;
    apr_size_t len;
    long status;
    int error;

    status = 0;
    if ((error = am_httpclient_get(r, url, &dontcare, &len, 
                                   timeout, &status)) != OK)
        return error;

    if (status != HTTP_OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Probe on \"%s\" returned HTTP %ld",
                      url, status);
        return status;
    }

    return OK;
}

/* This function handles requests to the probe discovery handler
 *
 * Parameters:
 *  request_rec *r       The request.
 *
 * Returns:
 *  OK on success, or an error if any of the steps fail.
 */
static int am_handle_probe_discovery(request_rec *r) {
    am_dir_cfg_rec *cfg = am_get_dir_cfg(r);
    LassoServer *server;
    const char *disco_idp = NULL;
    int timeout;
    char *return_to;
    char *idp_param;
    char *redirect_url;
    int ret;

    am_diag_printf(r, "enter function %s\n", __func__);

    server = am_get_lasso_server(r);
    if(server == NULL) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * If built-in IdP discovery is not configured, return error.
     * For now we only have the get-metadata metadata method, so this
     * information is not saved in configuration nor it is checked here.
     */
    timeout = cfg->probe_discovery_timeout;
    if (timeout == -1) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "probe discovery handler invoked but not "
                      "configured. Please set MellonProbeDiscoveryTimeout.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * Check for mandatory arguments early to avoid sending 
     * probles for nothing.
     */
    return_to = am_extract_query_parameter(r->pool, r->args, "return");
    if(return_to == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Missing required return parameter.");
        return HTTP_BAD_REQUEST;
    }

    ret = am_urldecode(return_to);
    if (ret != OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, ret, r,
                      "Could not urldecode return value.");
        return HTTP_BAD_REQUEST;
    }

    ret = am_validate_redirect_url(r, return_to);
    if (ret != OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Invalid target domain in probe discovery return parameter.");
        return ret;
    }

    idp_param = am_extract_query_parameter(r->pool, r->args, "returnIDParam");
    if(idp_param == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Missing required returnIDParam parameter.");
        return HTTP_BAD_REQUEST;
    }

    ret = am_urldecode(idp_param);
    if (ret != OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, ret, r,
                      "Could not urldecode returnIDParam value.");
        return HTTP_BAD_REQUEST;
    }

    /*
     * Proceed with built-in IdP discovery. 
     *
     * First try sending probes to IdP configured for discovery.
     * Second send probes for all configured IdP
     * The first to answer is chosen.
     * If none answer, use the first configured IdP
     */
    if (!apr_is_empty_table(cfg->probe_discovery_idp)) {
        const apr_array_header_t *header;
        apr_table_entry_t *elts;
        const char *url;
        const char *idp;
        int i;

        header = apr_table_elts(cfg->probe_discovery_idp);
        elts = (apr_table_entry_t *)header->elts;

        for (i = 0; i < header->nelts; i++) { 
            idp = elts[i].key;
            url = elts[i].val;

            if (am_probe_url(r, url, timeout) == OK) {
                disco_idp = idp;
                break;
            }
        }
    } else {
        GList *iter;
        GList *idp_list;
        const char *idp;

        idp_list = g_hash_table_get_keys(server->providers);
        for (iter = idp_list; iter != NULL; iter = iter->next) {
            idp = iter->data;
    
            if (am_probe_url(r, idp, timeout) == OK) {
                disco_idp = idp;
                break;
            }
        }
        g_list_free(idp_list);
    }

    /* 
     * On failure, fail if a MellonProbeDiscoveryIdP
     * list was provided, otherwise try first IdP.
     */
    if (disco_idp == NULL) {
        if (!apr_is_empty_table(cfg->probe_discovery_idp)) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "probeDiscovery failed and non empty "
                          "MellonProbeDiscoveryIdP was provided.");
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        disco_idp = am_first_idp(r);
        if (disco_idp == NULL) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "probeDiscovery found no usable IdP.");
            return HTTP_INTERNAL_SERVER_ERROR;
        } else {
            AM_LOG_RERROR(APLOG_MARK, APLOG_WARNING, 0, r, "probeDiscovery "
                          "failed, trying default IdP %s", disco_idp); 
        }
    } else {
        AM_LOG_RERROR(APLOG_MARK, APLOG_INFO, 0, r,
                      "probeDiscovery using %s", disco_idp);
    }

    redirect_url = apr_psprintf(r->pool, "%s%s%s=%s", return_to, 
                                strchr(return_to, '?') ? "&" : "?",
                                am_urlencode(r->pool, idp_param), 
                                am_urlencode(r->pool, disco_idp));

    apr_table_setn(r->headers_out, "Location", redirect_url);

    return HTTP_SEE_OTHER;
}


/* This function handles responses to request on our endpoint
 *
 * Parameters:
 *  request_rec *r       The request we received.
 *
 * Returns:
 *  OK on success, or an error on failure.
 */
int am_handler(request_rec *r)
{
    am_dir_cfg_rec *cfg = am_get_dir_cfg(r);
#ifdef HAVE_ECP
    am_req_cfg_rec *req_cfg = am_get_req_cfg(r);
#endif /* HAVE_ECP */
    const char *endpoint;

    /*
     * Normally this content handler is used to dispatch to the SAML
     * endpoints implmented by mod_auth_mellon. SAML endpoint dispatch
     * occurs when the URI begins with the SAML endpoint path.
     *
     * However, this handler is also responsible for generating ECP
     * authn requests, in this case the URL will be a protected
     * resource we're doing authtentication for. Early in the request
     * processing pipeline we detected we were doing ECP authn and set
     * a flag on the request. Here we test for that flag and if true
     * respond with the ECP PAOS authn request.
     *
     * If the request is neither for a SAML endpoint nor one that
     * requires generating an ECP authn we decline handling the request.
     */

#ifdef HAVE_ECP
    if (req_cfg->ecp_authn_req) { /* Are we doing ECP? */
        return am_send_paos_authn_request(r);
    }
#endif /* HAVE_ECP */

    /* Check if this is a request for one of our endpoints. We check if
     * the uri starts with the path set with the MellonEndpointPath
     * configuration directive.
     */
    if(strstr(r->uri, cfg->endpoint_path) != r->uri)
        return DECLINED;

    endpoint = &r->uri[strlen(cfg->endpoint_path)];
    if (!strcmp(endpoint, "metadata")) {
        return am_handle_metadata(r);
    } else if (!strcmp(endpoint, "repost")) {
        return am_handle_repost(r);
    } else if(!strcmp(endpoint, "postResponse")) {
        return am_handle_post_reply(r);
    } else if(!strcmp(endpoint, "artifactResponse")) {
        return am_handle_artifact_reply(r);
    } else if(!strcmp(endpoint, "paosResponse")) {
        return am_handle_paos_reply(r);
    } else if(!strcmp(endpoint, "auth")) {
        return am_handle_auth(r);
    } else if(!strcmp(endpoint, "logout")
              || !strcmp(endpoint, "logoutRequest")) {
        /* logoutRequest is included for backwards-compatibility
         * with version 0.0.6 and older.
         */
        return am_handle_logout(r);
    } else if(!strcmp(endpoint, "login")) {
        return am_handle_login(r);
    } else if(!strcmp(endpoint, "probeDisco")) {
        return am_handle_probe_discovery(r);
    } else {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Endpoint \"%s\" not handled by mod_auth_mellon.",
                      endpoint);

        return HTTP_NOT_FOUND;
    }
}


/**
 * Trigger a login operation from a "normal" request.
 *
 * Parameters:
 *  request_rec *r       The request we received.
 *
 * Returns:
 *  HTTP_SEE_OTHER on success, or an error on failure.
 */
static int am_start_auth(request_rec *r)
{
    am_dir_cfg_rec *cfg = am_get_dir_cfg(r);
    const char *endpoint = am_get_endpoint_url(r);
    const char *return_to;
    const char *idp;
    const char *login_url;

    am_diag_printf(r, "enter function %s\n", __func__);

    return_to = am_reconstruct_url(r);

    /* If this is a POST request, attempt to save it */
    if (r->method_number == M_POST) {
        if (CFG_VALUE(cfg, post_replay)) {
            if (am_save_post(r, &return_to) != OK)
                return HTTP_INTERNAL_SERVER_ERROR;
        } else {
            AM_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "POST data dropped because we do not have a"
                          " MellonPostReplay is not enabled.");
        }
    }

    /* Check if IdP discovery is in use. */
    if (cfg->discovery_url) {
        return am_start_disco(r, return_to);
    }

    idp = am_get_idp(r);
    login_url = apr_psprintf(r->pool, "%slogin?ReturnTo=%s&IdP=%s",
                             endpoint,
                             am_urlencode(r->pool, return_to),
                             am_urlencode(r->pool, idp));
    AM_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "Redirecting to login URL: %s", login_url);

    apr_table_setn(r->headers_out, "Location", login_url);
    return HTTP_SEE_OTHER;
}

int am_auth_mellon_user(request_rec *r)
{
    am_dir_cfg_rec *dir = am_get_dir_cfg(r);
    int return_code = HTTP_UNAUTHORIZED;
    am_cache_entry_t *session;
    const char *ajax_header;

    if (r->main) {
        /* We are a subrequest. Trust the main request to have
         * performed the authentication.
         */
        return OK;
    }

    /* Check that the user has enabled authentication for this directory. */
    if(dir->enable_mellon == am_enable_off
       || dir->enable_mellon == am_enable_default) {
	return DECLINED;
    }

    am_diag_printf(r, "enter function %s\n", __func__);

    /* Set defaut Cache-Control headers within this location */
    if (CFG_VALUE(dir, send_cache_control_header)) {
        am_set_cache_control_headers(r);
    }

    /* Check if this is a request for one of our endpoints. We check if
     * the uri starts with the path set with the MellonEndpointPath
     * configuration directive.
     */
    if(strstr(r->uri, dir->endpoint_path) == r->uri) {
        /* No access control on our internal endpoints. */
        return OK;
    }

    /* Get the session of this request. */
    session = am_get_request_session(r);


    if(dir->enable_mellon == am_enable_auth) {
        /* This page requires the user to be authenticated and authorized. */

        if(session == NULL || !session->logged_in) {
            /* We don't have a valid session. */

            am_diag_printf(r, "%s am_enable_auth, no valid session\n",
                           __func__);

            if(session) {
                /* Release the session. */
                am_release_request_session(r, session);
            }

            /*
             * If this is an AJAX request, we cannot proceed to the IdP,
             * Just fail early to save our resources
             */
            ajax_header = apr_table_get(r->headers_in, "X-Request-With");
            if (ajax_header != NULL &&
                strcmp(ajax_header, "XMLHttpRequest") == 0) {
                    AM_LOG_RERROR(APLOG_MARK, APLOG_INFO, 0, r,
                      "Deny unauthenticated X-Request-With XMLHttpRequest "
                      "(AJAX) request");
                    return HTTP_FORBIDDEN;
            }

#ifdef HAVE_ECP
            /*
             * If PAOS set a flag on the request indicating we're
             * doing ECP and allow the request to proceed through the
             * request handlers until we reach am_handler which then
             * checks the flag and if True initiates an ECP transaction.
             * See am_check_uid for detailed explanation.
             */

            bool is_paos;
            int error_code;

            is_paos = am_is_paos_request(r, &error_code);
            if (error_code) return HTTP_BAD_REQUEST;
            if (is_paos) {
                am_req_cfg_rec *req_cfg;

                req_cfg = am_get_req_cfg(r);
                req_cfg->ecp_authn_req = true;

                return OK;

            } else {
                /* Send the user to the authentication page on the IdP. */
                return am_start_auth(r);
            }
#else /* HAVE_ECP */
            /* Send the user to the authentication page on the IdP. */
            return am_start_auth(r);
#endif /* HAVE_ECP */
        }

        am_diag_printf(r, "%s am_enable_auth, have valid session\n",
                       __func__);

        /* Verify that the user has access to this resource. */
        return_code = am_check_permissions(r, session);
        if(return_code != OK) {
            am_diag_printf(r, "%s failed am_check_permissions, status=%d\n",
                           __func__, return_code);
            am_release_request_session(r, session);

            return return_code;
        }


        /* The user has been authenticated, and we can now populate r->user
         * and the r->subprocess_env with values from the session store.
         */
        am_cache_env_populate(r, session);

        /* Release the session. */
        am_release_request_session(r, session);

        return OK;

    } else {
        /* dir->enable_mellon == am_enable_info:
         * We should pass information about the user to the web application
         * if the user is authorized to access this resource.
         * However, we shouldn't attempt to do any access control.
         */

        if(session != NULL
           && session->logged_in
           && am_check_permissions(r, session) == OK) {

            am_diag_printf(r, "%s am_enable_info, have valid session\n",
                           __func__);

            /* The user is authenticated and has access to the resource.
             * Now we populate the environment with information about
             * the user.
             */
            am_cache_env_populate(r, session);
        } else {
            am_diag_printf(r, "%s am_enable_info, no valid session\n",
                           __func__);
        }

        if(session != NULL) {
            /* Release the session. */
            am_release_request_session(r, session);
        }

        /* We shouldn't really do any access control, so we always return
         * DECLINED.
         */
        return DECLINED;
    }
}


int am_check_uid(request_rec *r)
{
    am_dir_cfg_rec *dir = am_get_dir_cfg(r);
    am_cache_entry_t *session;
    int return_code = HTTP_UNAUTHORIZED;

    if (r->main) {
        /* We are a subrequest. Trust the main request to have
         * performed the authentication.
         */
        if (r->main->user) {
            /* Make sure that the username from the main request is
             * available in the subrequest.
             */
            r->user = apr_pstrdup(r->pool, r->main->user);
        }
        return OK;
    }

    /* Check that the user has enabled authentication for this directory. */
    if(dir->enable_mellon == am_enable_off
       || dir->enable_mellon == am_enable_default) {
	return DECLINED;
    }

    am_diag_printf(r, "enter function %s\n", __func__);

#ifdef HAVE_ECP
    am_req_cfg_rec *req_cfg = am_get_req_cfg(r);
    if (req_cfg->ecp_authn_req) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "am_check_uid is performing ECP authn request flow");
        /*
         * Normally when a protected resource requires authentication
         * the request processing pipeline is exited early by
         * responding with either a 401 or a redirect. But the flow
         * for ECP is different, there will be a successful response
         * (200) but instead of the response body containing the
         * protected resource it will contain a SAML AuthnRequest
         * with the Content-Type indicating it's PAOS ECP.
         *
         * In order to return a 200 Success with a PAOS body we have
         * to reach the handler stage of the request processing
         * pipeline. But this is a protected resource and we won't
         * reach the handler stage unless authn and authz are
         * satisfied. Therefore we lie and return results which
         * indicate authn and authz are satisfied. This is OK because
         * we're not actually going to respond with the protected
         * resource, instead we'll be responsing with a SAML request.
         *
         * Apache's internal request logic
         * (ap_process_request_internal) requires that after a
         * successful return from the check_user_id authentication
         * hook the r->user value be non-NULL. This makes sense
         * because authentication establishes who the authenticated
         * principal is. But with ECP flow there is no authenticated
         * user at this point, we're just faking successful
         * authentication in order to reach the handler stage. To get
         * around this problem we set r-user to the empty string to
         * keep Apache happy, otherwise it would throw an
         * error. mod_shibboleth does the same thing.
         */
        r->user = "";
        return OK;
    }
#endif /* HAVE_ECP */

    /* Check if this is a request for one of our endpoints. We check if
     * the uri starts with the path set with the MellonEndpointPath
     * configuration directive.
     */
    if(strstr(r->uri, dir->endpoint_path) == r->uri) {
        /* No access control on our internal endpoints. */
        r->user = "";           /* see above explanation */
        return OK;
    }


    /* Get the session of this request. */
    session = am_get_request_session(r);

    /* If we don't have a session, then we can't authorize the user. */
    if(session == NULL) {
        am_diag_printf(r, "%s no session, return HTTP_UNAUTHORIZED\n",
                       __func__);
        return HTTP_UNAUTHORIZED;
    }

    /* If the user isn't logged in, then we can't authorize the user. */
    if(!session->logged_in) {
        am_diag_printf(r, "%s session not logged in,"
                       " return HTTP_UNAUTHORIZED\n", __func__);
        am_release_request_session(r, session);
        return HTTP_UNAUTHORIZED;
    }

    /* Verify that the user has access to this resource. */
    return_code = am_check_permissions(r, session);
    if(return_code != OK) {
        am_diag_printf(r, "%s failed am_check_permissions, status=%d\n",
                       __func__, return_code);
        am_release_request_session(r, session);
        return return_code;
    }

    /* The user has been authenticated, and we can now populate r->user
     *  and the r->subprocess_env with values from the session store.
     */
    am_cache_env_populate(r, session);

    /* Release the session. */
    am_release_request_session(r, session);

    return OK;
}
