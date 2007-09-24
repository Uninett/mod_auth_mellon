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


static LassoServer *am_get_lasso_server(request_rec *r)
{
    am_dir_cfg_rec *cfg;
    gint ret;

    cfg = am_get_dir_cfg(r);

    apr_thread_mutex_lock(cfg->server_mutex);
    if(cfg->server == NULL) {
        cfg->server = lasso_server_new(cfg->sp_metadata_file,
				       cfg->sp_private_key_file,
				       NULL, NULL);
        if(cfg->server == NULL) {
	    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			  "Error initializing lasso server object. Please"
			  " verify the following configuration directives:"
			  " MellonSPMetadataFile and MellonSPPrivateKeyFile.");

	    apr_thread_mutex_unlock(cfg->server_mutex);
	    return NULL;
	}

      
	ret = lasso_server_add_provider(cfg->server, LASSO_PROVIDER_ROLE_IDP,
					cfg->idp_metadata_file,
					cfg->idp_public_key_file, NULL);
	if(ret != 0) {
	    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			  "Error adding IdP to lasso server object. Please"
			  " verify the following configuration directives:"
			  " MellonIdPMetadataFile and"
                          " MellonIdPPublicKeyFile.");

	    lasso_server_destroy(cfg->server);
	    cfg->server = NULL;

	    apr_thread_mutex_unlock(cfg->server_mutex);
	    return NULL;
	}
    }

    apr_thread_mutex_unlock(cfg->server_mutex);

    return cfg->server;
}


/* This function stores dumps of the LassoIdentity and LassoSession objects
 * for the given LassoProfile object. The dumps are stored in the session
 * belonging to the current request.
 *
 * Parameters:
 *  request_rec *r         The current request.
 *  LassoProfile *profile  The profile object.
 *
 * Returns:
 *  OK on success or HTTP_INTERNAL_SERVER_ERROR on failure.
 */
static int am_save_lasso_profile_state(request_rec *r, LassoProfile *profile)
{
    am_cache_entry_t *am_session;
    LassoIdentity *lasso_identity;
    LassoSession *lasso_session;
    gchar *identity_dump;
    gchar *session_dump;
    int ret;

    lasso_identity = lasso_profile_get_identity(profile);
    if(lasso_identity == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "The current LassoProfile object doesn't contain a"
                      " LassoIdentity object.");
        identity_dump = NULL;
    } else {
        identity_dump = lasso_identity_dump(lasso_identity);
        if(identity_dump == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Could not create a identity dump from the"
                          " LassoIdentity object.");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    lasso_session = lasso_profile_get_session(profile);
    if(lasso_session == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "The current LassoProfile object doesn't contain a"
                      " LassoSession object.");
        session_dump = NULL;
    } else {
        session_dump = lasso_session_dump(lasso_session);
        if(session_dump == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Could not create a session dump from the"
                          " LassoSession object.");
            if(identity_dump != NULL) {
                g_free(identity_dump);
            }
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }


    am_session = am_get_request_session(r);
    if(am_session == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Could not get auth_mellon session while attempting"
                      " to store the lasso profile state.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Save the profile state. */
    ret = am_cache_set_lasso_state(am_session, identity_dump, session_dump);

    am_release_request_session(r, am_session);


    if(identity_dump != NULL) {
        g_free(identity_dump);
    }

    if(session_dump != NULL) {
        g_free(session_dump);
    }

    return ret;
}


/* This function restores dumps of a LassoIdentity object and a LassoSession
 * object. The dumps are fetched from the session belonging to the current
 * request and restored to the given LassoProfile object.
 *
 * Parameters:
 *  request_rec *r         The current request.
 *  LassoProfile *profile  The profile object.
 *
 * Returns:
 *  OK on success or HTTP_INTERNAL_SERVER_ERROR on failure.
 */
static int am_restore_lasso_profile_state(request_rec *r,
                                          LassoProfile *profile)
{
    am_cache_entry_t *am_session;
    const char *identity_dump;
    const char *session_dump;
    int rc;


    am_session = am_get_request_session(r);
    if(am_session == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Could not get auth_mellon session while attempting"
                      " to restore the lasso profile state.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    identity_dump = am_cache_get_lasso_identity(am_session);
    if(identity_dump != NULL) {
        rc = lasso_profile_set_identity_from_dump(profile, identity_dump);
        if(rc < 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Could not restore identity from dump."
                          " Lasso error: [%i] %s", rc, lasso_strerror(rc));
            am_release_request_session(r, am_session);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    session_dump = am_cache_get_lasso_session(am_session);
    if(session_dump != NULL) {
        rc = lasso_profile_set_session_from_dump(profile, session_dump);
        if(rc < 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Could not restore session from dump."
                          " Lasso error: [%i] %s", rc, lasso_strerror(rc));
            am_release_request_session(r, am_session);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    am_release_request_session(r, am_session);

    return OK;
}


/* This function handles an IdP initiated logout request.
 *
 * Parameters:
 *  request_rec *r       The logout request.
 *
 * Returns:
 *  OK on success, or an error if any of the steps fail.
 */
static int am_handle_logout_request(request_rec *r)
{
    LassoServer *server;
    LassoLogout *logout;
    gint res;
    am_cache_entry_t *session;

    server = am_get_lasso_server(r);
    if(server == NULL) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    logout = lasso_logout_new(server);
    if(logout == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error creating lasso logout object.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Restore lasso profile state. We ignore errors since we want to be able
     * to redirect the user back to the IdP even in the case of an error.
     */
    am_restore_lasso_profile_state(r, LASSO_PROFILE(logout));

    /* Process the logout message. Ignore missing signature. */
    res = lasso_logout_process_request_msg(logout, r->args);
    if(res != 0 && res != LASSO_DS_ERROR_SIGNATURE_NOT_FOUND) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error processing logout request message."
                      " Lasso error: [%i] %s", res, lasso_strerror(res));

        lasso_logout_destroy(logout);
        return HTTP_BAD_REQUEST;
    }

    /* Validate the logout message. Ignore missing signature. */
    res = lasso_logout_validate_request(logout);
    if(res != 0 && res != LASSO_DS_ERROR_SIGNATURE_NOT_FOUND) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                      "Error validating logout request."
                      " Lasso error: [%i] %s", res, lasso_strerror(res));
        /* We continue with the logout despite the error. A error could be
         * caused by the IdP believing that we are logged in when we are not.
         */
    }


    /* Delete the session. */
    session = am_get_request_session(r);
    if(session != NULL) {
        am_delete_request_session(r, session);
    }


    /* Create response message. */
    res = lasso_logout_build_response_msg(logout);
    if(res != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error building logout response message."
                      " Lasso error: [%i] %s", res, lasso_strerror(res));

        lasso_logout_destroy(logout);
        return HTTP_INTERNAL_SERVER_ERROR;
    }


    /* Set redirect target. */
    apr_table_setn(r->headers_out, "Location",
		   apr_pstrdup(r->pool, LASSO_PROFILE(logout)->msg_url));

    lasso_logout_destroy(logout);

    /* HTTP_SEE_OTHER is a redirect where post-data isn't sent to the
     * new target.
     */
    return HTTP_SEE_OTHER;
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
    int i;
    char c;
    const char *expected;
    apr_time_exp_t time_exp;
    apr_time_t res;
    apr_status_t rc;

    /* Verify length of timestamp. */
    if(strlen(timestamp) != 20){
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                      "Invalid length of timestamp: \"%s\".", timestamp);
    }

    /* Verify components of timestamp. */
    for(i = 0; i < 20; i++) {
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
            /* Matches "                   Z" */
            if(c != 'Z') {
                expected = "'Z'";
            }
            break;

        default:
            /* Matches "YYYY MM DD hh mm ss " */
            if(c < '0' || c > '9') {
                expected = "a digit";
            }
            break;
        }

        if(expected != NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Invalid character in timestamp at position %i."
                          " Expected %s, got '%c'. Full timestamp: \"%s\"",
                          i, expected, c, timestamp);
            return 0;
        }
    }

    time_exp.tm_usec = 0;
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
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r,
                      "Error converting timestamp \"%s\".",
                      timestamp);
        return 0;
    }

    return res;
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
static void am_handle_condition(request_rec *r, am_cache_entry_t *session,
                                LassoSaml2Assertion *assertion)
{
    const char *not_on_or_after;
    apr_time_t t;


    /* Find timestamp. */

    if(assertion->Conditions == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                      "Did not receive conditions for an assertion.");
        return;
    }

    not_on_or_after = assertion->Conditions->NotOnOrAfter;

    if(not_on_or_after == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                      "Condition without NotOnOrAfter attribute.");
        return;
    }

    /* Parse timestamp. */
    t = am_parse_timestamp(r, not_on_or_after);
    if(t == 0) {
        return;
    }

    /* Updates the expires timestamp if this one is earlier than the
     * previous timestamp.
     */
    am_cache_update_expires(session, t);
}


/* This function is for decoding and storing attributes with the feide
 * encoding. It takes in an attribute name and a value. The value is split
 * into multiple values. We base64 decode these values, and store them in the
 * session data.
 *
 * Parameters:
 *  request_rec *r              The current request.
 *  am_cache_entry_t *session   The current session.
 *  const char *name            Name of the attribute.
 *  const char *value           The value(s) of the attribute.
 *
 * Returns:
 *  OK on success or an error from am_cache_env_append(...) if it was unable
 *  to store the attribute.
 */
static int am_store_attribute_feide(request_rec *r, am_cache_entry_t *session,
                                    const char *name, const char *value)
{
    char *edit_value;
    char *start; 
    char *next;
    int len;
    int ret;

    /* We need to be able to change the value. */
    edit_value = apr_pstrdup(r->pool, value);

    for(start = edit_value; start != NULL; start = next) {
        /* The values are separated by '_'. */
        next = strchr(start, '_');

        if(next != NULL) {
            /* Insert null-terminator after current value. */
            *next = '\0';

            /* The next value begins at next+1. */
            next++;
        }

        /* Now start points to the current value, which we have
         * null-terminated. next points to the next value, or NULL if
         * this is the last value.
         */

        /* base64-decode current value.
         * From looking at the source of apr_base64_decode_binary, it
         * appears to be safe to use in-place.
         */
        len = apr_base64_decode_binary((unsigned char *)start, start);

        /* Add null-terminator at end of string. */
        start[len] = '\0';


        /* Store current name-value-pair. */
        ret = am_cache_env_append(session, name, start);
        if(ret != OK) {
            return ret;
        }
    }

    return OK;
}


/* This function is for storing attributes without any encoding. We just store
 * the attribute as it is.
 *
 * Parameters:
 *  request_rec *r              The current request.
 *  am_cache_entry_t *session   The current session.
 *  const char *name            The name of the attribute.
 *  const char *value           The value of the attribute.
 *
 * Returns:
 *  OK on success or an error from am_cache_env_append(...) if it failed.
 */
static int am_store_attribute_none(request_rec *r, am_cache_entry_t *session,
                                   const char *name, const char *value)
{
    /* Store current name-value-pair. */
    return am_cache_env_append(session, name, value);
}


/* This function passes a name-value pair to the decoder selected by the
 * MellonDecoder configuration option. The decoder will decode the value
 * and store it in the session data.
 *
 * Parameters:
 *  request_rec *r              The current request.
 *  am_cache_entry_t *session   The current session.
 *  const char *name            The name of the attribute.
 *  const char *value           The value of the attribute.
 *
 * Returns:
 *  OK on success or an error from the attribute decoder if it failed.
 */
static int am_store_attribute(request_rec *r, am_cache_entry_t *session,
                              const char *name, const char *value)
{
    am_dir_cfg_rec *dir_cfg;

    dir_cfg = am_get_dir_cfg(r);

    switch(dir_cfg->decoder) {
    case am_decoder_none:
        return am_store_attribute_none(r, session, name, value);

    case am_decoder_feide:
        return am_store_attribute_feide(r, session, name, value);

    default:
        return am_store_attribute_none(r, session, name, value);
    }
}


/* This function iterates over a list of assertion elements, and adds all the
 * attributes it finds to the session data for the current user.
 *
 * Parameters:
 *  request_rec *r       The current request.
 *  const char *name_id  The name identifier we received from the IdP.
 *  GList *assertions    A list of LassoSaml2Assertion objects.
 *
 * Returns:
 *  HTTP_BAD_REQUEST if we couldn't find the session id of the user, or
 *  OK if no error occured.
 */
static int add_attributes(request_rec *r, const char *name_id,
                          GList *assertions)
{
    am_dir_cfg_rec *dir_cfg;
    am_cache_entry_t *session;
    GList *asrt_itr;
    LassoSaml2Assertion *assertion;
    GList *atr_stmt_itr;
    LassoSaml2AttributeStatement *atr_stmt;
    GList *atr_itr;
    LassoSaml2Attribute *attribute;
    GList *value_itr;
    LassoSaml2AttributeValue *value;
    LassoMiscTextNode *value_text;
    int ret;

    dir_cfg = am_get_dir_cfg(r);

    /* Get the session this request belongs to. */
    session = am_get_request_session(r);
    if(session == NULL) {
        if(am_cookie_get(r) == NULL) {
            /* Missing cookie. */
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "User has disabled cookies, or has lost"
                          " the cookie before returning from the SAML2"
                          " login server.");
            if(dir_cfg->no_cookie_error_page != NULL) {
                apr_table_setn(r->headers_out, "Location",
                               dir_cfg->no_cookie_error_page);
                return HTTP_SEE_OTHER;
            } else {
                /* Return 400 Bad Request when the user hasn't set a
                 * no-cookie error page.
                 */
                return HTTP_BAD_REQUEST;
            }
        } else {
            /* Missing session data. */
            ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                          "User has returned from the IdP with a session"
                          " id we can't locate in the table. This may be"
                          " caused by the MellonCacheSize being set to"
                          " low.");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* Set expires to whatever is set by MellonSessionLength. */
    if(dir_cfg->session_length == -1) {
        /* -1 means "use default. The current default is 86400 seconds. */
        am_cache_update_expires(session, apr_time_now()
                                + apr_time_make(86400, 0));
    } else {
        am_cache_update_expires(session, apr_time_now()
                                + apr_time_make(dir_cfg->session_length, 0));
    }

    /* Mark user as logged in. */
    session->logged_in = 1;

    /* Save session information. */
    ret = am_cache_env_append(session, "NAME_ID", name_id);
    if(ret != OK) {
        am_release_request_session(r, session);
        return ret;
    }

    /* assertions is a list of LassoSaml2Assertion objects. */
    for(asrt_itr = g_list_first(assertions); asrt_itr != NULL;
        asrt_itr = g_list_next(asrt_itr)) {

        assertion = LASSO_SAML2_ASSERTION(asrt_itr->data);

        /* Update expires timestamp of session. */
        am_handle_condition(r, session, assertion);

        /* assertion->AttributeStatement is a list of
         * LassoSaml2AttributeStatement objects.
         */
        for(atr_stmt_itr = g_list_first(assertion->AttributeStatement);
            atr_stmt_itr != NULL;
            atr_stmt_itr = g_list_next(atr_stmt_itr)) {

            atr_stmt = LASSO_SAML2_ATTRIBUTE_STATEMENT(atr_stmt_itr->data);

            /* atr_stmt->Attribute is list of LassoSaml2Attribute objects. */
            for(atr_itr = g_list_first(atr_stmt->Attribute);
                atr_itr != NULL;
                atr_itr = g_list_next(atr_itr)) {

                attribute = LASSO_SAML2_ATTRIBUTE(atr_itr->data);

                /* attribute->AttributeValue is a list of
                 * LassoSaml2AttributeValue objects.
                 */
                for(value_itr = g_list_first(attribute->AttributeValue);
                    value_itr != NULL;
                    value_itr = g_list_next(value_itr)) {

                    value = LASSO_SAML2_ATTRIBUTE_VALUE(
                        attribute->AttributeValue->data
                        );

                    /* value->any is a list with the child nodes of the
                     * AttributeValue element.
                     *
                     * We assume that the list contains a single text node.
                     */
                    if(value->any == NULL) {
                        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                                      "AttributeValue element was empty.");
                        continue;
                    }

                    /* Verify that this is a LassoMiscTextNode object. */
                    if(!LASSO_IS_MISC_TEXT_NODE(value->any->data)) {
                        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                                      "AttributeValue element contained an "
                                      " element which wasn't a text node.");
                        continue;
                    }

                    value_text = LASSO_MISC_TEXT_NODE(value->any->data);


                    /* Decode and save the attribute. */
                    ret = am_store_attribute(r, session, attribute->Name,
                                             value_text->content);
                    if(ret != OK) {
                        am_release_request_session(r, session);
                        return ret;
                    }
                }
            }
        }

        /* TODO: lasso only verifies the signature on the _first_ asserion
         * element. Therefore we can't trust any of following assertions.
         * If the Response-element is signed then we can trust all the
         * assertions, but we have no way to find what element is signed.
         */
        break;
    }

    am_release_request_session(r, session);

    return OK;
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
 *
 * Returns:
 *  A HTTP status code which should be returned to the client.
 */
static int am_handle_reply_common(request_rec *r, LassoLogin *login,
                                  char *relay_state)
{
    const char *name_id;
    GList *assertions;
    int rc;

    if(LASSO_PROFILE(login)->nameIdentifier == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "No acceptable name identifier found in"
                      " SAML 2.0 response.");
        lasso_login_destroy(login);
        return HTTP_BAD_REQUEST;
    }

    name_id = LASSO_SAML2_NAME_ID(LASSO_PROFILE(login)->nameIdentifier)
        ->content;

    assertions = LASSO_SAMLP2_RESPONSE(LASSO_PROFILE(login)->response)
        ->Assertion;


    rc = add_attributes(r, name_id, assertions);
    if(rc != OK) {
        lasso_login_destroy(login);
        return rc;
    }

    rc = lasso_login_accept_sso(login);
    if(rc < 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Unable to accept SSO message."
                      " Lasso error: [%i] %s", rc, lasso_strerror(rc));
        lasso_login_destroy(login);
        return HTTP_INTERNAL_SERVER_ERROR;
    }


    /* Save the profile state. */
    rc = am_save_lasso_profile_state(r, LASSO_PROFILE(login));
    if(rc != OK) {
        lasso_login_destroy(login);
        return rc;
    }

    lasso_login_destroy(login);


    /* No RelayState - we don't know what to do. */
    if(relay_state == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "RelayState wasn't included in reply from IdP.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = am_urldecode(relay_state);
    if (rc != OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r,
                      "Could not urldecode RelayState value.");
        return HTTP_BAD_REQUEST;
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

    /* Make sure that this is a POST request. */
    if(r->method_number != M_POST) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Exptected POST request for HTTP-POST endpoint."
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
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r,
                      "Error reading POST data.");
        return rc;
    }

    /* Extract the SAMLResponse-field from the data. */
    saml_response = am_extract_query_parameter(r->pool, post_data,
                                            "SAMLResponse");
    if (saml_response == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r,
                      "Could not find SAMLResponse field in POST data.");
        return HTTP_BAD_REQUEST;
    }

    rc = am_urldecode(saml_response);
    if (rc != OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r,
                      "Could not urldecode SAMLResponse value.");
        return rc;
    }

    server = am_get_lasso_server(r);
    if(server == NULL) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    login = lasso_login_new(server);
    if (login == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to initialize LassoLogin object.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Process login responce. */
    rc = lasso_login_process_authn_response_msg(login, saml_response);
    if (rc != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error processing authn response."
                      " Lasso error: [%i] %s", rc, lasso_strerror(rc));

        lasso_login_destroy(login);
        return HTTP_BAD_REQUEST;
    }

    /* Extract RelayState parameter. */
    relay_state = am_extract_query_parameter(r->pool, post_data,
                                               "RelayState");

    /* Finish handling the reply with the common handler. */
    return am_handle_reply_common(r, login, relay_state);
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

    /* Make sure that this is a GET request. */
    if(r->method_number != M_GET) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Exptected GET request for the HTTP-Artifact endpoint."
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
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to initialize LassoLogin object.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Parse artifact url. */
    rc = lasso_login_init_request(login, r->args,
                                  LASSO_HTTP_METHOD_ARTIFACT_GET);
    if(rc < 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to handle login response."
                      " Lasso error: [%i] %s", rc, lasso_strerror(rc));
        lasso_login_destroy(login);
        return HTTP_BAD_REQUEST;
    }

    /* Prepare SOAP request. */
    rc = lasso_login_build_request_msg(login);
    if(rc < 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
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
    if(rc != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to handle HTTP-Artifact response data."
                      " Lasso error: [%i] %s", rc, lasso_strerror(rc));
        lasso_login_destroy(login);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Extract the RelayState parameter. */
    relay_state = am_extract_query_parameter(r->pool, r->args,
                                               "RelayState");

    /* Finish handling the reply with the common handler. */
    return am_handle_reply_common(r, login, relay_state);
}


/* This function takes a request for an endpoint and passes it on to the
 * correct handler function.
 *
 * Parameters:
 *  request_rec *r       The request we are currently handling.
 *
 * Returns:
 *  The return value of the endpoint handler function,
 *  or HTTP_NOT_FOUND if we don't have a handler for the requested
 *  endpoint.
 */
static int am_endpoint_handler(request_rec *r)
{
    const char *endpoint;
    am_dir_cfg_rec *dir = am_get_dir_cfg(r);

    /* r->uri starts with cfg->endpoint_path, so we can find the endpoint
     * by extracting the string following chf->endpoint_path.
     */
    endpoint = &r->uri[strlen(dir->endpoint_path)];


    if(!strcmp(endpoint, "postResponse")) {
	return am_handle_post_reply(r);
    } else if(!strcmp(endpoint, "artifactResponse")) {
        return am_handle_artifact_reply(r);
    } else if(!strcmp(endpoint, "logoutRequest")) {
	return am_handle_logout_request(r);
    } else {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		      "Endpoint \"%s\" not handled by mod_auth_mellon.",
		      endpoint);

	return HTTP_NOT_FOUND;
    }
    
}


static int am_auth_new_ticket(request_rec *r)
{
    LassoServer *server;
    LassoLogin *login;
    LassoSamlp2AuthnRequest *request;
    gint ret;
    char *redirect_to;

    /* Create session. */
    am_release_request_session(r, am_new_request_session(r));


    server = am_get_lasso_server(r);
    if(server == NULL) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    login = lasso_login_new(server);
    if(login == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		      "Error creating LassoLogin object from LassoServer.");
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    ret = lasso_login_init_authn_request(login, NULL,
					 LASSO_HTTP_METHOD_REDIRECT);
    if(ret != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error creating login request."
                      " Lasso error: [%i] %s", ret, lasso_strerror(ret));
	lasso_login_destroy(login);
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    request = LASSO_SAMLP2_AUTHN_REQUEST(LASSO_PROFILE(login)->request);

    request->ForceAuthn = FALSE;
    request->IsPassive = FALSE;

    request->NameIDPolicy->Format
      = g_strdup(LASSO_SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT);

    request->NameIDPolicy->AllowCreate = TRUE;

    LASSO_SAMLP2_REQUEST_ABSTRACT(request)->Consent
      = g_strdup(LASSO_SAML2_CONSENT_IMPLICIT);

    LASSO_PROFILE(login)->msg_relayState = g_strdup(am_reconstruct_url(r));

    ret = lasso_login_build_authn_request_msg(login);
    if(ret != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error building login request."
                      " Lasso error: [%i] %s", ret, lasso_strerror(ret));
	lasso_login_destroy(login);
	return HTTP_INTERNAL_SERVER_ERROR;
    }


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

    lasso_login_destroy(login);

    /* We don't want to include POST data (in case this was a POST request). */
    return HTTP_SEE_OTHER;
}


int am_auth_mellon_user(request_rec *r)
{
    am_dir_cfg_rec *dir = am_get_dir_cfg(r);
    int return_code = HTTP_UNAUTHORIZED;
    am_cache_entry_t *session;

    /* check if we are a subrequest.  if we are, then just return OK
     * without any checking since these cannot be injected (heh). */
    if (r->main)
        return OK;

    /* Check that the user has enabled authentication for this directory. */
    if(dir->enable_mellon == am_enable_off
       || dir->enable_mellon == am_enable_default) {
	return DECLINED;
    }


    /* Disable all caching within this location. */
    am_set_nocache(r);

    /* Check if this is a request for one of our endpoints. We check if
     * the uri starts with the path set with the MellonEndpointPath
     * configuration directive.
     */
    if(strstr(r->uri, dir->endpoint_path) == r->uri) {
        return am_endpoint_handler(r);
    }

    /* Get the session of this request. */
    session = am_get_request_session(r);


    if(dir->enable_mellon == am_enable_auth) {
        /* This page requires the user to be authenticated and authorized. */

        if(session == NULL || !session->logged_in) {
            /* We don't have a valid session. */

            if(session) {
                /* Release the session. */
                am_release_request_session(r, session);
            }

            /* Send the user to the authentication page on the IdP. */
            return am_auth_new_ticket(r);
        }

        /* Verify that the user has access to this resource. */
        return_code = am_check_permissions(r, session);
        if(return_code != OK) {
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

            /* The user is authenticated and has access to the resource.
             * Now we populate the environment with information about
             * the user.
             */
            am_cache_env_populate(r, session);
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
    am_cache_entry_t *session;
    int return_code = HTTP_UNAUTHORIZED;

    /* check if we are a subrequest.  if we are, then just return OK
     * without any checking since these cannot be injected (heh). */
    if (r->main)
        return OK;


    /* Get the session of this request. */
    session = am_get_request_session(r);

    /* If we don't have a session, then we can't authorize the user. */
    if(session == NULL) {
        return HTTP_UNAUTHORIZED;
    }

    /* If the user isn't logged in, then we can't authorize the user. */
    if(!session->logged_in) {
        return HTTP_UNAUTHORIZED;
    }

    /* Verify that the user has access to this resource. */
    return_code = am_check_permissions(r, session);
    if(return_code != OK) {
        am_release_request_session(r, session);
        return HTTP_UNAUTHORIZED;
    }

    /* The user has been authenticated, and we can now populate r->user
     *  and the r->subprocess_env with values from the session store.
     */
    am_cache_env_populate(r, session);

    /* Release the session. */
    am_release_request_session(r, session);

    return OK;
}
