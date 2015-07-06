/*
 *
 *   auth_mellon_cookie.c: an authentication apache module
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


/* This function retrieves the name of our cookie.
 *
 * Parameters:
 *  request_rec *r       The current request. Used to find the identifier of
 *                       the cookie. We also allocate memory from r->pool.
 *
 * Returns:
 *  The name of the cookie.
 */
static const char *am_cookie_name(request_rec *r)
{
    am_dir_cfg_rec *dir_cfg;

    dir_cfg = am_get_dir_cfg(r);

    return apr_pstrcat(r->pool, "mellon-", dir_cfg->varname, NULL);
}


/* Calculate the cookie parameters.
 *
 * Parameters:
 *  request_rec *r       The request we should set the cookie in.
 *
 * Returns:
 *  The cookie parameters as a string.
 */
static const char *am_cookie_params(request_rec *r)
{
    int secure_cookie;
    const char *cookie_domain = ap_get_server_name(r);
    const char *cookie_path = "/";
    am_dir_cfg_rec *cfg = am_get_dir_cfg(r);

    if (cfg->cookie_domain) {
        cookie_domain = cfg->cookie_domain;
    }

    if (cfg->cookie_path) {
        cookie_path = cfg->cookie_path;
    }

    secure_cookie = cfg->secure;

    return apr_psprintf(r->pool,
                        "Version=1; Path=%s; Domain=%s%s;",
                        cookie_path, cookie_domain,
                        secure_cookie ? "; HttpOnly; secure" : "");
}


/* This functions finds the value of our cookie.
 *
 * Parameters:
 *  request_rec *r       The request we should find the cookie in.
 *
 * Returns:
 *  The value of the cookie, or NULL if we don't find the cookie.
 */
const char *am_cookie_get(request_rec *r)
{
    am_req_cfg_rec *req_cfg;
    const char *name;
    const char *value;
    const char *cookie;
    char *buffer, *end;

    /* don't run for subrequests */
    if (r->main) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "cookie_get: Subrequest, so return NULL");        
        return NULL;
    }

    /* Check if we have added a note on the current request. */
    req_cfg = am_get_req_cfg(r);
    value = req_cfg->cookie_value;
    if(value != NULL) {
        return value;
    }


    name = am_cookie_name(r);

    cookie = apr_table_get(r->headers_in, "Cookie");
    if(cookie == NULL) {
        return NULL;
    }

    for(value = ap_strstr_c(cookie, name); value != NULL;
        value = ap_strstr_c(value + 1, name)) {

        if(value != cookie) {
            /* value isn't pointing to the start of the string. */
            switch(value[-1]) {
                /* We allow the name in the cookie-string to be
                 * preceeded by [\t; ]. Note that only ' ' should be used
                 * by browsers. We test against the others just to be sure.
                 */
            case '\t':
            case ';':
            case ' ':
                break;
            default:
                /* value isn't preceeded by one of the listed characters, and
                 * therefore we assume that it is part of another cookie.
                 */
                continue; /* Search for the next instance of the name. */
            }
        }

        if(value[strlen(name)] != '=') {
            /* We don't have an equal-sign right after the name. Therefore we
             * assume that what we have matched is only part of a longer name.
             * We continue searching.
             */
            continue;
        }

        /* Now we have something that matches /[^ ,\t]<name>=/. The value
         * (following the equal-sign) can be found at value + strlen(name) + 1.
         */
        value += strlen(name) + 1;

        /* The cookie value may be double-quoted. */
        if(*value == '"') {
            value += 1;
        }

        buffer = apr_pstrdup(r->pool, value);
        end = strchr(buffer, '"');
        if(end) {
            /* Double-quoted string. */
            *end = '\0';
        }
        end = strchr(buffer, ';');
        if(end) {
            *end = '\0';
        }

        return buffer;
    }

    /* We didn't find the cookie. */
    return NULL;
}


/* This function sets the value of our cookie.
 *
 * Parameters:
 *  request_rec *r       The request we should set the cookie in.
 *  const char *id       The value ve should store in the cookie.
 *
 * Returns:
 *  Nothing.
 */
void am_cookie_set(request_rec *r, const char *id)
{
    am_req_cfg_rec *req_cfg;
    const char *name;
    const char *cookie_params;
    char *cookie;

    if (id == NULL)
        return;

    name = am_cookie_name(r);
    cookie_params = am_cookie_params(r);

    cookie = apr_psprintf(r->pool, "%s=%s; %s", name, id, cookie_params);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "cookie_set: %s", cookie);

    /* Setting the headers inn err_headers_out ensures that they will be
     * sent for all responses.
     */
    apr_table_addn(r->err_headers_out, "Set-Cookie", cookie);

    /* Add a note on the current request, to allow us to retrieve this
     * cookie in the current request.
     */
    req_cfg = am_get_req_cfg(r);
    req_cfg->cookie_value = apr_pstrdup(r->pool, id);
}


/* This function deletes the cookie.
 *
 * Parameters:
 *  request_rec *r       The request we should clear the cookie in. We will
 *                       allocate any neccesary memory from r->pool.
 *
 * Returns:
 *  Nothing.
 */
void am_cookie_delete(request_rec *r)
{
    const char *name;
    const char *cookie_params;
    char *cookie;

    name = am_cookie_name(r);
    cookie_params = am_cookie_params(r);


    /* Format a cookie. To delete a cookie we set the expires-timestamp
     * to the past.
     */
    cookie = apr_psprintf(r->pool, "%s=NULL;"
                          " expires=Thu, 01-Jan-1970 00:00:00 GMT;"
                          " %s",
                          name, cookie_params);

    apr_table_addn(r->err_headers_out, "Set-Cookie", cookie);
}
