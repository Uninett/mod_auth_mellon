/*
 *
 *   auth_mellon_session.c: an authentication apache module
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

/* Retrieve a session from the cache and validate its cookie settings
 *
 * Parameters:
 *  request_rec *r       The request we received from the user.
 *  am_cache_key_t type  AM_CACHE_SESSION or AM_CACHE_NAMEID
 *  const char *key      The session key or user
 *
 * Returns:
 *  The session associated, or NULL if unable to retrieve the given session.
 */
am_cache_entry_t *am_lock_and_validate(request_rec *r,
                                       am_cache_key_t type,
                                       const char *key)
{
    am_cache_entry_t *session = NULL;

    am_diag_printf(r, "searching for session with key %s (%s) ... ",
                   key, am_diag_cache_key_type_str(type));

    session = am_cache_lock(r, type, key);
    if (session == NULL) {
        am_diag_printf(r, "not found\n");
        return NULL;
    } else {
        am_diag_printf(r, "found.\n");
        am_diag_log_cache_entry(r, 0, session, "Session Cache Entry");
    }

    const char *cookie_token_session = am_cache_entry_get_string(
        session, &session->cookie_token);
    const char *cookie_token_target = am_cookie_token(r);
    if (strcmp(cookie_token_session, cookie_token_target)) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Session cookie parameter mismatch. "
                      "Session created with {%s}, but current "
                      "request has {%s}.",
                      cookie_token_session,
                      cookie_token_target);
        am_cache_unlock(r, session);
        return NULL;
    }

    return session;
}

/* This function gets the session associated with a user, using a cookie
 *
 * Parameters:
 *  request_rec *r       The request we received from the user.
 *
 * Returns:
 *  The session associated with the user who places the request, or
 *  NULL if we don't have a session yet.
 */
am_cache_entry_t *am_get_request_session(request_rec *r)
{
    const char *session_id;

    /* Get session id from cookie. */
    session_id = am_cookie_get(r);
    if(session_id == NULL) {
        /* Cookie is unset - we don't have a session. */
        return NULL;
    }

    return am_lock_and_validate(r, AM_CACHE_SESSION, session_id);
}

/* This function gets the session associated with a user, using a NameID
 *
 * Parameters:
 *  request_rec *r       The request we received from the user.
 *  char *nameid         The NameID
 *
 * Returns:
 *  The session associated with the user who places the request, or
 *  NULL if we don't have a session yet.
 */
am_cache_entry_t *am_get_request_session_by_nameid(request_rec *r, char *nameid)
{
    return am_lock_and_validate(r, AM_CACHE_NAMEID, nameid);
}

/* This function creates a new session.
 *
 * Parameters:
 *  request_rec *r       The request we are processing.
 *
 * Returns:
 *  The new session, or NULL if we have an internal error.
 */
am_cache_entry_t *am_new_request_session(request_rec *r)
{
    const char *session_id;

    /* Generate session id. */
    session_id = am_generate_id(r);
    if(session_id == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error creating session id.");
        return NULL;
    }

    /* Set session id. */
    am_cookie_set(r, session_id);

    const char *cookie_token = am_cookie_token(r);

    am_diag_printf(r, "%s id=%s cookie_token=\"%s\"\n",
                   __func__, session_id, cookie_token);

    return am_cache_new(r, session_id, cookie_token);
}


/* This function releases the session which was returned from
 * am_get_request_session.
 *
 * Parameters:
 *  request_rec *r              The request we are processing.
 *  am_cache_entry_t *session   The session we are releasing.
 *
 * Returns:
 *  Nothing.
 */
void am_release_request_session(request_rec *r, am_cache_entry_t *session)
{
    am_cache_unlock(r, session);
}


/* This function releases and deletes the session which was returned from
 * am_get_request_session.
 *
 * Parameters:
 *  request_rec *r              The request we are processing.
 *  am_cache_entry_t *session   The session we are deleting.
 *
 * Returns:
 *  Nothing.
 */
void am_delete_request_session(request_rec *r, am_cache_entry_t *session)
{
    am_diag_log_cache_entry(r, 0, session, "delete session");

    /* Delete the cookie. */
    am_cookie_delete(r);

    if(session == NULL) {
        return;
    }

    /* Delete session from the session store. */
    am_cache_delete(r, session);
}
