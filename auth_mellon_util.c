/*
 *
 *   auth_mellon_util.c: an authentication apache module
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

#include <openssl/err.h>
#include <openssl/rand.h>

#include "auth_mellon.h"

/* This function is used to get the url of the current request.
 *
 * Parameters:
 *  request_rec *r       The current request.
 *
 * Returns:
 *  A string containing the full url of the current request.
 *  The string is allocated from r->pool.
 */
const char *am_reconstruct_url(request_rec *r)
{
    const char *url;

    /* This function will construct an full url for a given path relative to
     * the root of the web site. To configure what hostname and port this
     * function will use, see the UseCanonicalName configuration directive.
     */
    url = ap_construct_url(r->pool, r->unparsed_uri, r);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "reconstruct_url: url==\"%s\", unparsed_uri==\"%s\"", url,
                  r->unparsed_uri);
    return url;
}


/* This function checks if the user has access according
 * to the MellonRequire directives.
 *
 * Parameters:
 *  request_rec *r              The current request.
 *  am_cache_entry_t *session   The current session.
 *
 * Returns:
 *  OK if the user has access and HTTP_FORBIDDEN if he doesn't.
 */
int am_check_permissions(request_rec *r, am_cache_entry_t *session)
{
    am_dir_cfg_rec *dir_cfg;
    apr_hash_index_t *idx;
    const char *key;
    apr_array_header_t *rlist;
    int i, j;
    int rlist_ok;
    const char **re;

    dir_cfg = am_get_dir_cfg(r);

    /* Iterate over all require-directives. */
    for(idx = apr_hash_first(r->pool, dir_cfg->require);
        idx != NULL;
        idx = apr_hash_next(idx)) {

        /* Get current require directive. key will be the name
         * of the attribute, and rlist is a list of all allowed values.
         */
        apr_hash_this(idx, (const void **)&key, NULL, (void **)&rlist);

        /* Reset status to 0 before search. */
        rlist_ok = 0;

        re = (const char **)rlist->elts;

        /* rlist is an array of all the valid values for this attribute. */
        for(i = 0; i < rlist->nelts && !rlist_ok; i++) {

            /* Search for a matching attribute in the session data. */
            for(j = 0; j < session->size && !rlist_ok; j++) {
                if(strcmp(session->env[j].varname, key) == 0 &&
                   strcmp(session->env[j].value, re[i]) == 0) {
                    /* We found a attribute with the correct name
                     * and value.
                     */
                    rlist_ok = 1;
                }
            }
        }

        if(!rlist_ok) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "Client failed to match required attribute \"%s\".",
                          key);
            return HTTP_FORBIDDEN;
        }
    }

    return OK;
}


/* This function disables caching of the response to this request. It does
 * this by setting the Pragme: no-cache and Cache-Control: no-cache headers.
 *
 * Parameters:
 *  request_rec *r       The request we are handling.
 *
 * Returns:
 *  Nothing.
 */
void am_set_nocache(request_rec *r)
{
    /* We set headers in both r->headers_out and r->err_headers_out, so that
     * we can be sure that they will be included.
     */

    apr_table_setn(r->headers_out, "Cache-Control", "no-cache");
    apr_table_setn(r->err_headers_out, "Cache-Control", "no-cache");

    apr_table_setn(r->headers_out, "Pragma", "no-cache");
    apr_table_setn(r->err_headers_out, "Pragma", "no-cache");
}


/* This function reads the post data for a request.
 *
 * The data is stored in a buffer allocated from the request pool.
 * After successful operation *data contains a pointer to the data and
 * *length contains the length of the data. 
 * The data will always be null-terminated.
 *
 * Parameters:
 *  request_rec *r        The request we read the form data from.
 *  char **data           Pointer to where we will store the pointer
 *                        to the data we read.
 *  apr_size_t *length    Pointer to where we will store the length
 *                        of the data we read. Pass NULL if you don't
 *                        need to know the length of the data.
 *
 * Returns:
 *  OK if we successfully read the POST data.
 *  An error if we fail to read the data.
 */
int am_read_post_data(request_rec *r, char **data, apr_size_t *length)
{
    apr_size_t bytes_read;
    apr_size_t bytes_left;
    apr_size_t len;
    long read_length;
    int rc;

    /* Prepare to receive data from the client. We request that apache
     * dechunks data if it is chunked.
     */
    rc = ap_setup_client_block(r, REQUEST_CHUNKED_DECHUNK);
    if (rc != OK) {
        return rc;
    }

    /* This function will send a 100 Continue response if the client is
     * waiting for that. If the client isn't going to send data, then this
     * function will return 0.
     */
    if (!ap_should_client_block(r)) {
        len = 0;
    } else {
        len = r->remaining;
    }

    if (length != NULL) {
        *length = len;
    }

    *data = (char *)apr_palloc(r->pool, len + 1);

    /* Make sure that the data is null-terminated.  */
    (*data)[len] = '\0';

    bytes_read = 0;
    bytes_left = len;

    while (bytes_left > 0) {
        /* Read data from the client. Returns 0 on EOF or error, the
         * number of bytes otherwise.
         */
        read_length = ap_get_client_block(r, &(*data)[bytes_read],
                                          bytes_left);
        if (read_length == 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Failed to read POST data from client.");
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        bytes_read += read_length;
        bytes_left -= read_length;
    }

    return OK;
}


/* extract_query_parameter is a function which extracts the value of
 * a given parameter in a query string. The query string can be the
 * query_string parameter of a GET request, or it can be the data
 * passed to the web server in a POST request.
 *
 * Parameters:
 *  apr_pool_t *pool           The memory pool which the memory for
 *                             the value will be allocated from.
 *  const char *query_string   Either the query_string from a GET
 *                             request, or the data from a POST
 *                             request.
 *  const char *name           The name of the parameter to extract.
 *                             Note that the search for this name is
 *                             case sensitive.
 *
 * Returns:
 *  The value of the parameter or NULL if we don't find the parameter.
 */
char *am_extract_query_parameter(apr_pool_t *pool,
                                 const char *query_string,
                                 const char *name)
{
    const char *ip;
    const char *value_end;
    apr_size_t namelen;

    if (query_string == NULL) {
        return NULL;
    }

    ip = query_string;
    namelen = strlen(name);

    /* Find parameter. Searches for /[^&]<name>[&=$]/.
     * Moves ip to the first character after the name (either '&', '='
     * or '\0').
     */
    for (;;) {
        /* First we find the name of the parameter. */
        ip = strstr(ip, name);
        if (ip == NULL) {
            /* Parameter not found. */
            return NULL;
        }

        /* Then we check what is before the parameter name. */
        if (ip != query_string && ip[-1] != '&') {
            /* Name not preceded by [^&]. */
            ip++;
            continue;
        }

        /* And last we check what follows the parameter name. */
        if (ip[namelen] != '=' && ip[namelen] != '&'
            && ip[namelen] != '\0') {
            /* Name not followed by [&=$]. */
            ip++;
            continue;
        }


        /* We have found the pattern. */
        ip += namelen;
        break;
    }

    /* Now ip points to the first character after the name. If this
     * character is '&' or '\0', then this field doesn't have a value.
     * If this character is '=', then this field has a value.
     */
    if (ip[0] == '=') {
        ip += 1;
    }

    /* The value is from ip to '&' or to the end of the string, whichever
     * comes first. */
    value_end = strchr(ip, '&');
    if (value_end != NULL) {
        /* '&' comes first. */
        return apr_pstrndup(pool, ip, value_end - ip);
    } else {
        /* Value continues until the end of the string. */
        return apr_pstrdup(pool, ip);
    }
}

/* This function urldecodes a string in-place.
 *
 * Parameters:
 *  char *data       The string to urldecode.
 *
 * Returns:
 *  OK if successful or HTTP_BAD_REQUEST if any escape sequence decodes to a
 *  null-byte ('\0'), or if an invalid escape sequence is found.
 */
int am_urldecode(char *data)
{
    int rc;
    char *ip;

    /* First we replace all '+'-characters with space. */
    for (ip = strchr(data, '+'); ip != NULL; ip = strchr(ip, '+')) {
        *ip = ' ';
    }

    /* Then we call ap_unescape_url_keep2f to decode all the "%xx"
     * escapes. This function returns HTTP_NOT_FOUND if the string
     * contains a null-byte.
     */
    rc = ap_unescape_url_keep2f(data);
    if (rc == HTTP_NOT_FOUND) {
        return HTTP_BAD_REQUEST;
    }

    return rc;
}


/* This function urlencodes a string. It will escape all characters
 * except a-z, A-Z, 0-9, '_' and '.'.
 *
 * Parameters:
 *  apr_pool_t *pool   The pool we should allocate memory from.
 *  const char *str    The string we should urlencode.
 *
 * Returns:
 *  The urlencoded string, or NULL if str == NULL.
 */
char *am_urlencode(apr_pool_t *pool, const char *str)
{
    const char *ip;
    apr_size_t length;
    char *ret;
    char *op;
    int hi, low;
    /* Return NULL if str is NULL. */
    if(str == NULL) {
        return NULL;
    }


    /* Find the length of the output string. */
    length = 0;
    for(ip = str; *ip; ip++) {
        if(*ip >= 'a' && *ip <= 'z') {
            length++;
        } else if(*ip >= 'A' && *ip <= 'Z') {
            length++;
        } else if(*ip >= '0' && *ip <= '9') {
            length++;
        } else if(*ip == '_' || *ip == '.') {
            length++;
        } else {
            length += 3;
        }
    }

    /* Add space for null-terminator. */
    length++;

    /* Allocate memory for string. */
    ret = (char *)apr_palloc(pool, length);

    /* Encode string. */
    for(ip = str, op = ret; *ip; ip++, op++) {
        if(*ip >= 'a' && *ip <= 'z') {
            *op = *ip;
        } else if(*ip >= 'A' && *ip <= 'Z') {
            *op = *ip;
        } else if(*ip >= '0' && *ip <= '9') {
            *op = *ip;
        } else if(*ip == '_' || *ip == '.') {
            *op = *ip;
        } else {
            *op = '%';
            op++;

            hi = (*ip & 0xf0) >> 4;

            if(hi < 0xa) {
                *op = '0' + hi;
            } else {
                *op = 'A' + hi - 0xa;
            }
            op++;

            low = *ip & 0x0f;

            if(low < 0xa) {
                *op = '0' + low;
            } else {
                *op = 'A' + low - 0xa;
            }
        }
    }

    /* Make output string null-terminated. */
    *op = '\0';

    return ret;
}

/* This function generates a given number of (pseudo)random bytes.
 * The current implementation uses OpenSSL's RAND_*-functions.
 *
 * Parameters:
 *  request_rec *r       The request we are generating random bytes for.
 *                       The request is used for configuration and
 *                       error/warning reporting.
 *  void *dest           The address if the buffer we should fill with data.
 *  apr_size_t count     The number of random bytes to create.
 *
 * Returns:
 *  OK on success, or HTTP_INTERNAL_SERVER on failure.
 */
int am_generate_random_bytes(request_rec *r, void *dest, apr_size_t count)
{
    int rc;
    rc = RAND_pseudo_bytes((unsigned char *)dest, (int)count);
    if(rc == -1) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error generating random data: %lu",
                      ERR_get_error());
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if(rc == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                      "Random data is not cryptographically strong.");
    }

    return OK;
}


/* This function generates a session id which is AM_SESSION_ID_LENGTH
 * characters long. The session id will consist of hexadecimal characters.
 *
 * Parameters:
 *  request_rec *r       The request we generate a session id for.
 *
 * Returns:
 *  The session id, made up of AM_SESSION_ID_LENGTH hexadecimal characters,
 *  terminated by a null-byte.
 */
char *am_generate_session_id(request_rec *r)
{
    int rc;
    char *ret;
    int rand_data_len;
    unsigned char *rand_data;
    int i;
    unsigned char b;
    int hi, low;

    ret = (char *)apr_palloc(r->pool, AM_SESSION_ID_LENGTH + 1);

    /* We need to round the length of the random data _up_, in case the
     * length of the session id isn't even.
     */
    rand_data_len = (AM_SESSION_ID_LENGTH + 1) / 2;

    /* Fill the last rand_data_len bytes of the string with
     * random bytes. This allows us to overwrite from the beginning of
     * the string.
     */
    rand_data = (unsigned char *)&ret[AM_SESSION_ID_LENGTH - rand_data_len];

    /* Generate random numbers. */
    rc = am_generate_random_bytes(r, rand_data, rand_data_len);
    if(rc != OK) {
        return NULL;
    }

    /* Convert the random bytes to hexadecimal. Note that we will write
     * AM_SESSION_LENGTH+1 characters if we have a non-even length of the
     * session id. This is OK - we will simply overwrite the last character
     * with the null-terminator afterwards.
     */
    for(i = 0; i < AM_SESSION_ID_LENGTH; i += 2) {
        b = rand_data[i / 2];
        hi = (b >> 4) & 0xf;
        low = b & 0xf;

        if(hi >= 0xa) {
            ret[i] = 'a' + hi - 0xa;
        } else {
            ret[i] = '0' + hi;
        }

        if(low >= 0xa) {
            ret[i+1] = 'a' + low - 0xa;
        } else {
            ret[i+1] = '0' + low;
        }
    }

    /* Add null-terminator- */
    ret[AM_SESSION_ID_LENGTH] = '\0';

    return ret;
}

/*
 * malloc a buffer and fill it with a given file
 *
 * Parameters:
 *   apr_pool_t *conf   The configuration pool. Valid as long as this
 *   server_rec *s      The server record for the current server.
 *   const char *file   The file path
 *
 * Returns:
 *   char *             The file content
 */
char *am_getfile(apr_pool_t *conf, server_rec *s, const char *file)
{
    apr_status_t rv;
    char buffer[512];
    apr_finfo_t finfo;
    char *data;
    apr_file_t *fd;
    apr_size_t nbytes;

    if (file == NULL)
        return NULL;

    if ((rv = apr_file_open(&fd, file, APR_READ, 0, conf)) != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "apr_file_open: Error opening \"%s\" [%d] \"%s\"",
                     file, rv, apr_strerror(rv, buffer, sizeof(buffer)));
        return NULL;
    }

    if ((rv = apr_file_info_get(&finfo, APR_FINFO_SIZE, fd)) != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "apr_file_info_get: Error opening \"%s\" [%d] \"%s\"",
                     file, rv, apr_strerror(rv, buffer, sizeof(buffer)));
        (void)apr_file_close(fd);
        return NULL;
    }

    nbytes = finfo.size;
    data = (char *)apr_palloc(conf, nbytes + 1);

    if ((rv = apr_file_read(fd, (void *)data, &nbytes)) != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "apr_file_read: Error reading \"%s\" [%d] \"%s\"",
                     file, rv, apr_strerror(rv, buffer, sizeof(buffer)));
    }
    data[finfo.size] = '\0';

    (void)apr_file_close(fd);

    return data;
}
