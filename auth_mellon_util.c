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
     const char *user_agent;

    /* We set headers in both r->headers_out and r->err_headers_out, so that
     * we can be sure that they will be included.
     */
    apr_table_setn(r->headers_out, 
		   "Expires", "Thu, 01 Jan 1970 00:00:00 GMT");
    apr_table_setn(r->headers_out,
		   "Cache-Control", "private, must-revalidate");
    apr_table_setn(r->err_headers_out,
		   "Expires", "Thu, 01 Jan 1970 00:00:00 GMT");
    apr_table_setn(r->err_headers_out,
		   "Cache-Control", "private, must-revalidate");

    /* 
     * Never use Cache-Control: no-cache for IE
     */
    user_agent = apr_table_get(r->headers_in, "User-Agent");
    if ((user_agent == NULL) ||
         (strstr(user_agent, "compatible; MSIE ") == NULL) ||
         (strstr(user_agent, "Opera") != NULL)) {
        apr_table_addn(r->headers_out,
		       "Cache-Control", "no-cache, no-store");
        apr_table_addn(r->err_headers_out,
		       "Cache-Control", "no-cache, no-store");
    }
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

/*
 * Check that a URL is safe for redirect.
 *
 * Parameters:
 *  request_rec *r       The request we are processing.
 *  const char *url      The URL we should check.
 *
 * Returns:
 *  OK on success, HTTP_BAD_REQUEST otherwise.
 */
int am_check_url(request_rec *r, const char *url)
{
    const char *i;

    for (i = url; *i; i++) {
        if (*i >= 0 && *i < ' ') {
            /* Deny all control-characters. */
            ap_log_rerror(APLOG_MARK, APLOG_ERR, HTTP_BAD_REQUEST, r,
                          "Control character detected in URL.");
            return HTTP_BAD_REQUEST;
        }
    }

    return OK;
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

    rv = apr_file_read_full(fd, data, nbytes, NULL);
    if (rv != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "apr_file_read_full: Error reading \"%s\" [%d] \"%s\"",
                     file, rv, apr_strerror(rv, buffer, sizeof(buffer)));
    }
    data[nbytes] = '\0';

    (void)apr_file_close(fd);

    return data;
}

/* 
 * Create a directory for saved POST sessions, check for proper permissions
 *
 * Parameters:
 *   request_rec *r     The current request
 *
 * Returns:
 *  OK on success, or HTTP_INTERNAL_SERVER on failure.
 */
static int am_postdir_mkdir(request_rec *r)
{
    apr_int32_t wanted;
    apr_finfo_t afi;
    apr_status_t rv;
    char buffer[512];
    am_mod_cfg_rec *mod_cfg;
    apr_fileperms_t mode;
    apr_uid_t user;
    apr_uid_t group;
    apr_fileperms_t prot;

    mod_cfg = am_get_mod_cfg(r->server);

    mode = APR_FPROT_UREAD|APR_FPROT_UWRITE|APR_FPROT_UEXECUTE;
    if ((rv = apr_dir_make_recursive(mod_cfg->post_dir, mode, r->pool)) != OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                      "cannot create POST directory \"%s\": %s",
                      mod_cfg->post_dir,
                      apr_strerror(rv, buffer, sizeof(buffer)));
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* 
     * The directory may have already existed. Check we really own it
     */
    wanted = APR_FINFO_USER|APR_FINFO_UPROT|APR_FINFO_GPROT|APR_FINFO_WPROT;
    if (apr_stat(&afi, mod_cfg->post_dir, wanted, r->pool) == OK) {
        if (apr_uid_current(&user, &group, r->pool) != OK) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                          "apr_uid_current failed");
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        if (afi.user != user) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                          "POST directory \"%s\" must be owned by the same "
                          "user as the web server is running as.",
                          mod_cfg->post_dir);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        prot = APR_FPROT_UREAD|APR_FPROT_UWRITE|APR_FPROT_UEXECUTE;
        if (afi.protection != prot) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                          "Premissions on POST directory \"%s\" must be 0700.",
                          mod_cfg->post_dir);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return OK;
}

/* 
 * Purge outdated saved POST requests. If the MellonPostDir directory
 * does not exist, create it first. 
 *
 * Parameters:
 *   request_rec *r     The current request
 *
 * Returns:
 *  OK on success, or HTTP_INTERNAL_SERVER on failure.
 */
int am_postdir_cleanup(request_rec *r)
{
    am_mod_cfg_rec *mod_cfg;
    apr_dir_t *postdir;
    apr_status_t rv;
    apr_finfo_t afi;
    char *fname;
    int count;

    mod_cfg = am_get_mod_cfg(r->server);

    /*
     * Open our POST directory or create it. 
     */
    if (apr_dir_open(&postdir, mod_cfg->post_dir, r->pool) != OK)
        return am_postdir_mkdir(r);

    /*
     * Purge outdated items
     */
    count = 0;
    do {
        rv = apr_dir_read(&afi, APR_FINFO_NAME|APR_FINFO_CTIME, postdir);
        if (rv != OK)
            break;

        /* Skip dot_files */
        if (afi.name[0] == '.')
             continue;

        if (afi.ctime + mod_cfg->post_ttl > apr_time_sec(apr_time_now())) {
            fname = apr_psprintf(r->pool, "%s/%s", mod_cfg->post_dir, afi.name);
            (void)apr_file_remove(fname , r->pool); 
        } else {
            count++;
        }
    } while (1 /* CONSTCOND */);

    (void)apr_dir_close(postdir);

    if (count >= mod_cfg->post_count) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                      "Too many saved POST sessions. "
                      "Increase MellonPostCount directive.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    return OK;
}

/* 
 * HTML-encode a string
 *
 * Parameters:
 *   request_rec *r     The current request
 *   const char *str    The string to encode
 *
 * Returns:
 *  The encoded string
 */
char *am_htmlencode(request_rec *r, const char *str)
{
    const char *cp;
    char *output;
    apr_size_t outputlen;
    int i;

    outputlen = 0;
    for (cp = str; *cp; cp++) {
        switch (*cp) {
        case '&':
            outputlen += 5;
            break;
        case '"':
            outputlen += 6;
            break;
        default:
            outputlen += 1;
            break;
        }
    }

    i = 0;
    output = apr_palloc(r->pool, outputlen + 1);
    for (cp = str; *cp; cp++) {
        switch (*cp) {
        case '&':
            (void)strcpy(&output[i], "&amp;");
            i += 5;
            break;
        case '"':
            (void)strcpy(&output[i], "&quot;");
            i += 6;
            break;
        default:
            output[i] = *cp;
            i += 1;
            break;
        }
    }
    output[i] = '\0';

    return output;
}

/* This function produces the endpoint URL
 *
 * Parameters:
 *  request_rec *r       The request we received.
 *
 * Returns:
 *  the endpoint URL
 */
char *am_get_endpoint_url(request_rec *r)
{
    static APR_OPTIONAL_FN_TYPE(ssl_is_https) *am_is_https = NULL;
    am_dir_cfg_rec *cfg = am_get_dir_cfg(r);
    apr_pool_t *p = r->pool;
    server_rec *s = r->server;
    apr_port_t default_port;
    char *port;
    char *scheme;

    am_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);

    if (am_is_https && am_is_https(r->connection)) {
        scheme = "https://";
        default_port = DEFAULT_HTTPS_PORT;
    } else {
        scheme = "http://";
        default_port = DEFAULT_HTTP_PORT;
    }

    if (s->addrs->host_port != default_port)
        port = apr_psprintf(p, ":%d", s->addrs->host_port);
    else
        port = "";

    return apr_psprintf(p, "%s%s%s%s", scheme,
                        s->server_hostname,
                        port,  cfg->endpoint_path);
}

/*
 * This function saves a POST request for later replay and updates
 * the return URL.
 *
 * Parameters:
 *  request_rec *r           The current request.
 *  const char **relay_state The returl URL
 *
 * Returns:
 *  OK on success, HTTP_INTERNAL_SERVER_ERROR otherwise
 */
int am_save_post(request_rec *r, const char **relay_state)
{
    am_mod_cfg_rec *mod_cfg;
    const char *content_type;
    const char *charset;
    const char *psf_id;
    char *psf_name;
    char *post_data;
    apr_size_t post_data_len;
    apr_size_t written;
    apr_file_t *psf;

    if (am_postdir_cleanup(r) != OK)
        return HTTP_INTERNAL_SERVER_ERROR;

    /* Check Content-Type */
    content_type = apr_table_get(r->headers_in, "Content-Type");
    if (content_type == NULL) {
        content_type = "urlencoded";
        charset = NULL; 
    } else {
        if (am_has_header(r, content_type, 
            "application/x-www-form-urlencoded")) {
            content_type = "urlencoded";

        } else if (am_has_header(r, content_type,
                   "multipart/form-data")) {
            content_type = "multipart";

        } else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                          "Unknown POST Content-Type \"%s\"", content_type);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        charset = am_get_header_attr(r, content_type, NULL, "charset");
    }     

    mod_cfg = am_get_mod_cfg(r->server);

    if ((psf_id = am_generate_session_id(r)) == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "cannot generate id");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    psf_name = apr_psprintf(r->pool, "%s/%s", mod_cfg->post_dir, psf_id);

    if (apr_file_open(&psf, psf_name,
                      APR_WRITE|APR_CREATE|APR_BINARY, 
                      APR_FPROT_UREAD|APR_FPROT_UWRITE,
                      r->pool) != OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "cannot create POST session file");
        return HTTP_INTERNAL_SERVER_ERROR;
    } 

    if (am_read_post_data(r, &post_data, &post_data_len) != OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "cannot read POST data");
        (void)apr_file_close(psf);
        return HTTP_INTERNAL_SERVER_ERROR;
    } 

    if (post_data_len > mod_cfg->post_size) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                      "POST data size %" APR_SIZE_T_FMT 
                      " exceeds maximum %" APR_SIZE_T_FMT ". "
                      "Increase MellonPostSize directive.",
                      post_data_len, mod_cfg->post_size);
        (void)apr_file_close(psf);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    written = post_data_len;
    if ((apr_file_write(psf, post_data, &written) != OK) ||
        (written != post_data_len)) { 
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "cannot write to POST session file");
            (void)apr_file_close(psf);
            return HTTP_INTERNAL_SERVER_ERROR;
    } 
    
    if (apr_file_close(psf) != OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "cannot close POST session file");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (charset != NULL)
        charset = apr_psprintf(r->pool, "&charset=%s", 
                               am_urlencode(r->pool, charset));
    else 
        charset = "";

    *relay_state = apr_psprintf(r->pool, 
                                "%srepost?id=%s&ReturnTo=%s&enctype=%s%s",
                                am_get_endpoint_url(r), psf_id,
                                am_urlencode(r->pool, *relay_state), 
                                content_type, charset);

    return OK;
}

/*
 * This function replaces CRLF by LF in a string
 *
 * Parameters:
 *  request_rec *r  The current request
 *  const char *str The string
 *
 * Returns:
 *  Output string
 */
const char *am_strip_cr(request_rec *r, const char *str)
{
    char *output;
    const char *cp;
    apr_size_t i;

    output = apr_palloc(r->pool, strlen(str) + 1);
    i = 0;

    for (cp = str; *cp; cp++) {
        if ((*cp == '\r') && (*(cp + 1) == '\n'))
            continue;
        output[i++] = *cp;
    }

    output[i++] = '\0';
    
    return (const char *)output;
}

/*
 * This function replaces LF by CRLF in a string
 *
 * Parameters:
 *  request_rec *r  The current request
 *  const char *str The string
 *
 * Returns:
 *  Output string
 */
const char *am_add_cr(request_rec *r, const char *str)
{
    char *output;
    const char *cp;
    apr_size_t xlen;
    apr_size_t i;

    xlen = 0;

    for (cp = str; *cp; cp++)
        if (*cp == '\n')
            xlen++;

    output = apr_palloc(r->pool, strlen(str) + xlen + 1);
    i = 0;

    for (cp = str; *cp; cp++) {
        if (*cp == '\n')
            output[i++] = '\r';
        output[i++] = *cp;
    }

    output[i++] = '\0';
    
    return (const char *)output;
}

/*
 * This function tokenize a string, just like strtok_r, except that
 * the separator is a string instead of a character set.
 *
 * Parameters:
 *  const char *str The string to tokenize
 *  const char *sep The separator string
 *  char **last     Pointer to state (char *)
 *
 * Returns:
 *  OK on success, HTTP_INTERNAL_SERVER_ERROR otherwise
 */
const char *am_xstrtok(request_rec *r, const char *str,
                       const char *sep, char **last)
{
    char *s;
    char *np;

    /* Resume */
    if (str != NULL)
        s = apr_pstrdup(r->pool, str);
    else
        s = *last;

    /* End of string */
    if (*s == '\0')
        return NULL;

    /* Next sep exists? */
    if ((np = strstr(s, sep)) == NULL) {
        *last = s + strlen(s);
    } else {
        *last = np + strlen(sep);
        memset(np, 0, strlen(sep));
    }

    return s;
}

/* This function strips leading spaces and tabs from a string
 *
 * Parameters:
 *  const char **s       Pointer to the string
 *
 */
void am_strip_blank(const char **s)
{
    while ((**s == ' ') || (**s == '\t'))
        (*s)++;
    return;
}

/* This function extracts a MIME header from a MIME section
 *
 * Parameters:
 *  request_rec *r        The request
 *  const char *m         The MIME section
 *  const char *h         The header to extract (case insensitive)
 *
 * Returns:
 *  The header value, or NULL on failure.
 */
const char *am_get_mime_header(request_rec *r, const char *m, const char *h) 
{
    const char *line;
    char *l1;
    const char *value;
    char *l2;

    for (line = am_xstrtok(r, m, "\n", &l1); line && *line; 
         line = am_xstrtok(r, NULL, "\n", &l1)) {

        am_strip_blank(&line);

        if (((value = am_xstrtok(r, line, ":", &l2)) != NULL) &&
            (strcasecmp(value, h) == 0)) {
            value =  am_xstrtok(r, NULL, ":", &l2);
            am_strip_blank(&value);
            return value;
        }
   }
   return NULL;
}

/* This function extracts an attribute from a header 
 *
 * Parameters:
 *  request_rec *r        The request
 *  const char *h         The header
 *  const char *v         Optional header value to check (case insensitive)
 *  const char *a         Optional attribute to extract (case insensitive)
 *
 * Returns:
 *   if i was provided, item value, or NULL on failure.
 *   if i is NULL, the whole header, or NULL on failure. This is
 *   useful for testing v.
 */
const char *am_get_header_attr(request_rec *r, const char *h,
                               const char *v, const char *a) 
{
    const char *value;
    const char *attr;
    char *l1;
    const char *attr_value = NULL;

    /* Looking for 
     * header-value; item_name="item_value"\n 
     */
    if ((value = am_xstrtok(r, h, ";", &l1)) == NULL)
        return NULL;
    am_strip_blank(&value);

    /* If a header value was provided, check it */ 
    if ((v != NULL) && (strcasecmp(value, v) != 0))
        return NULL;

    /* If no attribute name is provided, return everything */
    if (a == NULL)
        return h;

    while ((attr = am_xstrtok(r, NULL, ";", &l1)) != NULL) {
        const char *attr_name = NULL;
        char *l2;

        am_strip_blank(&attr);

        attr_name = am_xstrtok(r, attr, "=", &l2); 
        if ((attr_name != NULL) && (strcasecmp(attr_name, a) == 0)) {
        	attr_value = am_xstrtok(r, NULL, "=", &l2);
                am_strip_blank(&attr_value);
        	break;
        }
    }
  
    /* Remove leading and trailing quotes */
    if (attr_value != NULL) {
        apr_size_t len; 

        len = strlen(attr_value);
        if ((len > 1) && (attr_value[len - 1] == '\"'))
            attr_value = apr_pstrndup(r->pool, attr_value, len - 1);
        if (attr_value[0] == '\"')
            attr_value++;
    }
    
    return attr_value;
}

/* This function checks for a header name/value existence
 *
 * Parameters:
 *  request_rec *r        The request
 *  const char *h         The header (case insensitive)
 *  const char *v         Optional header value to check (case insensitive)
 *
 * Returns:
 *   0 if header does not exists or does not has the value, 1 otherwise
 */
int am_has_header(request_rec *r, const char *h, const char *v)
{
    return (am_get_header_attr(r, h, v, NULL) != NULL);
}

/* This function extracts the body from a MIME section
 *
 * Parameters:
 *  request_rec *r        The request
 *  const char *mime      The MIME section
 *
 * Returns:
 *  The MIME section body, or NULL on failure.
 */
const char *am_get_mime_body(request_rec *r, const char *mime) 
{
    const char lflf[] = "\n\n";
    const char *body;
    apr_size_t body_len;

    if ((body = strstr(mime, lflf)) == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "No MIME body");
        return NULL;
    }

    body += strlen(lflf);

    /* Strip tralling \n */
    if ((body_len = strlen(body)) >= 1) {
        if (body[body_len - 1] == '\n') 
            body = apr_pstrmemdup(r->pool, body, body_len - 1);
    }

    /* Turn back LF into CRLF */
    return am_add_cr(r, body);
}
