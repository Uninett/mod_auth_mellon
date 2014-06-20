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

#include <assert.h>

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
char *am_reconstruct_url(request_rec *r)
{
    char *url;

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

/* This function builds an array of regexp backreferences
 *
 * Parameters:
 *  request_rec *r                 The current request.
 *  const am_cond_t *ce            The condition
 *  const char *value              Attribute value
 *  const ap_regmatch_t *regmatch  regmatch_t from ap_regexec()
 *
 * Returns:
 *  An array of collected backreference strings
 */
const apr_array_header_t *am_cond_backrefs(request_rec *r, 
                                           const am_cond_t *ce, 
                                           const char *value, 
                                           const ap_regmatch_t *regmatch)
{
    apr_array_header_t *backrefs;
    const char **ref;
    int nsub;
    int i;

    nsub = ce->regex->re_nsub + 1;     /* +1 for %0 */
    backrefs = apr_array_make(r->pool, nsub, sizeof(const char *));
    backrefs->nelts = nsub;

    ref = (const char **)(backrefs->elts);

    for (i = 0; i < nsub; i++) {
        if ((regmatch[i].rm_so == -1) || (regmatch[i].rm_eo == -1)) {
            ref[i] = "";
        } else {
            int len = regmatch[i].rm_eo - regmatch[i].rm_so;
            int off = regmatch[i].rm_so;

            ref[i] = apr_pstrndup(r->pool, value + off, len);
        }
    }

    return (const apr_array_header_t *)backrefs;
}

/* This function clones an am_cond_t and substitute value to 
 * match (both regexp and string) with backreferences from
 * a previous regex match.
 *
 * Parameters:
 *  request_rec *r                      The current request.
 *  const am_cond_t *cond               The am_cond_t to clone and substiture
 *  const apr_array_header_t *backrefs  Collected backreferences
 *
 * Returns:
 *  The cloned am_cond_t
 */
const am_cond_t *am_cond_substitue(request_rec *r, const am_cond_t *ce, 
                                   const apr_array_header_t *backrefs)
{
    am_cond_t *c;
    const char *instr = ce->str;
    apr_size_t inlen = strlen(instr);
    const char *outstr = "";
    size_t last;
    size_t i;

    c = (am_cond_t *)apr_pmemdup(r->pool, ce, sizeof(*ce));
    c->str = outstr;
    last = 0;
    
    for (i = strcspn(instr, "%"); i < inlen; i += strcspn(instr + i, "%")) {
        const char *fstr;
        const char *ns;
        const char *name;
        const char *value;
        apr_size_t flen;
        apr_size_t pad;
        apr_size_t nslen;

        /* 
         * Make sure we got a %
         */
	assert(instr[i] == '%');

        /*
         * Copy the format string in fstr. It can be a single 
         * digit (e.g.: %1) , or a curly-brace enclosed text
         * (e.g.: %{12})
         */
        fstr = instr + i + 1;
        if (*fstr == '{') {          /* Curly-brace enclosed text */
            pad = 3; /* 3 for %{} */
            fstr++;
            flen = strcspn(fstr, "}");

            /* If there is no closing }, we do not substitute  */
            if (fstr[flen] == '\0') {
                pad = 2; /* 2 for %{ */
                i += flen + pad;
                break;
            }

        } else if (*fstr == '\0') {  /* String ending by a % */
            break;

        } else {                     /* Single digit */
            pad = 1; /* 1 for % */
            flen = 1;
        }

        /*
         * Try to extract a namespace (ns) and a name, e.g: %{ENV:foo}
         */ 
        fstr = apr_pstrndup(r->pool, fstr, flen);
        if ((nslen = strcspn(fstr, ":")) != flen) {
            ns = apr_pstrndup(r->pool, fstr, nslen);
            name = fstr + nslen + 1; /* +1 for : */
        } else {
            nslen = 0;
            ns = "";
            name = fstr;
        }

        value = NULL;
        if ((*ns == '\0') && (strspn(fstr, "0123456789") == flen)) {
            /*
             * If fstr has only digits, this is a regexp backreference
             */
            int d = (int)apr_atoi64(fstr);

            if ((d >= 0) && (d < backrefs->nelts)) 
                value = ((const char **)(backrefs->elts))[d];

        } else if ((*ns == '\0') && (strcmp(fstr, "%") == 0)) {
            /*
             * %-escape
             */
            value = fstr;

        } else if (strcmp(ns, "ENV") == 0) {
            /*
             * ENV namespace. Get value from apache environment
             */
            value = getenv(name);
        }

        /*
         * If we did not find a value, substitue the
         * format string with an empty string.
         */
         if (value == NULL)
            value = "";

        /*
         * Concatenate the value with leading text, and * keep track 
         * of the last location we copied in source string
         */
        outstr = apr_pstrcat(r->pool, outstr,
                             apr_pstrndup(r->pool, instr + last, i - last), 
                             value, NULL);
        last = i + flen + pad;

        /*
         * Move index to the end of the format string
         */
        i += flen + pad;
    }

    /*
     * Copy text remaining after the last format string.
     */
    outstr = apr_pstrcat(r->pool, outstr,
                         apr_pstrndup(r->pool, instr + last, i - last), 
                         NULL);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "Directive %s, \"%s\" substituted into \"%s\"",
                  ce->directive, instr, outstr);

    /*
     * If this was a regexp, recompile it.
     */
    if (ce->flags & AM_COND_FLAG_REG) {
        int regex_flags = AP_REG_EXTENDED|AP_REG_NOSUB;
 
        if (ce->flags & AM_COND_FLAG_NC)
            regex_flags |= AP_REG_ICASE;
 
        c->regex = ap_pregcomp(r->pool, outstr, regex_flags);
        if (c->regex == NULL) {
             ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                           "Invalid regular expression \"%s\"", outstr);
             return ce;
        }
    }

    return (const am_cond_t *)c;
}

/* This function checks if the user has access according
 * to the MellonRequire and MellonCond directives.
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
    int i, j;
    int skip_or = 0;
    const apr_array_header_t *backrefs = NULL;

    dir_cfg = am_get_dir_cfg(r);

    /* Iterate over all cond-directives */
    for (i = 0; i < dir_cfg->cond->nelts; i++) {
        const am_cond_t *ce;
        const char *value = NULL;
        int match = 0;

        ce = &((am_cond_t *)(dir_cfg->cond->elts))[i];

        /*
         * Rule with ignore flog?
         */
        if (ce->flags & AM_COND_FLAG_IGN)
            continue;

        /* 
         * We matched a [OR] rule, skip the next rules
         * until we have one without [OR]. 
         */
        if (skip_or) {
            if (!(ce->flags & AM_COND_FLAG_OR))
                skip_or = 0;

             ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                           "Skip %s, [OR] rule matched previously",
                           ce->directive);
            continue;
        }
        
        /* 
         * look for a match on each value for this attribute, 
         * stop on first match.
         */
        for (j = 0; (j < session->size) && !match; j++) {
            const char *varname = NULL;

            /*
             * if MAP flag is set, check for remapped 
             * attribute name with mellonSetEnv
             */
            if (ce->flags & AM_COND_FLAG_MAP)
                varname = apr_hash_get(dir_cfg->envattr, 
                                       am_cache_entry_get_string(session,
                                                    &session->env[j].varname),
                                       APR_HASH_KEY_STRING);

            /*
             * Otherwise or if not found, use the attribute name
             * sent by the IdP.
             */
            if (varname == NULL)
                varname = am_cache_entry_get_string(session,
                                                    &session->env[j].varname);
                      
            if (strcmp(varname, ce->varname) != 0)
                    continue;

            value = am_cache_entry_get_string(session, &session->env[j].value);

            /*
             * Substiture backrefs if available
             */
            if ((ce->flags & AM_COND_FLAG_FSTR) && (backrefs != NULL))
                ce = am_cond_substitue(r, ce, backrefs);

            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "Evaluate %s vs \"%s\"", 
                          ce->directive, value);
    
            if (value == NULL) {
                 match = 0;          /* can not happen */

            } else if (ce->flags & (AM_COND_FLAG_REG|AM_COND_FLAG_REF)) {
                 int nsub = ce->regex->re_nsub + 1;
                 ap_regmatch_t *regmatch;

                 regmatch = (ap_regmatch_t *)apr_palloc(r->pool, 
                            nsub * sizeof(*regmatch));

                 match = !ap_regexec(ce->regex, value, nsub, regmatch, 0);
                 if (match)
                     backrefs = am_cond_backrefs(r, ce, value, regmatch);

            } else if (ce->flags & AM_COND_FLAG_REG) {
                 match = !ap_regexec(ce->regex, value, 0, NULL, 0);

            } else if (ce->flags & (AM_COND_FLAG_SUB|AM_COND_FLAG_NC)) {
                 match = (strcasestr(ce->str, value) != NULL);

            } else if (ce->flags & AM_COND_FLAG_SUB) {
                 match = (strstr(ce->str, value) != NULL);

            } else if (ce->flags & AM_COND_FLAG_NC) {
                 match = !strcasecmp(ce->str, value);

            } else {
                 match = !strcmp(ce->str, value);
            }
        }

        if (ce->flags & AM_COND_FLAG_NOT)
            match = !match;

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "%s: %smatch", ce->directive,
                      (match == 0) ? "no ": "");

        /*
         * If no match, we stop here, except if it is an [OR] condition
         */
        if (!match & !(ce->flags & AM_COND_FLAG_OR)) {
            ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                          "Client failed to match %s",
                          ce->directive);
            return HTTP_FORBIDDEN;
        }

        /*
         * Match on [OR] condition means we skip until a rule
         * without [OR], 
         */
        if (match && (ce->flags & AM_COND_FLAG_OR))
            skip_or = 1;
    }

    return OK;
}

/* This function sets default Cache-Control headers.
 *
 * Parameters:
 *  request_rec *r       The request we are handling.
 *
 * Returns:
 *  Nothing.
 */
void am_set_cache_control_headers(request_rec *r)
{
    /* Send Cache-Control header to ensure that:
     * - no proxy in the path caches content inside this location (private),
     * - user agent have to revalidate content on server (must-revalidate).
     *
     * But never prohibit specifically any user agent to cache or store content
     *
     * Setting the headers in err_headers_out ensures that they will be
     * sent for all responses.
     */
    apr_table_setn(r->err_headers_out,
                   "Cache-Control", "private, must-revalidate");
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


/* Convert a hexadecimal digit to an integer.
 *
 * Parameters:
 *  char c           The digit we should convert.
 *
 * Returns:
 *  The digit as an integer, or -1 if it isn't a hex digit.
 */
static int am_unhex_digit(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 0xa;
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 0xa;
    } else {
        return -1;
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
    char *ip;
    char *op;
    int c1, c2;

    if (data == NULL) {
        return HTTP_BAD_REQUEST;
    }

    ip = data;
    op = data;
    while (*ip) {
        switch (*ip) {
        case '+':
            *op = ' ';
            ip++;
            op++;
            break;
        case '%':
            /* Decode the hex digits. Note that we need to check the
             * result of the first conversion before attempting the
             * second conversion -- otherwise we may read past the end
             * of the string.
             */
            c1 = am_unhex_digit(ip[1]);
            if (c1 < 0) {
                return HTTP_BAD_REQUEST;
            }
            c2 = am_unhex_digit(ip[2]);
            if (c2 < 0) {
                return HTTP_BAD_REQUEST;
            }

            *op = (c1 << 4) | c2;
            if (*op == '\0') {
                /* null-byte. */
                return HTTP_BAD_REQUEST;
            }
            ip += 3;
            op++;
            break;
        default:
            *op = *ip;
            ip++;
            op++;
        }
    }
    *op = '\0';

    return OK;
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


/* This function generates an id which is AM_ID_LENGTH characters long.
 * The id will consist of hexadecimal characters.
 *
 * Parameters:
 *  request_rec *r       The request we associate allocated memory with.
 *
 * Returns:
 *  The session id, made up of AM_ID_LENGTH hexadecimal characters,
 *  terminated by a null-byte.
 */
char *am_generate_id(request_rec *r)
{
    int rc;
    char *ret;
    int rand_data_len;
    unsigned char *rand_data;
    int i;
    unsigned char b;
    int hi, low;

    ret = (char *)apr_palloc(r->pool, AM_ID_LENGTH + 1);

    /* We need to round the length of the random data _up_, in case the
     * length of the session id isn't even.
     */
    rand_data_len = (AM_ID_LENGTH + 1) / 2;

    /* Fill the last rand_data_len bytes of the string with
     * random bytes. This allows us to overwrite from the beginning of
     * the string.
     */
    rand_data = (unsigned char *)&ret[AM_ID_LENGTH - rand_data_len];

    /* Generate random numbers. */
    rc = am_generate_random_bytes(r, rand_data, rand_data_len);
    if(rc != OK) {
        return NULL;
    }

    /* Convert the random bytes to hexadecimal. Note that we will write
     * AM_ID_LENGTH+1 characters if we have a non-even length of the
     * session id. This is OK - we will simply overwrite the last character
     * with the null-terminator afterwards.
     */
    for(i = 0; i < AM_ID_LENGTH; i += 2) {
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
    ret[AM_ID_LENGTH] = '\0';

    return ret;
}

/* This returns the directroy part of a path, a la dirname(3)
 *
 * Parameters:
 *  apr_pool_t p         Pool to allocate memory from
 *  const char *path     Path to extract directory from
 *
 * Returns:
 *  The directory part of path
 */
const char *am_filepath_dirname(apr_pool_t *p, const char *path) 
{
    char *cp;

    /*
     * Try Unix and then Windows style. Borrowed from
     * apr_match_glob(), it seems it cannot be made more
     * portable.
     */
    if (((cp = strrchr(path, (int)'/')) == NULL) &&
        ((cp = strrchr(path, (int)'\\')) == NULL))
            return ".";
   
    return apr_pstrndup(p, path, cp - path);
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
 * Purge outdated saved POST requests.
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
    char error_buffer[64];
    apr_finfo_t afi;
    char *fname;
    int count;
    apr_time_t expire_before;

    mod_cfg = am_get_mod_cfg(r->server);

    /* The oldes file we should keep. Delete files that are older. */
    expire_before = apr_time_now() - mod_cfg->post_ttl * APR_USEC_PER_SEC;

    /*
     * Open our POST directory or create it. 
     */
    rv = apr_dir_open(&postdir, mod_cfg->post_dir, r->pool);
    if (rv != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Unable to open MellonPostDirectory \"%s\": %s",
                      mod_cfg->post_dir,
                      apr_strerror(rv, error_buffer, sizeof(error_buffer)));
        return HTTP_INTERNAL_SERVER_ERROR;
    }

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

        if (afi.ctime < expire_before) {
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
    am_dir_cfg_rec *cfg = am_get_dir_cfg(r);

    return ap_construct_url(r->pool, cfg->endpoint_path, r);
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

    if ((psf_id = am_generate_id(r)) == NULL) {
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
            if ((value = am_xstrtok(r, NULL, ":", &l2)) != NULL)
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
            if ((attr_value = am_xstrtok(r, NULL, "=", &l2)) != NULL)
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

/* This function returns the URL for a given provider service (type + method)
 *
 * Parameters:
 *  request_rec *r        The request
 *  LassoProfile *profile Login profile
 *  char *endpoint_name   Service and method as specified in metadata
 *                        e.g.: "SingleSignOnService HTTP-Redirect"
 * Returns:
 *  The endpoint URL that must be freed by caller, or NULL on failure.
 */
char *
am_get_service_url(request_rec *r, LassoProfile *profile, char *service_name)
{
    LassoProvider *provider;
    gchar *url;

    provider = lasso_server_get_provider(profile->server, 
                                         profile->remote_providerID);
    if (LASSO_IS_PROVIDER(provider) == FALSE) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                      "Cannot find provider service %s, no provider.",
                      service_name);
	return NULL;
    }

    url = lasso_provider_get_metadata_one(provider, service_name);
    if (url == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                      "Cannot find provider service %s from metadata.",
                      service_name);
	return NULL;
    }

    return url;
}
