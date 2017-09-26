/*
 *
 *   mod_auth_mellon.c: an authentication apache module
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

#include <curl/curl.h>

/* The size of the blocks we will allocate. */
#define AM_HC_BLOCK_SIZE 1000

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(auth_mellon);
#endif

/* This structure describes a single-linked list of downloaded blocks. */
typedef struct am_hc_block_s {
    /* The next block we have allocated. */
    struct am_hc_block_s *next;

    /* The number of bytes written to this block. */
    apr_size_t used;

    /* The data stored in this block. */
    uint8_t data[AM_HC_BLOCK_SIZE];
} am_hc_block_t;


/* This structure describes a header for the block list. */
typedef struct {
    /* The pool we will allocate memory for new blocks from. */
    apr_pool_t *pool;

    /* The first block in the linked list of blocks. */
    am_hc_block_t *first;

    /* The last block in the linked list of blocks. */
    am_hc_block_t *last;
} am_hc_block_header_t;


/* This function allocates and initializes a block for data copying.
 *
 * Parameters:
 *  apr_pool_t *pool     The pool we should allocate the block from.
 *
 * Returns:
 *  The new block we allocated.
 */
static am_hc_block_t *am_hc_block_alloc(apr_pool_t *pool)
{
    am_hc_block_t *blk;

    blk = (am_hc_block_t *)apr_palloc(pool, sizeof(am_hc_block_t));

    blk->next = NULL;
    blk->used = 0;

    return blk;
}


/* This function adds data to the end of a block, and allocates new blocks
 * if the data doesn't fit in one block.
 *
 * Parameters:
 *  am_hc_block_t *block   The block we should begin by appending data to.
 *  apr_pool_t *pool       The pool we should allocate memory for new blocks
 *                         from.
 *  const uint8_t *data    The data we should append to the blocks.
 *  apr_size_t size        The length of the data we should append.
 *
 * Returns:
 *  The last block written to (i.e. the next block we should write to).
 */
static am_hc_block_t *am_hc_block_write(
    am_hc_block_t *block,
    apr_pool_t *pool,
    const uint8_t *data, apr_size_t size
    )
{
    apr_size_t num_cpy;

    while(size > 0) {
        /* Find the number of bytes we should write to this block. */
        num_cpy = AM_HC_BLOCK_SIZE - block->used;
        if(num_cpy == 0) {
            /* This block is full -- allocate a new block. */
            block->next = am_hc_block_alloc(pool);
            block = block->next;
            num_cpy = AM_HC_BLOCK_SIZE;
        }
        if(num_cpy > size) {
            num_cpy = size;
        }

        /* Copy data to this block. */
        memcpy(&block->data[block->used], data, num_cpy);
        block->used += num_cpy;

        size -= num_cpy;
        data += num_cpy;
    }

    /* The next write should be to this block. */
    return block;
}


/* This function initializes a am_hc_block_header_t structure, which
 * contains information about the linked list of data blocks.
 *
 * Parameters:
 *  am_hc_block_header_t *bh   Pointer to the data header whcih we
 *                             should initialize.
 *  apr_pool_t *pool           The pool we should allocate data from.
 *
 * Returns:
 *  Nothing.
 */
static void am_hc_block_header_init(am_hc_block_header_t *bh,
                                    apr_pool_t *pool)
{
    bh->pool = pool;

    bh->first = am_hc_block_alloc(pool);
    bh->last = bh->first;
}


/* This function writes data to the linked list of blocks identified by
 * the stream-parameter. It matches the prototype required by curl.
 *
 * Parameters:
 *  void *data           The data that should be written. It is size*nmemb
 *                       bytes long.
 *  size_t size          The size of each block of data that should
 *                       be written.
 *  size_t nmemb         The number of blocks of data that should be written.
 *  void *block_header   A pointer to a am_hc_block_header_t structure which
 *                       identifies the linked list we should store data in.
 *
 * Returns:
 *  The number of bytes that have been written.
 */
static size_t am_hc_data_write(void *data, size_t size, size_t nmemb,
                               void *data_header)
{
    am_hc_block_header_t *bh;

    bh = (am_hc_block_header_t *)data_header;

    bh->last = am_hc_block_write(bh->last, bh->pool, (const uint8_t *)data,
                                 size * nmemb);

    return size * nmemb;
}


/* This function fetches the data which was written to the databuffers
 * in the linked list which the am_hc_data_t structure keeps track of.
 *
 * Parameters:
 *  am_hc_block_header_t *bh   The header telling us which data buffers
 *                             we should extract data from.
 *  apr_pool_t *pool           The pool we should allocate the data
 *                             buffer from.
 *  void **buffer              A pointer to where we should store a pointer
 *                             to the data buffer we allocate. We will
 *                             always add a null-terminator to the end of
 *                             data buffer. This parameter can't be NULL.
 *  apr_size_t *size           This is a pointer to where we will store the
 *                             length of the data, not including the
 *                             null-terminator we add. This parameter can
 *                             be NULL.
 *
 * Returns:
 *  Nothing.
 */
static void am_hc_data_extract(am_hc_block_header_t *bh, apr_pool_t *pool,
                               void **buffer, apr_size_t *size)
{
    am_hc_block_t *blk;
    apr_size_t length;
    uint8_t *buf;
    apr_size_t pos;

    /* First we find the length of the data. */
    length = 0;
    for(blk = bh->first; blk != NULL; blk = blk->next) {
        length += blk->used;
    }

    /* Allocate memory for the data. Add one to the size in order to
     *  have space for the null-terminator.
     */
    buf = (uint8_t *)apr_palloc(pool, length + 1);

    /* Copy the data into the buffer. */
    pos = 0;
    for(blk = bh->first; blk != NULL; blk = blk->next) {
        memcpy(&buf[pos], blk->data, blk->used);
        pos += blk->used;
    }

    /* Add the null-terminator. */
    buf[length] = 0;

    /* Set up the return values. */
    *buffer = (void *)buf;
    if(size != NULL) {
        *size = length;
    }
}


/* This function creates a curl object and performs generic initialization
 * of it.
 *
 * Parameters:
 *  request_rec *r             The request we should log errors against.
 *  const char *uri            The URI we should request.
 *  am_hc_block_header_t *bh   The buffer curl will write response data to.
 *  char *curl_error           A buffer of size CURL_ERROR_SIZE where curl
 *                             will store error messages.
 *
 * Returns:
 *  A initialized curl object on succcess, or NULL on error.
 */
static CURL *am_httpclient_init_curl(request_rec *r, const char *uri,
                                     am_hc_block_header_t *bh,
                                     char *curl_error)
{
    am_dir_cfg_rec *cfg = am_get_dir_cfg(r);
    CURL *curl;
    CURLcode res;

    /* Initialize the curl object. */
    curl = curl_easy_init();
    if(curl == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to initialize a curl object.");
        return NULL;
    }


    /* Set up error reporting. */
    res = curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_error);
    if(res != CURLE_OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to set curl error buffer: [%u]\n", res);
        goto cleanup_fail;
    }

    /* Disable progress reporting. */
    res = curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
    if(res != CURLE_OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to disable curl progress reporting: [%u] %s",
                      res, curl_error);
        goto cleanup_fail;
    }

    /* Disable use of signals. */
    res = curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    if(res != CURLE_OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to disable signals in curl: [%u] %s",
                      res, curl_error);
        goto cleanup_fail;
    }

    /* Set the timeout of the transfer. It is currently set to two minutes. */
    res = curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L);
    if(res != CURLE_OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to set the timeout of the curl download:"
                      " [%u] %s", res, curl_error);
        goto cleanup_fail;
    }

    /* If we have a CA configured, try to use it */
    if (cfg->idp_ca_file != NULL) {
        res = curl_easy_setopt(curl, CURLOPT_CAINFO, cfg->idp_ca_file->path);
        if(res != CURLE_OK) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Failed to set SSL CA info %s:"
                          " [%u] %s", cfg->idp_ca_file->path, res, curl_error);
            goto cleanup_fail;
        }
    }

    /* Enable fail on http error. */
    res = curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    if(res != CURLE_OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to enable failure on http error: [%u] %s",
                      res, curl_error);
        goto cleanup_fail;
    }

    /* Select which uri we should download. */
    res = curl_easy_setopt(curl, CURLOPT_URL, uri);
    if(res != CURLE_OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to set curl download uri to \"%s\": [%u] %s",
                      uri, res, curl_error);
        goto cleanup_fail;
    }


    /* Set up data writing. */

    /* Set curl write function. */
    res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, am_hc_data_write);
    if(res != CURLE_OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to set the curl write function: [%u] %s",
                      res, curl_error);
        goto cleanup_fail;
    }

    /* Set the curl write function parameter. */
    res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, bh);
    if(res != CURLE_OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to set the curl write function data: [%u] %s",
                      res, curl_error);
        goto cleanup_fail;
    }

    return curl;


 cleanup_fail:
    curl_easy_cleanup(curl);
    return NULL;
}


/* This function downloads data from a specified URI, with specified timeout
 *
 * Parameters:
 *  request_rec *r       The apache request this download is associated
 *                       with. It is used for memory allocation and logging.
 *  const char *uri      The URI we should download.
 *  void **buffer        A pointer to where we should store a pointer to the
 *                       downloaded data. We will always add a null-terminator
 *                       to the data. This parameter can't be NULL.
 *  apr_size_t *size     This is a pointer to where we will store the length
 *                       of the downloaded data, not including the
 *                       null-terminator we add. This parameter can be NULL.
 *  int timeout          Timeout in seconds, 0 for no timeout.
 *  long *status         Pointer to HTTP status code. 
 *
 * Returns:
 *  OK on success, or HTTP_INTERNAL_SERVER_ERROR on failure. On failure we
 *  will write a log message describing the error.
 */
int am_httpclient_get(request_rec *r, const char *uri,
                      void **buffer, apr_size_t *size,
                      int timeout, long *status)
{
    am_hc_block_header_t bh;
    CURL *curl;
    char curl_error[CURL_ERROR_SIZE];
    CURLcode res;

    /* Initialize the data storage. */
    am_hc_block_header_init(&bh, r->pool);

    /* Initialize the curl object. */
    curl = am_httpclient_init_curl(r, uri, &bh, curl_error);
    if(curl == NULL) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    res = curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)timeout);
    if(res != CURLE_OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to download data from the uri \"%s\", "
                      "cannot set timeout to %ld: [%u] %s",
                      uri, (long)timeout, res, curl_error);
        goto cleanup_fail;
    }
    
    res = curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (long)timeout);
    if(res != CURLE_OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to download data from the uri \"%s\", "
                      "cannot set connect timeout to %ld: [%u] %s",
                      uri, (long)timeout,  res, curl_error);
        goto cleanup_fail;
    }

    /* Do the download. */
    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to download data from the uri \"%s\", "
                      "transaction aborted: [%u] %s",
                      uri, res, curl_error);
        goto cleanup_fail;
    }

    if (status != NULL) {
        res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, status);
        if(res != CURLE_OK) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Failed to download data from the uri \"%s\", "
                          "no status report: [%u] %s",
                          uri, res, curl_error);
            goto cleanup_fail;
       }
    }
    
    /* Free the curl object. */
    curl_easy_cleanup(curl);

    /* Copy the data. */
    am_hc_data_extract(&bh, r->pool, buffer, size);

    return OK;


 cleanup_fail:
    curl_easy_cleanup(curl);
    return HTTP_INTERNAL_SERVER_ERROR;
}


/* This function downloads data from a specified URI by issuing a POST
 * request.
 *
 * Parameters:
 *  request_rec *r             The apache request this download is
 *                             associated with. It is used for memory
 *                             allocation and logging.
 *  const char *uri            The URI we should post data to.
 *  const void *post_data      The POST data we should send.
 *  apr_size_t post_length     The length of the POST data.
 *  const char *content_type   The content type of the POST data. This
 *                             parameter can be NULL, in which case the
 *                             content type will be
 *                             "application/x-www-form-urlencoded".
 *  void **buffer              A pointer to where we should store a pointer
 *                             to the downloaded data. We will always add a
 *                             null-terminator to the data. This parameter
 *                             can't be NULL.
 *  apr_size_t *size           This is a pointer to where we will store the
 *                             length of the downloaded data, not including
 *                             the null-terminator we add. This parameter
 *                             can be NULL.
 *
 * Returns:
 *  OK on success. On failure we will write a log message describing the
 *  error, and return HTTP_INTERNAL_SERVER_ERROR.
 */
int am_httpclient_post(request_rec *r, const char *uri,
                       const void *post_data, apr_size_t post_length,
                       const char *content_type,
                       void **buffer, apr_size_t *size)
{
    am_hc_block_header_t bh;
    CURL *curl;
    char curl_error[CURL_ERROR_SIZE];
    CURLcode res;
    struct curl_slist *ctheader;

    /* Initialize the data storage. */
    am_hc_block_header_init(&bh, r->pool);

    /* Initialize the curl object. */
    curl = am_httpclient_init_curl(r, uri, &bh, curl_error);
    if(curl == NULL) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Enable POST request. */
    res = curl_easy_setopt(curl, CURLOPT_POST, 1L);
    if(res != CURLE_OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to enable POST request: [%u] %s",
                      res, curl_error);
        goto cleanup_fail;
    }

    /* Set POST data size. */
    res = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, post_length);
    if(res != CURLE_OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to set the POST data length: [%u] %s",
                      res, curl_error);
        goto cleanup_fail;
    }

    /* Set POST data. */
    res = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    if(res != CURLE_OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to set the POST data: [%u] %s",
                      res, curl_error);
        goto cleanup_fail;
    }


    /* Set the content-type header. */

    /* Set default content type if content_type is NULL. */
    if(content_type == NULL) {
        content_type = "application/x-www-form-urlencoded";
    }

    /* Create header list. */
    ctheader = NULL;
    ctheader = curl_slist_append(ctheader, apr_pstrcat(
                                     r->pool,
                                     "Content-Type: ",
                                     content_type,
                                     NULL
                                     ));

    /* Set headers. */
    res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, ctheader);
    if(res != CURLE_OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to set content-type header to \"%s\": [%u] %s",
                      content_type, res, curl_error);
        goto cleanup_fail;
    }


    /* Do the download. */
    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to download data from the uri \"%s\": [%u] %s",
                      uri, res, curl_error);
        goto cleanup_fail;
    }

    /* Free the curl object. */
    curl_easy_cleanup(curl);

    /* Free the content-type header. */
    curl_slist_free_all(ctheader);

    /* Copy the data. */
    am_hc_data_extract(&bh, r->pool, buffer, size);

    return OK;


 cleanup_fail:
    curl_easy_cleanup(curl);
    return HTTP_INTERNAL_SERVER_ERROR;
}


/* This function downloads data from a specified URI by issuing a POST
 * request.
 *
 * Parameters:
 *  request_rec *r             The apache request this download is
 *                             associated with. It is used for memory
 *                             allocation and logging.
 *  const char *uri            The URI we should post data to.
 *  const char *post_data      The POST data we should send.
 *  const char *content_type   The content type of the POST data. This
 *                             parameter can be NULL, in which case the
 *                             content type will be
 *                             "application/x-www-form-urlencoded".
 *  void **buffer              A pointer to where we should store a pointer
 *                             to the downloaded data. We will always add a
 *                             null-terminator to the data. This parameter
 *                             can't be NULL.
 *  apr_size_t *size           This is a pointer to where we will store the
 *                             length of the downloaded data, not including
 *                             the null-terminator we add. This parameter
 *                             can be NULL.
 *
 * Returns:
 *  OK on success. On failure we will write a log message describing the
 *  error, and return HTTP_INTERNAL_SERVER_ERROR.
 */
int am_httpclient_post_str(request_rec *r, const char *uri,
                           const char *post_data,
                           const char *content_type,
                           void **buffer, apr_size_t *size)
{
    return am_httpclient_post(r, uri, post_data, strlen(post_data),
                              content_type, buffer, size);
}
