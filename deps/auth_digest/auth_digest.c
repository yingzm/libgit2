//
//  auth_digest.c
//  GitMongo
//
//  Created by zouting on 4/29/13.
//  Copyright (c) 2013 zouting. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "auth_digest.h"
#include "buffer.h"
#include "crypto/md5/md5.h"

enum {
    STATE_PARSE_KEY,
    STATE_PARSE_VALUE,
    STATE_PARSE_STRING,
};

static const char *skipWhitespace(const char *ptr)
{
    while (*(ptr+1)==' ' || *(ptr+1)=='\t')
        ++ptr;
    
    return ptr;
}

static void handleParams(DigestParams *params, const char *key, const char *value)
{
    if (strcasecmp(key, "realm")==0)
        params->realm = strdup(value);
    else if (strcasecmp(key, "domain")==0)
        params->domain = strdup(value);
    else if (strcasecmp(key, "nonce")==0)
        params->nonce = strdup(value);
    else if (strcasecmp(key, "algorithm")==0)
        params->algorithm = strdup(value);
    else if (strcasecmp(key, "qop")==0)
        params->qop = strdup(value);
}

void initDigestParams(DigestParams *params, const char *www_authenticate)
{
    char key[256], value[256];
    int state = STATE_PARSE_KEY;
    char *keyptr = key, *valueptr = value;
    
    const char *ptr = www_authenticate;
    
    key[0] = '\0';
    value[0] = '\0';
    
    // If empty string, just return
    if (*ptr=='\0')
        return;
    
    if (strncasecmp(ptr, "Digest", 6)!=0)
        return;
    
    ptr += 7;
    
    ptr = skipWhitespace(ptr);
    
    while (*ptr) {
        if (state==STATE_PARSE_KEY) {
            if (*ptr=='=') {
                *keyptr = '\0';
                keyptr = key;
                state = STATE_PARSE_VALUE;
                ptr = skipWhitespace(ptr);
            } else
                *keyptr++ = *ptr;
        } else if (state==STATE_PARSE_VALUE) {
            if (*ptr=='"') {
                state = STATE_PARSE_STRING;
            } else if (*ptr==',') {
                *valueptr = '\0';
                valueptr = value;
                state = STATE_PARSE_KEY;
                ptr = skipWhitespace(ptr);
                
                handleParams(params, key, value);
                key[0] = '\0';
                value[0]='\0';
            } else
                *valueptr++ = *ptr;
        } else if (state==STATE_PARSE_STRING) {
            if (*ptr=='"')
                state = STATE_PARSE_VALUE;
            else
                *valueptr++ = *ptr;
        }
        
        ++ptr;
    }
    
    if (state==STATE_PARSE_VALUE) {
        *valueptr = '\0';
        handleParams(params, key, value);
    }
}

void freeDigestParams(DigestParams *params)
{
    if (params->method)
        free(params->method);
    if (params->uri)
        free(params->uri);
    if (params->username)
        free(params->username);
    if (params->password)
        free(params->password);
    if (params->realm)
        free(params->realm);
    if (params->domain)
        free(params->domain);
    if (params->algorithm)
        free(params->algorithm);
    if (params->nonce)
        free(params->nonce);
    if (params->cnonce)
        free(params->cnonce);
    if (params->nc)
        free(params->nc);
    if (params->qop)
        free(params->qop);
}

static const char hex_chars[] = "0123456789abcdef";  
  
char int2hex(char c)   
{  
    return hex_chars[(c & 0x0F)];  
}  

static void H(git_buf *buf, unsigned char *md5)
{
    MD5_CTX ctx;
    unsigned char bin[16];
    unsigned short i;
    
    MD5_Init(&ctx);
    MD5_Update(&ctx, buf->ptr, buf->size);
    MD5_Final(bin, &ctx);
    
  
    for (i = 0; i < 16; i++) {
        md5[i*2] = int2hex((bin[i] >> 4) & 0xf);
        md5[i*2+1] = int2hex(bin[i] & 0xf);
    }  
    md5[32] = '\0';
}

void calcDigest(DigestParams *params, git_buf *digest)
{
    const char *authorization_digest = "Authorization: Digest ";
    
    unsigned char Ha1[256] = {0}, Ha2[256] = {0}, md[256] = {0};
    git_buf a1 = GIT_BUF_INIT, a2 = GIT_BUF_INIT, response=GIT_BUF_INIT;
    git_buf_printf(&a1, "%s:%s:%s", params->username, params->realm, params->password);
    H(&a1, Ha1);

    git_buf_printf(&a2, "%s:%s", params->method, params->uri);
    H(&a2, Ha2);
    
    if (strcmp(params->qop, "auth")==0 || strcmp(params->qop, "auth-int")==0)
        git_buf_printf(&response, "%s:%s:%s:%s:%s:%s", Ha1, params->nonce, params->nc, params->cnonce, params->qop, Ha2);
    else
        git_buf_printf(&response, "%s:%s:%s", Ha1, params->nonce, Ha2);
    H(&response, md);
    
    // Make digest
    git_buf_put(digest, authorization_digest, strlen(authorization_digest));
    git_buf_printf(digest, "username=\"%s\", ", params->username);
    git_buf_printf(digest, "realm=\"%s\", ", params->realm);
    git_buf_printf(digest, "nonce=\"%s\", ", params->nonce);
    git_buf_printf(digest, "uri=\"%s\", ", params->uri);
    git_buf_printf(digest, "qop=%s, ", params->qop);
    git_buf_printf(digest, "nc=%s, ", params->nc);
    git_buf_printf(digest, "cnonce=\"%s\", ", params->cnonce);
    git_buf_printf(digest, "response=\"%s\"\r\n", md);
}