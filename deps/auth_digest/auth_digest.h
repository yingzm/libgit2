//
//  auth_digest.h
//  GitMongo
//
//  Created by zouting on 4/29/13.
//  Copyright (c) 2013 zouting. All rights reserved.
//

#ifndef GitMongo_auth_digest_h
#define GitMongo_auth_digest_h

#include "buffer.h"

typedef struct DigestParams {
    char *method;
    char *uri;
    char *username;
    char *password;
    char *realm;
    char *domain;
    char *algorithm;
    char *nonce;
    char *cnonce;
    char *nc;
    char *qop;
} DigestParams;

void initDigestParams(DigestParams *params, const char *www_authenticate);
void freeDigestParams(DigestParams *params);
void calcDigest(DigestParams *params, git_buf *digest);

#endif
