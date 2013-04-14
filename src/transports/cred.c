/*
 * Copyright (C) 2009-2012 the libgit2 contributors
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "git2.h"
#include "smart.h"

static void plaintext_free(struct git_cred *cred)
{
	git_cred_userpass_plaintext *c = (git_cred_userpass_plaintext *)cred;
	size_t pass_len = strlen(c->password);

	git__free(c->username);

	/* Zero the memory which previously held the password */
	memset(c->password, 0x0, pass_len);
	git__free(c->password);

	memset(c, 0, sizeof(*c));

	git__free(c);
}

int git_cred_userpass_plaintext_new(
	git_cred **cred,
	const char *username,
	const char *password)
{
	git_cred_userpass_plaintext *c;

	if (!cred)
		return -1;

	c = git__malloc(sizeof(git_cred_userpass_plaintext));
	GITERR_CHECK_ALLOC(c);

	c->parent.credtype = GIT_CREDTYPE_USERPASS_PLAINTEXT;
	c->parent.free = plaintext_free;
	c->username = git__strdup(username);

	if (!c->username) {
		git__free(c);
		return -1;
	}

	c->password = git__strdup(password);

	if (!c->password) {
		git__free(c->username);
		git__free(c);
		return -1;
	}

	*cred = &c->parent;
	return 0;
}

int git_cred_userpass_base64_new(
	git_cred **cred,
	const char *username,
	const char *password)
{
	git_cred_userpass_base64 *c;

	if (!cred)
		return -1;

	c = git__malloc(sizeof(git_cred_userpass_base64));
	GITERR_CHECK_ALLOC(c);

	c->parent.credtype = GIT_CREDTYPE_USERPASS_BASE64;
	c->parent.free = plaintext_free;
	c->username = git__strdup(username);

	if (!c->username) {
		git__free(c);
		return -1;
	}

	c->password = git__strdup(password);

	if (!c->password) {
		git__free(c->username);
		git__free(c);
		return -1;
	}

	*cred = &c->parent;
	return 0;
}

static void ssh_password_free(git_cred *cred)
{
	git_cred_ssh_password *c = (git_cred_ssh_password *)cred;
	int pass_len = strlen(c->password);

	git__free(c->username);

	/* Zero the memory which previously held the password */
	memset(c->password, 0x0, pass_len);
	git__free(c->password);

	git__free(c);
}

int git_cred_ssh_password_new(
	git_cred **cred,
	const char *username,
	const char *password)
{
	git_cred_ssh_password *c;

	if (!cred)
		return -1;

	c = (git_cred_ssh_password *)git__malloc(sizeof(git_cred_ssh_password));
	GITERR_CHECK_ALLOC(c);

	c->parent.credtype = GIT_CREDTYPE_SSH_PASSWORD;
	c->parent.free = ssh_password_free;
	c->username = git__strdup(username);

	if (!c->username) {
		git__free(c);
		return -1;
	}

	c->password = git__strdup(password);

	if (!c->password) {
		git__free(c->username);
		git__free(c);
		return -1;
	}
    
    *cred = &c->parent;
    
    return 0;
}

static void ssh_key_free(git_cred *cred)
{
	git_cred_ssh_key *c = (git_cred_ssh_key *)cred;

    if (c->pass)
        git__free(c->pass);
    
    if (c->private_key)
        git__free(c->private_key);

    if (c->username)
        git__free(c->username);

	git__free(c);
}

int git_cred_ssh_key_new(
    git_cred **cred,
    const char *username,
    const char *private_key,
    const char *pass)
{
    git_cred_ssh_key *c;
    
    if (!cred)
        return -1;
    
    c = (git_cred_ssh_key *)git__malloc(sizeof(git_cred_ssh_key));
    GITERR_CHECK_ALLOC(c);
    
    c->parent.credtype = GIT_CREDTYPE_SSH_KEY;
    c->parent.free = ssh_key_free;
    c->username = git__strdup(username);
    c->private_key = git__strdup(private_key);
    if (pass)
        c->pass = git__strdup(pass);
    else
        c->pass = NULL;
    
    *cred = &c->parent;
    
    return 0;
    
}

