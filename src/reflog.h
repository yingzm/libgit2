/*
 * Copyright (C) 2009-2012 the libgit2 contributors
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_reflog_h__
#define INCLUDE_reflog_h__

#include "common.h"
#include "git2/reflog.h"
#include "vector.h"

#define GIT_REFLOG_DIR "logs/"
#define GIT_REFLOG_DIR_MODE 0777
#define GIT_REFLOG_FILE_MODE 0666

#define GIT_REFLOG_SIZE_MIN (2*GIT_OID_HEXSZ+2+17)

struct git_reflog_entry {
	git_oid oid_old;
	git_oid oid_cur;

	git_signature *committer;

	char *msg;
};

struct git_reflog {
	char *ref_name;
	git_repository *owner;
	git_vector entries;
};

#endif /* INCLUDE_reflog_h__ */
