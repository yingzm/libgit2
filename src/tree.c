/*
 * Copyright (C) 2009-2012 the libgit2 contributors
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"
#include "commit.h"
#include "tree.h"
#include "git2/repository.h"
#include "git2/object.h"

#define DEFAULT_TREE_SIZE 16
#define MAX_FILEMODE_BYTES 6

static bool valid_filemode(const int filemode)
{
	return (filemode == GIT_FILEMODE_TREE
		|| filemode == GIT_FILEMODE_BLOB
		|| filemode == GIT_FILEMODE_BLOB_EXECUTABLE
		|| filemode == GIT_FILEMODE_LINK
		|| filemode == GIT_FILEMODE_COMMIT);
}

GIT_INLINE(git_filemode_t) normalize_filemode(git_filemode_t filemode)
{
	/* Tree bits set, but it's not a commit */
	if (filemode & GIT_FILEMODE_TREE && !(filemode & 0100000))
		return GIT_FILEMODE_TREE;

	/* If any of the x bits is set */
	if (filemode & 0111)
		return GIT_FILEMODE_BLOB_EXECUTABLE;

	/* 16XXXX means commit */
	if ((filemode & GIT_FILEMODE_COMMIT) == GIT_FILEMODE_COMMIT)
		return GIT_FILEMODE_COMMIT;

	/* 12XXXX means commit */
	if ((filemode & GIT_FILEMODE_LINK) == GIT_FILEMODE_LINK)
		return GIT_FILEMODE_LINK;

	/* Otherwise, return a blob */
	return GIT_FILEMODE_BLOB;
}

static int valid_entry_name(const char *filename)
{
	return *filename != '\0' &&
		strchr(filename, '/') == NULL &&
		(*filename != '.' ||
		 (strcmp(filename, ".") != 0 &&
		  strcmp(filename, "..") != 0 &&
		  strcmp(filename, DOT_GIT) != 0));
}

static int entry_sort_cmp(const void *a, const void *b)
{
	const git_tree_entry *entry_a = (const git_tree_entry *)(a);
	const git_tree_entry *entry_b = (const git_tree_entry *)(b);

	return git_path_cmp(
		entry_a->filename, entry_a->filename_len, git_tree_entry__is_tree(entry_a),
		entry_b->filename, entry_b->filename_len, git_tree_entry__is_tree(entry_b));
}

static git_tree_entry *alloc_entry(const char *filename)
{
	git_tree_entry *entry = NULL;
	size_t filename_len = strlen(filename);

	entry = git__malloc(sizeof(git_tree_entry) + filename_len + 1);
	if (!entry)
		return NULL;

	memset(entry, 0x0, sizeof(git_tree_entry));
	memcpy(entry->filename, filename, filename_len);
	entry->filename[filename_len] = 0;
	entry->filename_len = filename_len;

	return entry;
}

struct tree_key_search {
	const char *filename;
	size_t filename_len;
};

static int homing_search_cmp(const void *key, const void *array_member)
{
	const struct tree_key_search *ksearch = key;
	const git_tree_entry *entry = array_member;

	const size_t len1 = ksearch->filename_len;
	const size_t len2 = entry->filename_len;

	return memcmp(
		ksearch->filename,
		entry->filename,
		len1 < len2 ? len1 : len2
	);
}

/*
 * Search for an entry in a given tree.
 *
 * Note that this search is performed in two steps because
 * of the way tree entries are sorted internally in git:
 *
 * Entries in a tree are not sorted alphabetically; two entries
 * with the same root prefix will have different positions
 * depending on whether they are folders (subtrees) or normal files.
 *
 * Consequently, it is not possible to find an entry on the tree
 * with a binary search if you don't know whether the filename
 * you're looking for is a folder or a normal file.
 *
 * To work around this, we first perform a homing binary search
 * on the tree, using the minimal length root prefix of our filename.
 * Once the comparisons for this homing search start becoming
 * ambiguous because of folder vs file sorting, we look linearly
 * around the area for our target file.
 */
static int tree_key_search(
	git_vector *entries, const char *filename, size_t filename_len)
{
	struct tree_key_search ksearch;
	const git_tree_entry *entry;
	int homing, i;

	ksearch.filename = filename;
	ksearch.filename_len = filename_len;

	/* Initial homing search; find an entry on the tree with
	 * the same prefix as the filename we're looking for */
	homing = git_vector_bsearch2(entries, &homing_search_cmp, &ksearch);
	if (homing < 0)
		return homing;

	/* We found a common prefix. Look forward as long as
	 * there are entries that share the common prefix */
	for (i = homing; i < (int)entries->length; ++i) {
		entry = entries->contents[i];

		if (homing_search_cmp(&ksearch, entry) < 0)
			break;

		if (entry->filename_len == filename_len &&
			memcmp(filename, entry->filename, filename_len) == 0)
			return i;
	}

	/* If we haven't found our filename yet, look backwards
	 * too as long as we have entries with the same prefix */
	for (i = homing - 1; i >= 0; --i) {
		entry = entries->contents[i];

		if (homing_search_cmp(&ksearch, entry) > 0)
			break;

		if (entry->filename_len == filename_len &&
			memcmp(filename, entry->filename, filename_len) == 0)
			return i;
	}

	/* The filename doesn't exist at all */
	return GIT_ENOTFOUND;
}

void git_tree_entry_free(git_tree_entry *entry)
{
	if (entry == NULL)
		return;

	git__free(entry);
}

git_tree_entry *git_tree_entry_dup(const git_tree_entry *entry)
{
	size_t total_size;
	git_tree_entry *copy;

	assert(entry);

	total_size = sizeof(git_tree_entry) + entry->filename_len + 1;

	copy = git__malloc(total_size);
	if (!copy)
		return NULL;

	memcpy(copy, entry, total_size);

	return copy;
}

void git_tree__free(git_tree *tree)
{
	unsigned int i;

	for (i = 0; i < tree->entries.length; ++i) {
		git_tree_entry *e = git_vector_get(&tree->entries, i);
		git_tree_entry_free(e);
	}

	git_vector_free(&tree->entries);
	git__free(tree);
}

const git_oid *git_tree_id(const git_tree *t)
{
	return git_object_id((const git_object *)t);
}

git_repository *git_tree_owner(const git_tree *t)
{
	return git_object_owner((const git_object *)t);
}

git_filemode_t git_tree_entry_filemode(const git_tree_entry *entry)
{
	return (git_filemode_t)entry->attr;
}

const char *git_tree_entry_name(const git_tree_entry *entry)
{
	assert(entry);
	return entry->filename;
}

const git_oid *git_tree_entry_id(const git_tree_entry *entry)
{
	assert(entry);
	return &entry->oid;
}

git_otype git_tree_entry_type(const git_tree_entry *entry)
{
	assert(entry);

	if (S_ISGITLINK(entry->attr))
		return GIT_OBJ_COMMIT;
	else if (S_ISDIR(entry->attr))
		return GIT_OBJ_TREE;
	else
		return GIT_OBJ_BLOB;
}

int git_tree_entry_to_object(
	git_object **object_out,
	git_repository *repo,
	const git_tree_entry *entry)
{
	assert(entry && object_out);
	return git_object_lookup(object_out, repo, &entry->oid, GIT_OBJ_ANY);
}

static const git_tree_entry *entry_fromname(
	git_tree *tree, const char *name, size_t name_len)
{
	int idx = tree_key_search(&tree->entries, name, name_len);
	if (idx < 0)
		return NULL;

	return git_vector_get(&tree->entries, idx);
}

const git_tree_entry *git_tree_entry_byname(
	git_tree *tree, const char *filename)
{
	assert(tree && filename);
	return entry_fromname(tree, filename, strlen(filename));
}

const git_tree_entry *git_tree_entry_byindex(
	git_tree *tree, size_t idx)
{
	assert(tree);
	return git_vector_get(&tree->entries, idx);
}

const git_tree_entry *git_tree_entry_byoid(
	const git_tree *tree, const git_oid *oid)
{
	size_t i;
	const git_tree_entry *e;

	assert(tree);

	git_vector_foreach(&tree->entries, i, e) {
		if (memcmp(&e->oid.id, &oid->id, sizeof(oid->id)) == 0)
			return e;
	}

	return NULL;
}

int git_tree__prefix_position(git_tree *tree, const char *path)
{
	git_vector *entries = &tree->entries;
	struct tree_key_search ksearch;
	size_t at_pos;

	if (!path)
		return 0;

	ksearch.filename = path;
	ksearch.filename_len = strlen(path);

	/* Find tree entry with appropriate prefix */
	git_vector_bsearch3(&at_pos, entries, &homing_search_cmp, &ksearch);

	for (; at_pos < entries->length; ++at_pos) {
		const git_tree_entry *entry = entries->contents[at_pos];
		if (homing_search_cmp(&ksearch, entry) < 0)
			break;
	}

	for (; at_pos > 0; --at_pos) {
		const git_tree_entry *entry = entries->contents[at_pos - 1];
		if (homing_search_cmp(&ksearch, entry) > 0)
			break;
	}

	return (int)at_pos;
}

size_t git_tree_entrycount(const git_tree *tree)
{
	assert(tree);
	return tree->entries.length;
}

static int tree_error(const char *str, const char *path)
{
	if (path)
		giterr_set(GITERR_TREE, "%s - %s", str, path);
	else
		giterr_set(GITERR_TREE, "%s", str);
	return -1;
}

static int tree_parse_buffer(git_tree *tree, const char *buffer, const char *buffer_end)
{
	if (git_vector_init(&tree->entries, DEFAULT_TREE_SIZE, entry_sort_cmp) < 0)
		return -1;

	while (buffer < buffer_end) {
		git_tree_entry *entry;
		int attr;

		if (git__strtol32(&attr, buffer, &buffer, 8) < 0 || !buffer)
			return tree_error("Failed to parse tree. Can't parse filemode", NULL);

		attr = normalize_filemode(attr); /* make sure to normalize the filemode */

		if (*buffer++ != ' ')
			return tree_error("Failed to parse tree. Object is corrupted", NULL);

		if (memchr(buffer, 0, buffer_end - buffer) == NULL)
			return tree_error("Failed to parse tree. Object is corrupted", NULL);

		/** Allocate the entry and store it in the entries vector */
		{
			entry = alloc_entry(buffer);
			GITERR_CHECK_ALLOC(entry);

			if (git_vector_insert(&tree->entries, entry) < 0)
				return -1;

			entry->attr = attr;
		}

		while (buffer < buffer_end && *buffer != 0)
			buffer++;

		buffer++;

		git_oid_fromraw(&entry->oid, (const unsigned char *)buffer);
		buffer += GIT_OID_RAWSZ;
	}

	return 0;
}

int git_tree__parse(git_tree *tree, git_odb_object *obj)
{
	assert(tree);
	return tree_parse_buffer(tree, (char *)obj->raw.data, (char *)obj->raw.data + obj->raw.len);
}

static size_t find_next_dir(const char *dirname, git_index *index, size_t start)
{
	size_t dirlen, i, entries = git_index_entrycount(index);

	dirlen = strlen(dirname);
	for (i = start; i < entries; ++i) {
		const git_index_entry *entry = git_index_get_byindex(index, i);
		if (strlen(entry->path) < dirlen ||
		    memcmp(entry->path, dirname, dirlen) ||
			(dirlen > 0 && entry->path[dirlen] != '/')) {
			break;
		}
	}

	return i;
}

static int append_entry(
	git_treebuilder *bld,
	const char *filename,
	const git_oid *id,
	git_filemode_t filemode)
{
	git_tree_entry *entry;

	if (!valid_entry_name(filename))
		return tree_error("Failed to insert entry. Invalid name for a tree entry", filename);

	entry = alloc_entry(filename);
	GITERR_CHECK_ALLOC(entry);

	git_oid_cpy(&entry->oid, id);
	entry->attr = (uint16_t)filemode;

	if (git_vector_insert(&bld->entries, entry) < 0)
		return -1;

	return 0;
}

static int write_tree(
	git_oid *oid,
	git_repository *repo,
	git_index *index,
	const char *dirname,
	size_t start)
{
	git_treebuilder *bld = NULL;
	size_t i, entries = git_index_entrycount(index);
	int error;
	size_t dirname_len = strlen(dirname);
	const git_tree_cache *cache;

	cache = git_tree_cache_get(index->tree, dirname);
	if (cache != NULL && cache->entries >= 0){
		git_oid_cpy(oid, &cache->oid);
		return (int)find_next_dir(dirname, index, start);
	}

	if ((error = git_treebuilder_create(&bld, NULL)) < 0 || bld == NULL)
		return -1;

	/*
	 * This loop is unfortunate, but necessary. The index doesn't have
	 * any directores, so we need to handle that manually, and we
	 * need to keep track of the current position.
	 */
	for (i = start; i < entries; ++i) {
		const git_index_entry *entry = git_index_get_byindex(index, i);
		const char *filename, *next_slash;

	/*
	 * If we've left our (sub)tree, exit the loop and return. The
	 * first check is an early out (and security for the
	 * third). The second check is a simple prefix comparison. The
	 * third check catches situations where there is a directory
	 * win32/sys and a file win32mmap.c. Without it, the following
	 * code believes there is a file win32/mmap.c
	 */
		if (strlen(entry->path) < dirname_len ||
		    memcmp(entry->path, dirname, dirname_len) ||
		    (dirname_len > 0 && entry->path[dirname_len] != '/')) {
			break;
		}

		filename = entry->path + dirname_len;
		if (*filename == '/')
			filename++;
		next_slash = strchr(filename, '/');
		if (next_slash) {
			git_oid sub_oid;
			int written;
			char *subdir, *last_comp;

			subdir = git__strndup(entry->path, next_slash - entry->path);
			GITERR_CHECK_ALLOC(subdir);

			/* Write out the subtree */
			written = write_tree(&sub_oid, repo, index, subdir, i);
			if (written < 0) {
				tree_error("Failed to write subtree", subdir);
				git__free(subdir);
				goto on_error;
			} else {
				i = written - 1; /* -1 because of the loop increment */
			}

			/*
			 * We need to figure out what we want toinsert
			 * into this tree. If we're traversing
			 * deps/zlib/, then we only want to write
			 * 'zlib' into the tree.
			 */
			last_comp = strrchr(subdir, '/');
			if (last_comp) {
				last_comp++; /* Get rid of the '/' */
			} else {
				last_comp = subdir;
			}

			error = append_entry(bld, last_comp, &sub_oid, S_IFDIR);
			git__free(subdir);
			if (error < 0)
				goto on_error;
		} else {
			error = append_entry(bld, filename, &entry->oid, entry->mode);
			if (error < 0)
				goto on_error;
		}
	}

	if (git_treebuilder_write(oid, repo, bld) < 0)
		goto on_error;

	git_treebuilder_free(bld);
	return (int)i;

on_error:
	git_treebuilder_free(bld);
	return -1;
}

int git_tree__write_index(
	git_oid *oid, git_index *index, git_repository *repo)
{
	int ret;

	assert(oid && index && repo);

	if (git_index_has_conflicts(index)) {
		giterr_set(GITERR_INDEX,
			"Cannot create a tree from a not fully merged index.");
		return GIT_EUNMERGED;
	}

	if (index->tree != NULL && index->tree->entries >= 0) {
		git_oid_cpy(oid, &index->tree->oid);
		return 0;
	}

	/* The tree cache didn't help us */
	ret = write_tree(oid, repo, index, "", 0);
	return ret < 0 ? ret : 0;
}

static void sort_entries(git_treebuilder *bld)
{
	git_vector_sort(&bld->entries);
}

int git_treebuilder_create(git_treebuilder **builder_p, const git_tree *source)
{
	git_treebuilder *bld;
	size_t i, source_entries = DEFAULT_TREE_SIZE;

	assert(builder_p);

	bld = git__calloc(1, sizeof(git_treebuilder));
	GITERR_CHECK_ALLOC(bld);

	if (source != NULL)
		source_entries = source->entries.length;

	if (git_vector_init(&bld->entries, source_entries, entry_sort_cmp) < 0)
		goto on_error;

	if (source != NULL) {
		for (i = 0; i < source->entries.length; ++i) {
			git_tree_entry *entry_src = source->entries.contents[i];

			if (append_entry(
				bld, entry_src->filename,
				&entry_src->oid,
				entry_src->attr) < 0)
				goto on_error;
		}
	}

	*builder_p = bld;
	return 0;

on_error:
	git_treebuilder_free(bld);
	return -1;
}

int git_treebuilder_insert(
	const git_tree_entry **entry_out,
	git_treebuilder *bld,
	const char *filename,
	const git_oid *id,
	git_filemode_t filemode)
{
	git_tree_entry *entry;
	int pos;

	assert(bld && id && filename);

	if (!valid_filemode(filemode))
		return tree_error("Failed to insert entry. Invalid filemode for file", filename);

	if (!valid_entry_name(filename))
		return tree_error("Failed to insert entry. Invalid name for a tree entry", filename);

	pos = tree_key_search(&bld->entries, filename, strlen(filename));

	if (pos >= 0) {
		entry = git_vector_get(&bld->entries, pos);
		if (entry->removed)
			entry->removed = 0;
	} else {
		entry = alloc_entry(filename);
		GITERR_CHECK_ALLOC(entry);
	}

	git_oid_cpy(&entry->oid, id);
	entry->attr = filemode;

	if (pos < 0) {
		if (git_vector_insert(&bld->entries, entry) < 0)
			return -1;
	}

	if (entry_out != NULL) {
		*entry_out = entry;
	}

	return 0;
}

static git_tree_entry *treebuilder_get(git_treebuilder *bld, const char *filename)
{
	int idx;
	git_tree_entry *entry;

	assert(bld && filename);

	idx = tree_key_search(&bld->entries, filename, strlen(filename));
	if (idx < 0)
		return NULL;

	entry = git_vector_get(&bld->entries, idx);
	if (entry->removed)
		return NULL;

	return entry;
}

const git_tree_entry *git_treebuilder_get(git_treebuilder *bld, const char *filename)
{
	return treebuilder_get(bld, filename);
}

int git_treebuilder_remove(git_treebuilder *bld, const char *filename)
{
	git_tree_entry *remove_ptr = treebuilder_get(bld, filename);

	if (remove_ptr == NULL || remove_ptr->removed)
		return tree_error("Failed to remove entry. File isn't in the tree", filename);

	remove_ptr->removed = 1;
	return 0;
}

int git_treebuilder_write(git_oid *oid, git_repository *repo, git_treebuilder *bld)
{
	unsigned int i;
	git_buf tree = GIT_BUF_INIT;
	git_odb *odb;

	assert(bld);

	sort_entries(bld);

	/* Grow the buffer beforehand to an estimated size */
	git_buf_grow(&tree, bld->entries.length * 72);

	for (i = 0; i < bld->entries.length; ++i) {
		git_tree_entry *entry = bld->entries.contents[i];

		if (entry->removed)
			continue;

		git_buf_printf(&tree, "%o ", entry->attr);
		git_buf_put(&tree, entry->filename, entry->filename_len + 1);
		git_buf_put(&tree, (char *)entry->oid.id, GIT_OID_RAWSZ);
	}

	if (git_buf_oom(&tree))
		goto on_error;

	if (git_repository_odb__weakptr(&odb, repo) < 0)
		goto on_error;


	if (git_odb_write(oid, odb, tree.ptr, tree.size, GIT_OBJ_TREE) < 0)
		goto on_error;

	git_buf_free(&tree);
	return 0;

on_error:
	git_buf_free(&tree);
	return -1;
}

void git_treebuilder_filter(
	git_treebuilder *bld,
	git_treebuilder_filter_cb filter,
	void *payload)
{
	unsigned int i;

	assert(bld && filter);

	for (i = 0; i < bld->entries.length; ++i) {
		git_tree_entry *entry = bld->entries.contents[i];
		if (!entry->removed && filter(entry, payload))
			entry->removed = 1;
	}
}

void git_treebuilder_clear(git_treebuilder *bld)
{
	unsigned int i;
	assert(bld);

	for (i = 0; i < bld->entries.length; ++i) {
		git_tree_entry *e = bld->entries.contents[i];
		git_tree_entry_free(e);
	}

	git_vector_clear(&bld->entries);
}

void git_treebuilder_free(git_treebuilder *bld)
{
	if (bld == NULL)
		return;

	git_treebuilder_clear(bld);
	git_vector_free(&bld->entries);
	git__free(bld);
}

static size_t subpath_len(const char *path)
{
	const char *slash_pos = strchr(path, '/');
	if (slash_pos == NULL)
		return strlen(path);

	return slash_pos - path;
}

int git_tree_entry_bypath(
	git_tree_entry **entry_out,
	git_tree *root,
	const char *path)
{
	int error = 0;
	git_tree *subtree;
	const git_tree_entry *entry;
	size_t filename_len;

	/* Find how long is the current path component (i.e.
	 * the filename between two slashes */
	filename_len = subpath_len(path);

	if (filename_len == 0) {
		giterr_set(GITERR_TREE, "Invalid tree path given");
		return GIT_ENOTFOUND;
	}

	entry = entry_fromname(root, path, filename_len);

	if (entry == NULL) {
		giterr_set(GITERR_TREE,
			"The path '%s' does not exist in the given tree", path);
		return GIT_ENOTFOUND;
	}

	switch (path[filename_len]) {
	case '/':
		/* If there are more components in the path...
		 * then this entry *must* be a tree */
		if (!git_tree_entry__is_tree(entry)) {
			giterr_set(GITERR_TREE,
				"The path '%s' does not exist in the given tree", path);
			return GIT_ENOTFOUND;
		}

		/* If there's only a slash left in the path, we 
		 * return the current entry; otherwise, we keep
		 * walking down the path */
		if (path[filename_len + 1] != '\0')
			break;

	case '\0':
		/* If there are no more components in the path, return
		 * this entry */
		*entry_out = git_tree_entry_dup(entry);
		return 0;
	}

	if (git_tree_lookup(&subtree, root->object.repo, &entry->oid) < 0)
		return -1;

	error = git_tree_entry_bypath(
		entry_out,
		subtree,
		path + filename_len + 1
	);

	git_tree_free(subtree);
	return error;
}

static int tree_walk(
	const git_tree *tree,
	git_treewalk_cb callback,
	git_buf *path,
	void *payload,
	bool preorder)
{
	int error = 0;
	size_t i;

	for (i = 0; i < tree->entries.length; ++i) {
		const git_tree_entry *entry = tree->entries.contents[i];

		if (preorder) {
			error = callback(path->ptr, entry, payload);
			if (error > 0)
				continue;
			if (error < 0)
				return GIT_EUSER;
		}

		if (git_tree_entry__is_tree(entry)) {
			git_tree *subtree;
			size_t path_len = git_buf_len(path);

			if ((error = git_tree_lookup(
				&subtree, tree->object.repo, &entry->oid)) < 0)
				break;

			/* append the next entry to the path */
			git_buf_puts(path, entry->filename);
			git_buf_putc(path, '/');

			if (git_buf_oom(path))
				return -1;

			error = tree_walk(subtree, callback, path, payload, preorder);
			if (error != 0)
				break;

			git_buf_truncate(path, path_len);
			git_tree_free(subtree);
		}

		if (!preorder && callback(path->ptr, entry, payload) < 0) {
			error = GIT_EUSER;
			break;
		}
	}

	return error;
}

int git_tree_walk(
	const git_tree *tree,
	git_treewalk_mode mode,
	git_treewalk_cb callback,
	void *payload)
{
	int error = 0;
	git_buf root_path = GIT_BUF_INIT;

	switch (mode) {
	case GIT_TREEWALK_POST:
		error = tree_walk(tree, callback, &root_path, payload, false);
		break;

	case GIT_TREEWALK_PRE:
		error = tree_walk(tree, callback, &root_path, payload, true);
		break;

	default:
		giterr_set(GITERR_INVALID, "Invalid walking mode for tree walk");
		return -1;
	}

	git_buf_free(&root_path);

	return error;
}

