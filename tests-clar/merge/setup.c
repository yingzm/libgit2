#include "clar_libgit2.h"
#include "git2/repository.h"
#include "git2/merge.h"
#include "merge.h"
#include "merge_helpers.h"
#include "refs.h"
#include "fileops.h"

static git_repository *repo;
static git_index *repo_index;

// #define TEST_REPO_PATH "testrepo"
#define TEST_REPO_PATH "merge-resolve"
#define TEST_INDEX_PATH TEST_REPO_PATH "/.git/index"

#define ORIG_HEAD                   "bd593285fc7fe4ca18ccdbabf027f5d689101452"

#define THEIRS_SIMPLE_BRANCH        "branch"
#define THEIRS_SIMPLE_OID           "7cb63eed597130ba4abb87b3e544b85021905520"

#define OCTO1_BRANCH                "octo1"
#define OCTO1_OID                   "16f825815cfd20a07a75c71554e82d8eede0b061"

#define OCTO2_BRANCH                "octo2"
#define OCTO2_OID                   "158dc7bedb202f5b26502bf3574faa7f4238d56c"

#define OCTO3_BRANCH                "octo3"
#define OCTO3_OID                   "50ce7d7d01217679e26c55939eef119e0c93e272"

#define OCTO4_BRANCH                "octo4"
#define OCTO4_OID                   "54269b3f6ec3d7d4ede24dd350dd5d605495c3ae"

#define OCTO5_BRANCH                "octo5"
#define OCTO5_OID                   "e4f618a2c3ed0669308735727df5ebf2447f022f"

// Fixture setup and teardown
void test_merge_setup__initialize(void)
{
	repo = cl_git_sandbox_init(TEST_REPO_PATH);
    git_repository_index(&repo_index, repo);
}

void test_merge_setup__cleanup(void)
{
    git_index_free(repo_index);
	cl_git_sandbox_cleanup();
}

<<<<<<< HEAD
static void write_file_contents(const char *filename, const char *output)
{
	git_buf file_path_buf = GIT_BUF_INIT;

    git_buf_printf(&file_path_buf, "%s/%s", git_repository_path(repo), filename);
	cl_git_rewritefile(file_path_buf.ptr, output);

	git_buf_free(&file_path_buf);
}

struct merge_head_cb_data {
	const char **oid_str;
	unsigned int len;

	unsigned int i;
};

static int merge_head_foreach_cb(const git_oid *oid, void *payload)
{
	git_oid expected_oid;
	struct merge_head_cb_data *cb_data = payload;

	git_oid_fromstr(&expected_oid, cb_data->oid_str[cb_data->i]);
	cl_assert(git_oid_cmp(&expected_oid, oid) == 0);
	cb_data->i++;
	return 0;
}

void test_merge_setup__head_notfound(void)
{
	int error;

	cl_git_fail((error = git_repository_mergehead_foreach(repo,
		merge_head_foreach_cb, NULL)));
	cl_assert(error == GIT_ENOTFOUND);
}

void test_merge_setup__head_invalid_oid(void)
{
	int error;

	write_file_contents(GIT_MERGE_HEAD_FILE, "invalid-oid\n");

	cl_git_fail((error = git_repository_mergehead_foreach(repo,
		merge_head_foreach_cb, NULL)));
	cl_assert(error == -1);
}

void test_merge_setup__head_foreach_nonewline(void)
{
	int error;

	write_file_contents(GIT_MERGE_HEAD_FILE, THEIRS_SIMPLE_OID);

	cl_git_fail((error = git_repository_mergehead_foreach(repo,
		merge_head_foreach_cb, NULL)));
	cl_assert(error == -1);
}

void test_merge_setup__head_foreach_one(void)
{
	const char *expected = THEIRS_SIMPLE_OID;

	struct merge_head_cb_data cb_data = { &expected, 1 };

	write_file_contents(GIT_MERGE_HEAD_FILE, THEIRS_SIMPLE_OID "\n");

	cl_git_pass(git_repository_mergehead_foreach(repo,
		merge_head_foreach_cb, &cb_data));

	cl_assert(cb_data.i == cb_data.len);
}

void test_merge_setup__head_foreach_octopus(void)
{
	const char *expected[] = { THEIRS_SIMPLE_OID,
		OCTO1_OID, OCTO2_OID, OCTO3_OID, OCTO4_OID, OCTO5_OID };

	struct merge_head_cb_data cb_data = { expected, 6 };

	write_file_contents(GIT_MERGE_HEAD_FILE,
		THEIRS_SIMPLE_OID "\n"
		OCTO1_OID "\n"
		OCTO2_OID "\n"
		OCTO3_OID "\n"
		OCTO4_OID "\n"
		OCTO5_OID "\n");

	cl_git_pass(git_repository_mergehead_foreach(repo,
		merge_head_foreach_cb, &cb_data));

	cl_assert(cb_data.i == cb_data.len);
=======
static bool test_file_contents(const char *filename, const char *expected)
{
    git_buf file_path_buf = GIT_BUF_INIT, file_buf = GIT_BUF_INIT;
    bool equals;
    
    git_buf_printf(&file_path_buf, "%s/%s", git_repository_path(repo), filename);
    
    cl_git_pass(git_futils_readbuffer(&file_buf, file_path_buf.ptr));
    equals = (strcmp(file_buf.ptr, expected) == 0);

    git_buf_free(&file_path_buf);
    git_buf_free(&file_buf);
    
    return equals;
}

/* git merge --no-ff octo1 */
void test_merge_setup__one_branch(void)
{
	git_oid our_oid;
    git_reference *octo1_ref;
    git_merge_head *our_head, *their_heads[1];
    
	cl_git_pass(git_oid_fromstr(&our_oid, ORIG_HEAD));
	cl_git_pass(git_merge_head_from_oid(&our_head, repo, &our_oid));
	
    cl_git_pass(git_reference_lookup(&octo1_ref, repo, GIT_REFS_HEADS_DIR OCTO1_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[0], repo, octo1_ref));
    
	cl_git_pass(git_merge__setup(repo, our_head, (const git_merge_head **)their_heads, 1, GIT_MERGE_NO_FASTFORWARD));

    cl_assert(test_file_contents(GIT_MERGE_HEAD_FILE, OCTO1_OID "\n"));
    cl_assert(test_file_contents(GIT_ORIG_HEAD_FILE, ORIG_HEAD "\n"));
    cl_assert(test_file_contents(GIT_MERGE_MODE_FILE, "no-ff"));
    cl_assert(test_file_contents(GIT_MERGE_MSG_FILE, "Merge branch '" OCTO1_BRANCH "'\n"));

    git_reference_free(octo1_ref);
    
	git_merge_head_free(our_head);
    git_merge_head_free(their_heads[0]);
}

/* git merge --no-ff 16f825815cfd20a07a75c71554e82d8eede0b061 */
void test_merge_setup__one_oid(void)
{
	git_oid our_oid;
    git_oid octo1_oid;
    git_merge_head *our_head, *their_heads[1];
    
	cl_git_pass(git_oid_fromstr(&our_oid, ORIG_HEAD));
	cl_git_pass(git_merge_head_from_oid(&our_head, repo, &our_oid));
	
    cl_git_pass(git_oid_fromstr(&octo1_oid, OCTO1_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[0], repo, &octo1_oid));

	cl_git_pass(git_merge__setup(repo, our_head, (const git_merge_head **)their_heads, 1, GIT_MERGE_NO_FASTFORWARD));

    cl_assert(test_file_contents(GIT_MERGE_HEAD_FILE, OCTO1_OID "\n"));
    cl_assert(test_file_contents(GIT_ORIG_HEAD_FILE, ORIG_HEAD "\n"));
    cl_assert(test_file_contents(GIT_MERGE_MODE_FILE, "no-ff"));
    cl_assert(test_file_contents(GIT_MERGE_MSG_FILE, "Merge commit '" OCTO1_OID "'\n"));

	git_merge_head_free(our_head);
    git_merge_head_free(their_heads[0]);
}

/* git merge octo1 octo2 */
void test_merge_setup__two_branches(void)
{
	git_oid our_oid;
    git_reference *octo1_ref;
    git_reference *octo2_ref;
    git_merge_head *our_head, *their_heads[2];
    
	cl_git_pass(git_oid_fromstr(&our_oid, ORIG_HEAD));
	cl_git_pass(git_merge_head_from_oid(&our_head, repo, &our_oid));
	
    cl_git_pass(git_reference_lookup(&octo1_ref, repo, GIT_REFS_HEADS_DIR OCTO1_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[0], repo, octo1_ref));

    cl_git_pass(git_reference_lookup(&octo2_ref, repo, GIT_REFS_HEADS_DIR OCTO2_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[1], repo, octo2_ref));

	cl_git_pass(git_merge__setup(repo, our_head, (const git_merge_head **)their_heads, 2, 0));
    
    cl_assert(test_file_contents(GIT_MERGE_HEAD_FILE, OCTO1_OID "\n" OCTO2_OID "\n"));
    cl_assert(test_file_contents(GIT_ORIG_HEAD_FILE, ORIG_HEAD "\n"));
    cl_assert(test_file_contents(GIT_MERGE_MODE_FILE, ""));
    cl_assert(test_file_contents(GIT_MERGE_MSG_FILE, "Merge branches '" OCTO1_BRANCH "' and '" OCTO2_BRANCH "'\n"));
    
    git_reference_free(octo1_ref);
    git_reference_free(octo2_ref);
    
	git_merge_head_free(our_head);
    git_merge_head_free(their_heads[0]);
    git_merge_head_free(their_heads[1]);
}

/* git merge octo1 octo2 octo3 */
void test_merge_setup__three_branches(void)
{
	git_oid our_oid;
    git_reference *octo1_ref;
    git_reference *octo2_ref;
    git_reference *octo3_ref;
    git_merge_head *our_head, *their_heads[3];
    
	cl_git_pass(git_oid_fromstr(&our_oid, ORIG_HEAD));
	cl_git_pass(git_merge_head_from_oid(&our_head, repo, &our_oid));

    cl_git_pass(git_reference_lookup(&octo1_ref, repo, GIT_REFS_HEADS_DIR OCTO1_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[0], repo, octo1_ref));
    
    cl_git_pass(git_reference_lookup(&octo2_ref, repo, GIT_REFS_HEADS_DIR OCTO2_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[1], repo, octo2_ref));

    cl_git_pass(git_reference_lookup(&octo3_ref, repo, GIT_REFS_HEADS_DIR OCTO3_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[2], repo, octo3_ref));

	cl_git_pass(git_merge__setup(repo, our_head, (const git_merge_head **)their_heads, 3, 0));

    cl_assert(test_file_contents(GIT_MERGE_HEAD_FILE, OCTO1_OID "\n" OCTO2_OID "\n" OCTO3_OID "\n"));
    cl_assert(test_file_contents(GIT_ORIG_HEAD_FILE, ORIG_HEAD "\n"));
    cl_assert(test_file_contents(GIT_MERGE_MODE_FILE, ""));
    cl_assert(test_file_contents(GIT_MERGE_MSG_FILE, "Merge branches '" OCTO1_BRANCH "', '" OCTO2_BRANCH "' and '" OCTO3_BRANCH "'\n"));
    
    git_reference_free(octo1_ref);
    git_reference_free(octo2_ref);
    git_reference_free(octo3_ref);

	git_merge_head_free(our_head);
    git_merge_head_free(their_heads[0]);
    git_merge_head_free(their_heads[1]);
    git_merge_head_free(their_heads[2]);
}

/* git merge 16f825815cfd20a07a75c71554e82d8eede0b061 158dc7bedb202f5b26502bf3574faa7f4238d56c 50ce7d7d01217679e26c55939eef119e0c93e272 */
void test_merge_setup__three_oids(void)
{
	git_oid our_oid;
    git_oid octo1_oid;
    git_oid octo2_oid;
    git_oid octo3_oid;
    git_merge_head *our_head, *their_heads[3];
    
	cl_git_pass(git_oid_fromstr(&our_oid, ORIG_HEAD));
	cl_git_pass(git_merge_head_from_oid(&our_head, repo, &our_oid));

    cl_git_pass(git_oid_fromstr(&octo1_oid, OCTO1_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[0], repo, &octo1_oid));
    
    cl_git_pass(git_oid_fromstr(&octo2_oid, OCTO2_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[1], repo, &octo2_oid));

    cl_git_pass(git_oid_fromstr(&octo3_oid, OCTO3_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[2], repo, &octo3_oid));

	cl_git_pass(git_merge__setup(repo, our_head, (const git_merge_head **)their_heads, 3, 0));

    cl_assert(test_file_contents(GIT_MERGE_HEAD_FILE, OCTO1_OID "\n" OCTO2_OID "\n" OCTO3_OID "\n"));
    cl_assert(test_file_contents(GIT_ORIG_HEAD_FILE, ORIG_HEAD "\n"));
    cl_assert(test_file_contents(GIT_MERGE_MODE_FILE, ""));
    cl_assert(test_file_contents(GIT_MERGE_MSG_FILE, "Merge commit '" OCTO1_OID "'; commit '" OCTO2_OID "'; commit '" OCTO3_OID "'\n"));
    
	git_merge_head_free(our_head);
    git_merge_head_free(their_heads[0]);
    git_merge_head_free(their_heads[1]);
    git_merge_head_free(their_heads[2]);
}

/* git merge octo1 158dc7bedb202f5b26502bf3574faa7f4238d56c */
void test_merge_setup__branches_and_oids_1(void)
{
	git_oid our_oid;
    git_reference *octo1_ref;
    git_oid octo2_oid;
    git_merge_head *our_head, *their_heads[2];
	
	cl_git_pass(git_oid_fromstr(&our_oid, ORIG_HEAD));
	cl_git_pass(git_merge_head_from_oid(&our_head, repo, &our_oid));

    cl_git_pass(git_reference_lookup(&octo1_ref, repo, GIT_REFS_HEADS_DIR OCTO1_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[0], repo, octo1_ref));

    cl_git_pass(git_oid_fromstr(&octo2_oid, OCTO2_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[1], repo, &octo2_oid));

	cl_git_pass(git_merge__setup(repo, our_head, (const git_merge_head **)their_heads, 2, 0));

    cl_assert(test_file_contents(GIT_MERGE_HEAD_FILE, OCTO1_OID "\n" OCTO2_OID "\n"));
    cl_assert(test_file_contents(GIT_ORIG_HEAD_FILE, ORIG_HEAD "\n"));
    cl_assert(test_file_contents(GIT_MERGE_MODE_FILE, ""));
    cl_assert(test_file_contents(GIT_MERGE_MSG_FILE, "Merge branch '" OCTO1_BRANCH "'; commit '" OCTO2_OID "'\n"));
    
    git_reference_free(octo1_ref);

	git_merge_head_free(our_head);
    git_merge_head_free(their_heads[0]);
    git_merge_head_free(their_heads[1]);
}

/* git merge octo1 158dc7bedb202f5b26502bf3574faa7f4238d56c octo3 54269b3f6ec3d7d4ede24dd350dd5d605495c3ae */
void test_merge_setup__branches_and_oids_2(void)
{
	git_oid our_oid;
    git_reference *octo1_ref;
    git_oid octo2_oid;
    git_reference *octo3_ref;
    git_oid octo4_oid;
    git_merge_head *our_head, *their_heads[4];

	cl_git_pass(git_oid_fromstr(&our_oid, ORIG_HEAD));
	cl_git_pass(git_merge_head_from_oid(&our_head, repo, &our_oid));

    cl_git_pass(git_reference_lookup(&octo1_ref, repo, GIT_REFS_HEADS_DIR OCTO1_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[0], repo, octo1_ref));
    
    cl_git_pass(git_oid_fromstr(&octo2_oid, OCTO2_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[1], repo, &octo2_oid));

    cl_git_pass(git_reference_lookup(&octo3_ref, repo, GIT_REFS_HEADS_DIR OCTO3_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[2], repo, octo3_ref));
    
    cl_git_pass(git_oid_fromstr(&octo4_oid, OCTO4_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[3], repo, &octo4_oid));
    
	cl_git_pass(git_merge__setup(repo, our_head, (const git_merge_head **)their_heads, 4, 0));

    cl_assert(test_file_contents(GIT_MERGE_HEAD_FILE, OCTO1_OID "\n" OCTO2_OID "\n" OCTO3_OID "\n" OCTO4_OID "\n"));
    cl_assert(test_file_contents(GIT_ORIG_HEAD_FILE, ORIG_HEAD "\n"));
    cl_assert(test_file_contents(GIT_MERGE_MODE_FILE, ""));
    cl_assert(test_file_contents(GIT_MERGE_MSG_FILE, "Merge branches '" OCTO1_BRANCH "' and '" OCTO3_BRANCH "'; commit '" OCTO2_OID "'; commit '" OCTO4_OID "'\n"));
    
    git_reference_free(octo1_ref);
    git_reference_free(octo3_ref);

	git_merge_head_free(our_head);
    git_merge_head_free(their_heads[0]);
    git_merge_head_free(their_heads[1]);
    git_merge_head_free(their_heads[2]);
    git_merge_head_free(their_heads[3]);
}

/* git merge 16f825815cfd20a07a75c71554e82d8eede0b061 octo2 50ce7d7d01217679e26c55939eef119e0c93e272 octo4 */
void test_merge_setup__branches_and_oids_3(void)
{
	git_oid our_oid;
    git_oid octo1_oid;
    git_reference *octo2_ref;
    git_oid octo3_oid;
    git_reference *octo4_ref;
    git_merge_head *our_head, *their_heads[4];
	
	cl_git_pass(git_oid_fromstr(&our_oid, ORIG_HEAD));
	cl_git_pass(git_merge_head_from_oid(&our_head, repo, &our_oid));

    cl_git_pass(git_oid_fromstr(&octo1_oid, OCTO1_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[0], repo, &octo1_oid));

    cl_git_pass(git_reference_lookup(&octo2_ref, repo, GIT_REFS_HEADS_DIR OCTO2_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[1], repo, octo2_ref));

    cl_git_pass(git_oid_fromstr(&octo3_oid, OCTO3_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[2], repo, &octo3_oid));
    
    cl_git_pass(git_reference_lookup(&octo4_ref, repo, GIT_REFS_HEADS_DIR OCTO4_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[3], repo, octo4_ref));
    
	cl_git_pass(git_merge__setup(repo, our_head, (const git_merge_head **)their_heads, 4, 0));

    cl_assert(test_file_contents(GIT_MERGE_HEAD_FILE, OCTO1_OID "\n" OCTO2_OID "\n" OCTO3_OID "\n" OCTO4_OID "\n"));
    cl_assert(test_file_contents(GIT_ORIG_HEAD_FILE, ORIG_HEAD "\n"));
    cl_assert(test_file_contents(GIT_MERGE_MODE_FILE, ""));
    cl_assert(test_file_contents(GIT_MERGE_MSG_FILE, "Merge commit '" OCTO1_OID "'; branches '" OCTO2_BRANCH "' and '" OCTO4_BRANCH "'; commit '" OCTO3_OID "'\n"));
    
    git_reference_free(octo2_ref);
    git_reference_free(octo4_ref);

	git_merge_head_free(our_head);
    git_merge_head_free(their_heads[0]);
    git_merge_head_free(their_heads[1]);
    git_merge_head_free(their_heads[2]);
    git_merge_head_free(their_heads[3]);
}

/* git merge 16f825815cfd20a07a75c71554e82d8eede0b061 octo2 50ce7d7d01217679e26c55939eef119e0c93e272 octo4 octo5 */
void test_merge_setup__branches_and_oids_4(void)
{
	git_oid our_oid;
    git_oid octo1_oid;
    git_reference *octo2_ref;
    git_oid octo3_oid;
    git_reference *octo4_ref;
    git_reference *octo5_ref;
    git_merge_head *our_head, *their_heads[5];
	
	cl_git_pass(git_oid_fromstr(&our_oid, ORIG_HEAD));
	cl_git_pass(git_merge_head_from_oid(&our_head, repo, &our_oid));
    
    cl_git_pass(git_oid_fromstr(&octo1_oid, OCTO1_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[0], repo, &octo1_oid));
    
    cl_git_pass(git_reference_lookup(&octo2_ref, repo, GIT_REFS_HEADS_DIR OCTO2_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[1], repo, octo2_ref));
    
    cl_git_pass(git_oid_fromstr(&octo3_oid, OCTO3_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[2], repo, &octo3_oid));
    
    cl_git_pass(git_reference_lookup(&octo4_ref, repo, GIT_REFS_HEADS_DIR OCTO4_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[3], repo, octo4_ref));

    cl_git_pass(git_reference_lookup(&octo5_ref, repo, GIT_REFS_HEADS_DIR OCTO5_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[4], repo, octo5_ref));

	cl_git_pass(git_merge__setup(repo, our_head, (const git_merge_head **)their_heads, 5, 0));

    cl_assert(test_file_contents(GIT_MERGE_HEAD_FILE, OCTO1_OID "\n" OCTO2_OID "\n" OCTO3_OID "\n" OCTO4_OID "\n" OCTO5_OID "\n"));
    cl_assert(test_file_contents(GIT_ORIG_HEAD_FILE, ORIG_HEAD "\n"));
    cl_assert(test_file_contents(GIT_MERGE_MODE_FILE, ""));
    cl_assert(test_file_contents(GIT_MERGE_MSG_FILE, "Merge commit '" OCTO1_OID "'; branches '" OCTO2_BRANCH "', '" OCTO4_BRANCH "' and '" OCTO5_BRANCH "'; commit '" OCTO3_OID "'\n"));
    
    git_reference_free(octo2_ref);
    git_reference_free(octo4_ref);
    git_reference_free(octo5_ref);

	git_merge_head_free(our_head);
    git_merge_head_free(their_heads[0]);
    git_merge_head_free(their_heads[1]);
    git_merge_head_free(their_heads[2]);
    git_merge_head_free(their_heads[3]);
    git_merge_head_free(their_heads[4]);
}

/* git merge octo1 octo1 octo1 */
void test_merge_setup__three_same_branches(void)
{
	git_oid our_oid;
    git_reference *octo1_1_ref;
    git_reference *octo1_2_ref;
    git_reference *octo1_3_ref;
    git_merge_head *our_head, *their_heads[3];
	
	cl_git_pass(git_oid_fromstr(&our_oid, ORIG_HEAD));
	cl_git_pass(git_merge_head_from_oid(&our_head, repo, &our_oid));
    
    cl_git_pass(git_reference_lookup(&octo1_1_ref, repo, GIT_REFS_HEADS_DIR OCTO1_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[0], repo, octo1_1_ref));
    
    cl_git_pass(git_reference_lookup(&octo1_2_ref, repo, GIT_REFS_HEADS_DIR OCTO1_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[1], repo, octo1_2_ref));
    
    cl_git_pass(git_reference_lookup(&octo1_3_ref, repo, GIT_REFS_HEADS_DIR OCTO1_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[2], repo, octo1_3_ref));
	
	cl_git_pass(git_merge__setup(repo, our_head, (const git_merge_head **)their_heads, 3, 0));

    cl_assert(test_file_contents(GIT_MERGE_HEAD_FILE, OCTO1_OID "\n" OCTO1_OID "\n" OCTO1_OID "\n"));
    cl_assert(test_file_contents(GIT_ORIG_HEAD_FILE, ORIG_HEAD "\n"));
    cl_assert(test_file_contents(GIT_MERGE_MODE_FILE, ""));
    cl_assert(test_file_contents(GIT_MERGE_MSG_FILE, "Merge branches '" OCTO1_BRANCH "', '" OCTO1_BRANCH "' and '" OCTO1_BRANCH "'\n"));
    
    git_reference_free(octo1_1_ref);
    git_reference_free(octo1_2_ref);
    git_reference_free(octo1_3_ref);
    
	git_merge_head_free(our_head);
    git_merge_head_free(their_heads[0]);
    git_merge_head_free(their_heads[1]);
    git_merge_head_free(their_heads[2]);
}

/* git merge 16f825815cfd20a07a75c71554e82d8eede0b061 16f825815cfd20a07a75c71554e82d8eede0b061 16f825815cfd20a07a75c71554e82d8eede0b061 */
void test_merge_setup__three_same_oids(void)
{
	git_oid our_oid;
    git_oid octo1_1_oid;
    git_oid octo1_2_oid;
    git_oid octo1_3_oid;
    git_merge_head *our_head, *their_heads[3];
	
	cl_git_pass(git_oid_fromstr(&our_oid, ORIG_HEAD));
	cl_git_pass(git_merge_head_from_oid(&our_head, repo, &our_oid));
    
    cl_git_pass(git_oid_fromstr(&octo1_1_oid, OCTO1_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[0], repo, &octo1_1_oid));
    
    cl_git_pass(git_oid_fromstr(&octo1_2_oid, OCTO1_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[1], repo, &octo1_2_oid));
    
    cl_git_pass(git_oid_fromstr(&octo1_3_oid, OCTO1_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[2], repo, &octo1_3_oid));
    
	cl_git_pass(git_merge__setup(repo, our_head, (const git_merge_head **)their_heads, 3, 0));
    
    cl_assert(test_file_contents(GIT_MERGE_HEAD_FILE, OCTO1_OID "\n" OCTO1_OID "\n" OCTO1_OID "\n"));
    cl_assert(test_file_contents(GIT_ORIG_HEAD_FILE, ORIG_HEAD "\n"));
    cl_assert(test_file_contents(GIT_MERGE_MODE_FILE, ""));
    cl_assert(test_file_contents(GIT_MERGE_MSG_FILE, "Merge commit '" OCTO1_OID "'; commit '" OCTO1_OID "'; commit '" OCTO1_OID "'\n"));
    
	git_merge_head_free(our_head);
    git_merge_head_free(their_heads[0]);
    git_merge_head_free(their_heads[1]);
    git_merge_head_free(their_heads[2]);
}
