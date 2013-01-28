#include "clar_libgit2.h"
#include "git2/repository.h"
#include "git2/merge.h"
#include "merge.h"
#include "merge_helpers.h"
#include "refs.h"

static git_repository *repo;
static git_index *repo_index;

#define TEST_REPO_PATH "merge-resolve"
#define TEST_INDEX_PATH TEST_REPO_PATH "/.git/index"

#define THEIRS_FASTFORWARD_BRANCH	"ff_branch"
#define THEIRS_FASTFORWARD_OID		"fd89f8cffb663ac89095a0f9764902e93ceaca6a"

// Fixture setup and teardown
void test_merge_fastforward__initialize(void)
{
	repo = cl_git_sandbox_init(TEST_REPO_PATH);
    git_repository_index(&repo_index, repo);
}

void test_merge_fastforward__cleanup(void)
{
    git_index_free(repo_index);
	cl_git_sandbox_cleanup();
}

static git_merge_result *merge_fastforward_branch(int flags)
{
    git_reference *their_ref;
    git_merge_head *their_heads[1];
	git_merge_result *result;
	git_merge_opts opts = GIT_MERGE_OPTS_INIT;

	opts.merge_flags = flags;

    cl_git_pass(git_reference_lookup(&their_ref, repo, GIT_REFS_HEADS_DIR THEIRS_FASTFORWARD_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[0], repo, their_ref));

	cl_git_pass(git_merge(&result, repo, (const git_merge_head **)their_heads, 1, &opts));

	git_merge_head_free(their_heads[0]);
	git_reference_free(their_ref);

	return result;
}

void test_merge_fastforward__fastforward(void)
{
	git_merge_result *result;
	git_oid expected, ff_oid;

	cl_git_pass(git_oid_fromstr(&expected, THEIRS_FASTFORWARD_OID));

	cl_assert(result = merge_fastforward_branch(0));
	cl_assert(git_merge_result_is_fastforward(result));
	cl_git_pass(git_merge_result_fastforward_oid(&ff_oid, result));
	cl_assert(git_oid_cmp(&ff_oid, &expected) == 0);

	git_merge_result_free(result);
}

void test_merge_fastforward__no_fastforward(void)
{
	git_merge_result *result;
    
    struct merge_index_entry merge_index_entries[] = {
		{ 0100644, "233c0919c998ed110a4b6ff36f353aec8b713487", 0, "added-in-master.txt" },
        { 0100644, "ee3fa1b8c00aff7fe02065fdb50864bb0d932ccf", 0, "automergeable.txt" },
        { 0100644, "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b", 0, "changed-in-branch.txt" },
        { 0100644, "bd9cb4cd0a770cb9adcb5fce212142ef40ea1c35", 0, "changed-in-master.txt" },
        { 0100644, "4e886e602529caa9ab11d71f86634bd1b6e0de10", 0, "conflicting.txt" },
        { 0100644, "364bbe4ce80c7bd31e6307dce77d46e3e1759fb3", 0, "new-in-ff.txt" },
        { 0100644, "dfe3f22baa1f6fce5447901c3086bae368de6bdd", 0, "removed-in-branch.txt" },
        { 0100644, "c8f06f2e3bb2964174677e91f0abead0e43c9e5d", 0, "unchanged.txt" },
    };

	cl_assert(result = merge_fastforward_branch(GIT_MERGE_NO_FASTFORWARD));
	cl_assert(!git_merge_result_is_fastforward(result));

    cl_assert(merge_test_index(repo_index, merge_index_entries, 8));
	cl_assert(git_index_reuc_entrycount(repo_index) == 0);

	git_merge_result_free(result);
}

void test_merge_fastforward__uptodate(void)
{
    git_reference *their_ref;
    git_merge_head *their_heads[1];
	git_merge_result *result;

    cl_git_pass(git_reference_lookup(&their_ref, repo, GIT_HEAD_FILE));
    cl_git_pass(git_merge_head_from_ref(&their_heads[0], repo, their_ref));

	cl_git_pass(git_merge(&result, repo, (const git_merge_head **)their_heads, 1, NULL));

	cl_assert(git_merge_result_is_uptodate(result));

	git_merge_head_free(their_heads[0]);
	git_merge_result_free(result);
}
