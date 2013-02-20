#include <libssh2.h>

#include "git2.h"
#include "buffer.h"
#include "netops.h"
#include "smart.h"

#define OWNING_SUBTRANSPORT(s) ((ssh_subtransport *)(s)->parent.subtransport)

static const char prefix_ssh[] = "ssh://";
static const char cmd_uploadpack[] = "git-upload-pack";
static const char cmd_receivepack[] = "git-receive-pack";

typedef struct {
	git_smart_subtransport_stream parent;
	const char *cmd;
	char *url;
	unsigned sent_command : 1;
} ssh_stream;

typedef struct {
	git_smart_subtransport parent;
	transport_smart *owner;
	ssh_stream *current_stream;
	git_cred *cred;
	char *host;
	char *port;
	gitno_socket socket;
	unsigned connected : 1;
	LIBSSH2_SESSION *session;
	LIBSSH2_CHANNEL *channel;	
} ssh_subtransport;

static int gen_proto(git_buf *request, const char *cmd, const char *url)
{
	char *delim, *repo;

	if (!cmd)
		cmd = cmd_uploadpack;

	delim = strchr(url, '/');
	if (delim==NULL) {
		giterr_set(GITERR_NET, "Malformed URL");
		return -1;
	}

	repo = delim+1;
	git_buf_grow(request, strlen(cmd)+strlen(repo)+2);
	git_buf_printf(request, "%s \'%s\'", cmd, repo);
	git_buf_putc(request, '\0');

	if (git_buf_oom(request))
		return -1;

	return 0;
}

static int ssh_set_error(LIBSSH2_SESSION *session)
{
	char *error;
	libssh2_session_last_error(session, &error, NULL, 0);
	giterr_set(GITERR_NET, "SSH error: %s", error);

	return -1;
}

static int send_command(ssh_stream *s)
{
	int error;
	git_buf request = GIT_BUF_INIT;
	ssh_subtransport *t = OWNING_SUBTRANSPORT(s);

	error = gen_proto(&request, s->cmd, s->url);
	if (error<0)
		goto cleanup;

    printf("send command %s\n", request.ptr);
	error = libssh2_channel_exec(t->channel, git_buf_cstr(&request));

	if (error>=0)
		s->sent_command = 1;

cleanup:
	git_buf_free(&request);
	return error >= 0 ? error : ssh_set_error(t->session);
}

static int ssh_stream_read(
	git_smart_subtransport_stream *stream,
	char *buffer,
	size_t buf_size,
	size_t *bytes_read)
{
	int error;
	ssh_stream *s = (ssh_stream *)stream;
	ssh_subtransport *t = OWNING_SUBTRANSPORT(s);
	gitno_buffer buf;

	*bytes_read = 0;

	if (!s->sent_command && send_command(s)<0)
		return -1;

	gitno_buffer_setup(&t->socket, &buf, buffer, buf_size);

	error = libssh2_channel_read(t->channel, buf.data, buf.len);
    printf("read %ld %s\n", buf.offset, buf.data);
	if (error < 0)
		return ssh_set_error(t->session);
	else
		buf.offset = error;
    

	*bytes_read = buf.offset;

	return 0;
}

static int ssh_stream_write(
	git_smart_subtransport_stream *stream,
	const char *buffer,
	size_t len)
{
	ssh_stream *s = (ssh_stream *)stream;
	ssh_subtransport *t = OWNING_SUBTRANSPORT(s);

    printf("send %ld %s\n", len, buffer);
    
	if (!s->sent_command && send_command(s)<0)
		return -1;
    

	return libssh2_channel_write(t->channel, buffer, len);
}

static void ssh_stream_free(git_smart_subtransport_stream *stream)
{
	ssh_stream *s = (ssh_stream *)stream;

	git__free(s->url);
	git__free(s);
}

static int ssh_stream_alloc(
	git_smart_subtransport_stream **stream,
	ssh_subtransport *t,
	const char *url,
	const char *cmd)
{
	ssh_stream *s;

	if (!stream)
		return -1;

	s = (ssh_stream *)git__calloc(sizeof(ssh_stream), 1);
	GITERR_CHECK_ALLOC(s);

	s->parent.subtransport = &t->parent;
	s->parent.read = ssh_stream_read;
	s->parent.write = ssh_stream_write;
	s->parent.free = ssh_stream_free;

	s->url = git__strdup(url);
	s->cmd = cmd;

	*stream = &s->parent;
	return 0;
}

static int ssh_uploadpack_ls(
	git_smart_subtransport_stream **stream,
	ssh_subtransport *t,
	const char *url)
{
	ssh_stream *s;

	*stream = NULL;
	
	if (ssh_stream_alloc(stream, t, url, cmd_uploadpack) <0)
		return -1;

	s = (ssh_stream *)*stream;
	t->current_stream = s;

	return 0;
}

static int ssh_uploadpack(
	git_smart_subtransport_stream **stream,
	ssh_subtransport *t)
{
	if (t->current_stream) {
		*stream = &t->current_stream->parent;
		return 0;
	}

	giterr_set(GITERR_NET, "Must call UPLOADPACK_LS before UPLOADPACK");
	return -1;
}

static int ssh_receivepack_ls(
    git_smart_subtransport_stream **stream,
    ssh_subtransport *t,
    const char *url)
{
    ssh_stream *s;
    
    *stream = NULL;
    if (ssh_stream_alloc(stream, t, url, cmd_receivepack)<0)
        return -1;
    
    s = (ssh_stream *)*stream;
    t->current_stream = s;
    
    return 0;
}

static int ssh_receivepack(
    git_smart_subtransport_stream **stream,
    ssh_subtransport *t)
{
    if (t->current_stream) {
        *stream = &t->current_stream->parent;
        return 0;
    }
    
    giterr_set(GITERR_NET, "Must call RECEIVEPACK_LS before RECEIVEPACK");
    return -1;
}

static int ssh_action(
	git_smart_subtransport_stream **stream,
	git_smart_subtransport *smart_transport,
	const char *url,
	git_smart_service_t action)
{
	ssh_subtransport *t = (ssh_subtransport *)smart_transport;
	const char *default_port = "22";

	if (!stream)
		return -1;

	if (!git__prefixcmp(url, prefix_ssh))
		url += strlen(prefix_ssh);

	if (!t->host || !t->port) {
		if (gitno_extract_host_and_port(&t->host, &t->port,
			url, default_port)<0)
		return -1;
	}

	if (!t->connected) {
		if (!t->owner->cred_acquire_cb) {
			giterr_set(GITERR_NET, "No credential callback given");
			return -1;
		}

		if (gitno_connect(&t->socket, t->host, t->port, 0)<0)
			return -1;

		if (libssh2_init(0)<0) {
			giterr_set(GITERR_NET, "Failed to init libssh2");
			return -1;
		}

		t->session = libssh2_session_init();
		if (t->session==NULL) {
			giterr_set(GITERR_NET, "Failed to init SSH session");
			return -1;
		}

		libssh2_session_set_blocking(t->session, 1);

		if (libssh2_session_handshake(t->session,
			(libssh2_socket_t)(t->socket.socket))<0)
			return ssh_set_error(t->session);

		if (t->owner->cred_acquire_cb(&t->cred, t->owner->url,
			GIT_CREDTYPE_SSH_KEY | GIT_CREDTYPE_SSH_PASSWORD,
            t->owner->cred_acquire_payload)<0)
			return -1;

		assert(t->cred);

        if (t->cred->credtype==GIT_CREDTYPE_SSH_PASSWORD) {
            git_cred_ssh_password *c = (git_cred_ssh_password *)t->cred;
            if (libssh2_userauth_password(t->session, c->username, c->password)<0)
                return ssh_set_error(t->session);
        } else if (t->cred->credtype==GIT_CREDTYPE_SSH_KEY) {
            git_cred_ssh_key *c = (git_cred_ssh_key *)t->cred;
            if (libssh2_userauth_publickey_fromfile(t->session, c->username, NULL, c->private_key, c->pass)<0)
                return ssh_set_error(t->session);
        }

		t->channel = libssh2_channel_open_session(t->session);
		if (t->channel==NULL)
			return ssh_set_error(t->session);
	
		t->connected = 1;
	}

	switch (action) {
	case GIT_SERVICE_UPLOADPACK_LS:
		return ssh_uploadpack_ls(stream, t, url);
	case GIT_SERVICE_UPLOADPACK:
		return ssh_uploadpack(stream, t);
    case GIT_SERVICE_RECEIVEPACK_LS:
        return ssh_receivepack_ls(stream, t, url);
    case GIT_SERVICE_RECEIVEPACK:
        return ssh_receivepack(stream, t);
	}

	*stream = NULL;
	return -1;
}

static int ssh_close(git_smart_subtransport *smart_transport)
{
    ssh_subtransport *t = (ssh_subtransport *)smart_transport;
    if (t->channel) {
        libssh2_channel_close(t->channel);
        libssh2_channel_free(t->channel);
        t->channel = NULL;
    }
    
    if (t->session) {
        libssh2_session_disconnect(t->session, NULL);
        libssh2_session_free(t->session);
        t->session = NULL;
    }
    
    libssh2_exit();
    
	if (t->cred) {
		t->cred->free(t->cred);
        t->cred = NULL;
    }
    
    t->connected = 0;
    if (t->socket.socket) {
        gitno_close(&t->socket);
		memset(&t->socket, 0x0, sizeof(gitno_socket));
    }
    
    if (t->host) {
        git__free(t->host);
        t->host = NULL;
    }
    
    if (t->port) {
        git__free(t->port);
        t->port = NULL;
    }
    
    return 0;
}

static void ssh_free(git_smart_subtransport *smart_transport)
{
	ssh_subtransport *t = (ssh_subtransport *)smart_transport;

    ssh_close(smart_transport);

	git__free(t);
}

int git_smart_subtransport_ssh(git_smart_subtransport **out, 
	git_transport *owner)
{
	ssh_subtransport *t;

	if (!out)
		return -1;

	t = (ssh_subtransport *)git__calloc(sizeof(ssh_subtransport), 1);
	GITERR_CHECK_ALLOC(t);

	t->owner = (transport_smart *)owner;
	t->parent.action = ssh_action;
    t->parent.close = ssh_close;
	t->parent.free = ssh_free;

	*out = (git_smart_subtransport *)t;
	return 0;
}

