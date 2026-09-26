//go:build darwin && esf && cgo

#include "client.h"
#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <mach/mach.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

/* Threats: AUTH and NOTIFY run on separate clients so a NOTIFY_WRITE flood
   cannot hold the serial queue past an AUTH deadline. The auth handler
   answers before it hands anything to Go. On any internal failure (Go panic,
   nil authorizer, failed copy, missing executable) an exec is allowed unless
   its basename is a stop tool, and a signal is allowed. Denying every exec on
   an internal error would brick the host. */

static es_client_t *auth_client = NULL;
static es_client_t *notify_client = NULL;
static pid_t self_pid = 0;

extern int AuthorizeExec(char *path, char *args, int truncated, int pid, int ppid, long long start_sec, int start_usec);
extern int AuthorizeSignal(int sender, int target, int sig);
extern void HandleESFEvent(int type, int pid, int ppid, unsigned int uid,
                          char *path, char *signing_id, unsigned long long sequence, int kind,
                          int responded, int answer, int fallback, int target_pid, int sig,
                          int truncated, long long start_sec, int start_usec, char *args);

#define ARGV_MAX 64

static int darkd_kind(es_event_type_t type) {
    if (type == ES_EVENT_TYPE_NOTIFY_EXEC) return 1;
    if (type == ES_EVENT_TYPE_NOTIFY_FORK) return 2;
    if (type == ES_EVENT_TYPE_NOTIFY_EXIT) return 3;
    if (type == ES_EVENT_TYPE_NOTIFY_WRITE) return 4;
    if (type == ES_EVENT_TYPE_NOTIFY_UNLINK) return 5;
    if (type == ES_EVENT_TYPE_AUTH_EXEC) return 6;
    if (type == ES_EVENT_TYPE_AUTH_SIGNAL) return 7;
    return 0;
}
static char *copy_token(es_string_token_t token) {
    if (token.data == NULL && token.length > 0) return NULL;
    char *copy = malloc(token.length + 1);
    if (copy) { if (token.length) memcpy(copy, token.data, token.length); copy[token.length] = 0; }
    return copy;
}

/* Fallback when the Go decision is unavailable. Works on the kernel's token,
   no allocation. Mirrored by isStopTool in internal/service/esf. */
static int is_stop_tool(const es_file_t *file) {
    static const char *tools[] = { "launchctl", "systemctl", "kill", "pkill", "killall" };
    if (!file || !file->path.data) return 0;
    const char *p = file->path.data;
    size_t n = file->path.length;
    size_t start = n;
    while (start > 0 && p[start - 1] != '/') start--;
    size_t len = n - start;
    for (size_t i = 0; i < sizeof(tools)/sizeof(tools[0]); i++) {
        if (strlen(tools[i]) == len && strncasecmp(p + start, tools[i], len) == 0) return 1;
    }
    return 0;
}

/* Bounded argv for the decision. The journal does not store these bytes. */
static void copy_exec_args(const es_event_exec_t *exec, char *out, size_t out_len, int *truncated) {
    uint32_t count = es_exec_arg_count(exec);
    uint32_t limit = count;
    size_t used = 0;
    *truncated = 0;
    out[0] = 0;
    if (count > ARGV_MAX) { limit = ARGV_MAX; *truncated = 1; }
    for (uint32_t i = 0; i < limit; i++) {
        es_string_token_t arg = es_exec_arg(exec, i);
        if ((arg.data == NULL && arg.length > 0) || arg.length >= 256 ||
            (arg.length > 0 && memchr(arg.data, '\x1e', arg.length) != NULL)) {
            *truncated = 1;
            break;
        }
        if (i > 0) {
            if (used + 1 >= out_len) { *truncated = 1; break; }
            out[used++] = '\x1e';
            out[used] = 0;
        }
        if (used + arg.length >= out_len) { *truncated = 1; break; }
        if (arg.length) memcpy(out + used, arg.data, arg.length);
        used += arg.length;
        out[used] = 0;
    }
}

/* Auth kinds are always delivered, with empty strings where a copy failed, so
   the answer sent to the kernel is journaled. Notify events without a path are
   dropped as before. */
static void deliver(const es_message_t *message, const es_process_t *process, const es_file_t *file,
                    int kind, int responded, int answer, int fallback, int target_pid, int sig,
                    int truncated, const char *args) {
    int auth = kind == 6 || kind == 7;
    char *path = file ? copy_token(file->path) : NULL;
    char *signing = process ? copy_token(process->signing_id) : NULL;
    long long start_sec = 0;
    int start_usec = 0;
    if (message->version >= 3 && process) {
        start_sec = (long long)process->start_time.tv_sec;
        start_usec = (int)process->start_time.tv_usec;
    }
    if ((path && signing && process) || auth) {
        HandleESFEvent((int)message->event_type,
            process ? audit_token_to_pid(process->audit_token) : 0, process ? process->ppid : 0,
            process ? audit_token_to_euid(process->audit_token) : 0,
            path ? path : "", signing ? signing : "",
            message->version >= 4 ? message->global_seq_num : 0, kind,
            responded, answer, fallback, target_pid, sig,
            truncated, start_sec, start_usec, (char *)(args ? args : ""));
    }
    free(path);
    free(signing);
}

static void handle_auth_exec(es_client_t *c, const es_message_t *message) {
    /* Answer before returning. A missed deadline kills this client.
       cache is false so one path cannot authorize a later exec. */
    const es_process_t *target = message->event.exec.target;
    char args[2048];
    int truncated = 1;
    int result = -1;
    int allow;
    int fallback = 0;
    char *path = target && target->executable ? copy_token(target->executable->path) : NULL;
    args[0] = 0;
    if (target) copy_exec_args(&message->event.exec, args, sizeof(args), &truncated);
    if (path) {
        long long start_sec = 0;
        int start_usec = 0;
        if (message->version >= 3) {
            start_sec = (long long)target->start_time.tv_sec;
            start_usec = (int)target->start_time.tv_usec;
        }
        result = AuthorizeExec(path, args, truncated,
            audit_token_to_pid(target->audit_token), target->ppid, start_sec, start_usec);
    }
    if (result == 1 || result == 0) {
        allow = result;
    } else {
        fallback = 1;
        allow = !is_stop_tool(target ? target->executable : NULL);
    }
    es_respond_result_t rc = es_respond_auth_result(c, message,
        allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY, false);
    free(path);
    deliver(message, target, target ? target->executable : NULL, 6,
        rc == ES_RESPOND_RESULT_SUCCESS, allow, fallback, 0, 0, truncated, args);
}

static void handle_auth_signal(es_client_t *c, const es_message_t *message) {
    /* Signals to other processes never reach Go. Signal caching is not
       supported by ES, so every answer is uncached. */
    const es_process_t *target = message->event.signal.target;
    const es_process_t *sender = message->process;
    int sig = message->event.signal.sig;
    int target_pid = target ? audit_token_to_pid(target->audit_token) : -1;
    if (target_pid != self_pid) {
        es_respond_auth_result(c, message, ES_AUTH_RESULT_ALLOW, false);
        return;
    }
    int sender_pid = sender ? audit_token_to_pid(sender->audit_token) : 0;
    int result = AuthorizeSignal(sender_pid, target_pid, sig);
    int fallback = result != 0 && result != 1;
    int allow = fallback ? 1 : result;
    es_respond_result_t rc = es_respond_auth_result(c, message,
        allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY, false);
    if (!allow || fallback) {
        deliver(message, sender, sender ? sender->executable : NULL, 7,
            rc == ES_RESPOND_RESULT_SUCCESS, allow, fallback, target_pid, sig, 0, "");
    }
}

static void handle_auth(es_client_t *c, const es_message_t *message) {
    if (message->event_type == ES_EVENT_TYPE_AUTH_EXEC) { handle_auth_exec(c, message); return; }
    if (message->event_type == ES_EVENT_TYPE_AUTH_SIGNAL) { handle_auth_signal(c, message); return; }
    if (message->action_type == ES_ACTION_TYPE_AUTH) es_respond_auth_result(c, message, ES_AUTH_RESULT_ALLOW, false);
}

static void handle_notify(const es_message_t *message) {
    const es_process_t *process = message->process;
    if (message->event_type == ES_EVENT_TYPE_NOTIFY_EXEC) process = message->event.exec.target;
    if (message->event_type == ES_EVENT_TYPE_NOTIFY_FORK) process = message->event.fork.child;
    const es_file_t *file = process ? process->executable : NULL;
    if (message->event_type == ES_EVENT_TYPE_NOTIFY_WRITE) file = message->event.write.target;
    if (message->event_type == ES_EVENT_TYPE_NOTIFY_UNLINK) file = message->event.unlink.target;
    char args[2048];
    int truncated = 0;
    args[0] = 0;
    if (message->event_type == ES_EVENT_TYPE_NOTIFY_EXEC) {
        copy_exec_args(&message->event.exec, args, sizeof(args), &truncated);
    }
    deliver(message, process, file, darkd_kind(message->event_type), 0, 1, 0, 0, 0, truncated, args);
}

int init_notify_client(void) {
    if (notify_client) return -1;
    self_pid = getpid();
    return (int)es_new_client(&notify_client, ^(es_client_t *c, const es_message_t *message) {
        (void)c;
        handle_notify(message);
    });
}
/* Mute this process on the notify client so journal writes do not feed back. */
int mute_self_notify(void) {
    if (!notify_client) return -1;
    audit_token_t token;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&token, &count) != KERN_SUCCESS) return -2;
    return (int)es_mute_process(notify_client, &token);
}
int init_auth_client(void) {
    if (auth_client) return -1;
    self_pid = getpid();
    return (int)es_new_client(&auth_client, ^(es_client_t *c, const es_message_t *message) {
        handle_auth(c, message);
    });
}
int subscribe_notify(void) {
    if (!notify_client) return -1;
    es_event_type_t events[] = { ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXIT, ES_EVENT_TYPE_NOTIFY_WRITE, ES_EVENT_TYPE_NOTIFY_UNLINK };
    return (int)es_subscribe(notify_client, events, sizeof(events)/sizeof(events[0]));
}
int subscribe_auth(void) {
    if (!auth_client) return -1;
    es_event_type_t events[] = { ES_EVENT_TYPE_AUTH_EXEC, ES_EVENT_TYPE_AUTH_SIGNAL };
    return (int)es_subscribe(auth_client, events, sizeof(events)/sizeof(events[0]));
}
void stop_es_clients(void) {
    if (auth_client) { es_unsubscribe_all(auth_client); es_delete_client(auth_client); auth_client = NULL; }
    if (notify_client) { es_unsubscribe_all(notify_client); es_delete_client(notify_client); notify_client = NULL; }
}
