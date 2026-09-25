//go:build darwin && esf && cgo

#include "client.h"
#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <stdlib.h>
#include <string.h>

static es_client_t *client = NULL;
extern int AuthorizeExec(char *path, char *args, int truncated, int pid, int ppid, long long start_sec, int start_usec);
extern void HandleESFEvent(int type, int pid, int ppid, unsigned int uid,
                          char *path, char *signing_id, unsigned long long sequence, int kind,
                          int responded, int truncated, long long start_sec, int start_usec, char *args);

static int darkd_kind(es_event_type_t type) {
    if (type == ES_EVENT_TYPE_NOTIFY_EXEC) return 1;
    if (type == ES_EVENT_TYPE_NOTIFY_FORK) return 2;
    if (type == ES_EVENT_TYPE_NOTIFY_EXIT) return 3;
    if (type == ES_EVENT_TYPE_NOTIFY_WRITE) return 4;
    if (type == ES_EVENT_TYPE_NOTIFY_UNLINK) return 5;
    if (type == ES_EVENT_TYPE_AUTH_EXEC) return 6;
    return 0;
}
static char *copy_token(es_string_token_t token) {
    char *copy = malloc(token.length + 1);
    if (copy) { memcpy(copy, token.data, token.length); copy[token.length] = 0; }
    return copy;
}

/* Bounded argv for the decision. The journal does not store these bytes. */
static void copy_exec_args(const es_event_exec_t *exec, char *out, size_t out_len, int *truncated) {
    uint32_t count = es_exec_arg_count(exec);
    uint32_t limit = count;
    size_t used = 0;
    *truncated = 0;
    out[0] = 0;
    if (count > 8) { limit = 8; *truncated = 1; }
    for (uint32_t i = 0; i < limit; i++) {
        es_string_token_t arg = es_exec_arg(exec, i);
        if (arg.data == NULL || arg.length == 0 || arg.length >= 256 || memchr(arg.data, '\x1e', arg.length) != NULL) {
            *truncated = 1;
            break;
        }
        if (used > 0) {
            if (used + 1 >= out_len) { *truncated = 1; break; }
            out[used++] = '\x1e';
        }
        if (used + arg.length >= out_len) { *truncated = 1; break; }
        memcpy(out + used, arg.data, arg.length);
        used += arg.length;
        out[used] = 0;
    }
}

static void deliver(const es_message_t *message, const es_process_t *process, const es_file_t *file,
                    int kind, int responded, int truncated, const char *args) {
    char *path = file ? copy_token(file->path) : NULL;
    char *signing = process ? copy_token(process->signing_id) : NULL;
    long long start_sec = 0;
    int start_usec = 0;
    if (message->version >= 3 && process) {
        start_sec = (long long)process->start_time.tv_sec;
        start_usec = (int)process->start_time.tv_usec;
    }
    if (path && signing && process) {
        HandleESFEvent((int)message->event_type,
            audit_token_to_pid(process->audit_token), process->ppid,
            audit_token_to_euid(process->audit_token), path, signing,
            message->version >= 4 ? message->global_seq_num : 0, kind,
            responded, truncated, start_sec, start_usec, (char *)(args ? args : ""));
    }
    free(path);
    free(signing);
}

static void handle_event(es_client_t *c, const es_message_t *message) {
    if (message->event_type == ES_EVENT_TYPE_AUTH_EXEC) {
        /* Answer before returning. A missed deadline kills this client.
           cache is false so one path cannot authorize a later exec. */
        const es_process_t *target = message->event.exec.target;
        char args[2048];
        int truncated = 1;
        int allow = 0;
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
            allow = AuthorizeExec(path, args, truncated,
                audit_token_to_pid(target->audit_token), target->ppid, start_sec, start_usec);
            if (allow != 1) allow = 0;
        }
        es_respond_result_t rc = es_respond_auth_result(c, message,
            allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY, false);
        deliver(message, target, target ? target->executable : NULL, 6, rc == ES_RESPOND_RESULT_SUCCESS, truncated, args);
        free(path);
        return;
    }

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
    deliver(message, process, file, darkd_kind(message->event_type), 0, truncated, args);
}

int init_es_client(void) {
    if (client) return -1;
    return (int)es_new_client(&client, ^(es_client_t *c, const es_message_t *message) {
        handle_event(c, message);
    });
}
int subscribe_to_events(void) {
    if (!client) return -1;
    es_event_type_t events[] = { ES_EVENT_TYPE_AUTH_EXEC, ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXIT, ES_EVENT_TYPE_NOTIFY_WRITE, ES_EVENT_TYPE_NOTIFY_UNLINK };
    return (int)es_subscribe(client, events, sizeof(events)/sizeof(events[0]));
}
void stop_es_client(void) {
    if (client) { es_unsubscribe_all(client); es_delete_client(client); client = NULL; }
}
