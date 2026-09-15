//go:build darwin && esf && cgo

#include "client.h"
#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <stdlib.h>
#include <string.h>

static es_client_t *client = NULL;
extern void HandleESFEvent(int type, int pid, int ppid, unsigned int uid,
                          char *path, char *signing_id, unsigned long long sequence);
static char *copy_token(es_string_token_t token) {
    char *copy = malloc(token.length + 1);
    if (copy) { memcpy(copy, token.data, token.length); copy[token.length] = 0; }
    return copy;
}
static void handle_event(const es_message_t *message) {
    const es_process_t *process = message->process;
    if (message->event_type == ES_EVENT_TYPE_NOTIFY_EXEC) process = message->event.exec.target;
    if (message->event_type == ES_EVENT_TYPE_NOTIFY_FORK) process = message->event.fork.child;
    const es_file_t *file = process->executable;
    if (message->event_type == ES_EVENT_TYPE_NOTIFY_WRITE) file = message->event.write.target;
    if (message->event_type == ES_EVENT_TYPE_NOTIFY_UNLINK) file = message->event.unlink.target;
    char *path = copy_token(file->path);
    char *signing = copy_token(process->signing_id);
    if (path && signing) HandleESFEvent((int)message->event_type,
        audit_token_to_pid(process->audit_token), process->ppid,
        audit_token_to_euid(process->audit_token), path, signing,
        message->version >= 4 ? message->global_seq_num : 0);
    free(path); free(signing);
}
int init_es_client(void) {
    if (client) return -1;
    return (int)es_new_client(&client, ^(es_client_t *c, const es_message_t *message) {
        handle_event(message);
    });
}
int subscribe_to_events(void) {
    if (!client) return -1;
    es_event_type_t events[] = { ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXIT, ES_EVENT_TYPE_NOTIFY_WRITE, ES_EVENT_TYPE_NOTIFY_UNLINK };
    return (int)es_subscribe(client, events, sizeof(events)/sizeof(events[0]));
}
void stop_es_client(void) {
    if (client) { es_unsubscribe_all(client); es_delete_client(client); client = NULL; }
}
