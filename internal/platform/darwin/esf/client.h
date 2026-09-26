#ifndef DARKD_ES_CLIENT_H
#define DARKD_ES_CLIENT_H
int init_notify_client(void);
int mute_self_notify(void);
int init_auth_client(void);
int subscribe_notify(void);
int subscribe_auth(void);
void stop_es_clients(void);
#endif
