#pragma once

#include <fltKernel.h>

extern CONST FLT_OPERATION_REGISTRATION g_callbacks[];
extern const FLT_REGISTRATION g_filter_registration;

extern PFLT_FILTER g_filter;
extern PFLT_PORT g_server_port;
extern PFLT_PORT g_client_port;

extern volatile LONG g_unloading;
extern volatile LONG g_inflight_sends;
extern volatile LONG g_inflight_flt_callbacks;
//extern volatile LONG g_send_count;