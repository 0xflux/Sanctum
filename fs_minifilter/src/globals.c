#include "globals.h"

volatile LONG g_inflight_flt_callbacks = 0;

PFLT_FILTER g_filter = NULL;
PFLT_PORT g_server_port = NULL;
PFLT_PORT g_client_port = NULL;

volatile LONG g_unloading = 0;
volatile LONG g_inflight_sends = 0;
//volatile LONG g_send_count = 0;
