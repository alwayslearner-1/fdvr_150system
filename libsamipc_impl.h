
/*
 * libsamipc_impl.h
 *
 * Samoon IPC Program.
 *
 * History:
 *    2015/05/16 - [Adam] created file
 *
 * Copyright (C) 2012-2015, Samoon, Inc.
 *
 * All rights reserved. No Part of this file may be reproduced, stored
 * in a retrieval system, or transmitted, in any form, or by any means,
 * electronic, mechanical, photocopying, recording, or otherwise,
 * without the prior consent of Samoon, Inc.
 */


#ifndef __LIBSAMIPC_IMPL_H__
#define __LIBSAMIPC_IMPL_H__

#ifdef  __cplusplus
extern "C" {
#endif

enum LIBSAMIPC_STREAMING_Type_e{
	LIBSAMIPC_VIDEO_ENCSTREAM=0,
	LIBSAMIPC_AUDIO_ENCSTREAM,
};

typedef struct Notify_s {
	unsigned int msg_id;
	unsigned int param1;
	unsigned int param2;
	unsigned int resv[52];
}Notify_t, *PNotify_t;

typedef void(* NotifyCallback_t)(PNotify_t pNotify);

extern int libSamIPC_init();
extern int libSamIPC_release();

//int libSamIPC_framer_enable(int Stream_type);
//int libSamIPC_framer_disable(int Stream_type);

int libSamIPC_streaming_enable(int stream_type);
int libSamIPC_streaming_disable(int stream_type);

int libSamIPC_register_notify_callback(NotifyCallback_t pfnNotifyCallback);

int libSamIPC_send_notify(PNotify_t pNotify);

int libSamIPC_printk(char *msg);

int libSamIPC_get_device_spec(struct DeviceSpec_s *spec);

int libSamIPC_get_system_status(struct SystemStatus_s *sysStatus);

int libSamIPC_getting(struct CommParam_s *p);

int libSamIPC_setting(struct CommParam_s *p);

int libSamIPC_control(struct CtrlCommand_s *p);

int libSamIPC_get_gsensorinfo(struct GSensorInfo_s *p);

int libSamIPC_get_gpsinfo(struct GPSInfo_s *p);

int libSamIPC_get_adsinfo(struct ADSInfo_s *p);

int libSamIPC_get_moblielinkinfo(struct MobileLinkInfo_s *p);

int libSamIPC_get_dvrclientinfo(struct DVRClientInfo_s *p);

int libSamIPC_send_message(unsigned short msg, char* param);
int libSamIPC_receive_message(struct DeveiceStatusInfo *p);
int libSamIPC_get_video_quality(struct IpcCommdata_s *p);
int libSamIPC_get_video_alarm_msg(struct IpcCommdata_s *p);




#ifdef  __cplusplus
}
#endif

#endif //__LIBSAMIPC_IMPL_H__
