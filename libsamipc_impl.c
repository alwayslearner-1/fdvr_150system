/*
 * ipc/usrspace/libSamIPC/libSamIPC_impl.c
 *
 * Authors:
 *	Adam <adam@samoon.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * Copyright (C) 2009-2012, Samoon Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>

#include <aipc.h>
#include "libsamipc_framer.h"
#include "P2PClient/P2PClient.h"


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

#ifndef __AIPC_USERSPACE__
#define __AIPC_USERSPACE__
#endif
#if !defined(__DEPENDENCY_GENERATION__)
#include "ipcgen/lu_libsamipc.h"
#define __IPC_SERVER_IMPL__
#include "ipcgen/lu_libsamipc_tab.i"
#endif
#if !defined(__DEPENDENCY_GENERATION__)
#include "ipcgen/i_libsamipc.h"
#define __IPC_CLIENT_IMPL__
#include "ipcgen/i_libsamipc_tab.i"
#endif

#ifndef LOGE
#define LOGE printf
#endif

//#define EXAM_FRAMER_DEBUG 1

#if EXAM_FRAMER_DEBUG
#define DBGMSG LOGE
#else
#define DBGMSG(...) //
#endif

/************************** Global definition ***************************/
#define ________Global_definition________
static NotifyCallback_t G_lu_Notify_Callback = NULL;

/*************************** Framer Structure ***************************/
#define ________Framer_Structure________
#define ENC_STREAM_ID(x) (x-EXAM_FRAMER_VIDEO_ENCSTREAM)
#define ENC_STREAM_NUM	2

typedef struct Exam_framer_encframe_status_s
{
	pthread_mutex_t mutex;
	int enc_ValidFrames;
	struct lu_libsamipc_framer_frameinfo enc_framedata;
	pthread_cond_t cond;
	int wait_frm;
}Exam_framer_encframe_status_t;

typedef struct Exam_framer_status_s
{
	unsigned char inited;
	struct i_libsamipc_framer_buf_info iavpool;
	int iavpool_mmap_offset;
	Exam_framer_encframe_status_t encframe[ENC_STREAM_NUM];
	frame_ready_cb enc_frameready_cb;
	void* enc_frameready_userdata;
	int mbxid;
	pthread_t ipcsvc_tid;
	get_dec_frame_info_cb dec_finfo_cb;
	void* dec_finfo_userdata;
	get_dec_frame_data_cb dec_fdata_cb;
	void* dec_fdata_userdata;
	get_dec_notify_cb dec_notify_cb;
	void* dec_notify_userdata;
	Exam_framer_media_config_t dec_mconf;
} Exam_framer_status_t;

static Exam_framer_status_t G_libSamIPC_status;

/*************************** IPC initialize ************************/
#define ________IPC_Initialize________

static CLIENT *IPC_i_libsamipc = NULL;	/* Client handle */

/*
 * Program meta data for Client
 */
static struct ipc_prog_s i_libsamipc_prog =
{
	.name = "i_libsamipc",
	.prog = I_LIBSAMIPC_PROG,
	.vers = I_LIBSAMIPC_VERS,
	.table = (struct ipcgen_table *) i_libsamipc_prog_1_table,
	.nproc = i_libsamipc_prog_1_nproc,
};

/*
 * Program meta data for server.
 */
static struct ipc_prog_s lu_libsamipc_prog =
{
	.name = "lu_libsamipc",
	.prog = LU_LIBSAMIPC_PROG,
	.vers = LU_LIBSAMIPC_VERS,
	.table = (struct ipcgen_table *) &lu_libsamipc_prog_1_table,
	.nproc = lu_libsamipc_prog_1_nproc,
};

void libSamIPC_init_IPC_Clnt(void)
{
	if(IPC_i_libsamipc==NULL){
		IPC_i_libsamipc = ipc_clnt_prog_register(&i_libsamipc_prog);
	}
}

void libSamIPC_release_IPC_Clnt(void)
{
	if(IPC_i_libsamipc!=NULL){
		ipc_clnt_prog_unregister(&i_libsamipc_prog, IPC_i_libsamipc);
		IPC_i_libsamipc = NULL;
	}
}

//LU Server Task
static void *libSamIPC_IpcSvc_thread(void)
{
	int rval;

	for (;;) {
		rval = ipc_svc_prog_poll(&lu_libsamipc_prog, NULL);
		DBGMSG("%s: %d\n\r",__func__,rval);
		if (rval < 0)
			break;
	}
	LOGE("%s exit.\n\r",__func__);
}

int libSamIPC_init_IPC_Svc(void)
{
	int r=0;
	ipc_lib_init();
	r=ipc_svc_prog_register(&lu_libsamipc_prog);
	if(r>=0) {
		//create svc task
		if(pthread_create(&G_libSamIPC_status.ipcsvc_tid, NULL, (void *)&libSamIPC_IpcSvc_thread, NULL)!=0)
		{
			LOGE("Fail to create Exam_framer_IpcScv_thread!!\n\r");
			G_libSamIPC_status.ipcsvc_tid=0;
			return -1;
		}
		LOGE("Create Exam_framer_IpcScv_thread!!\n\r");
	}
	return r;
}

int libSamIPC_release_IPC_Svc(void)
{
	int r=0;
	r=ipc_svc_prog_stop_poll(&lu_libsamipc_prog);
	if(r>=0) {
		pthread_join(G_libSamIPC_status.ipcsvc_tid, NULL); //pthread_cancel
		G_libSamIPC_status.ipcsvc_tid=0;
		r=ipc_svc_prog_unregister(&lu_libsamipc_prog);
		ipc_lib_cleanup();
	}
	return r;
}

#define ________Internal_Functions________
//Do memory map
static int do_mmap(void)
{
	int fd;
	unsigned char *kadr;
	enum clnt_stat stat;
	struct i_libsamipc_framer_buf_info *poolinfo=&(G_libSamIPC_status.iavpool);

	stat=i_libsamipc_framer_get_iavpool_info_1(NULL,poolinfo,IPC_i_libsamipc);
	if (stat != IPC_SUCCESS) {
		LOGE("%s: ipc error %d (%s)\n", __FUNCTION__, stat, ipc_strerror(stat));
		return -stat;
	}

	if ((fd=open("/dev/amba_streammem", O_RDWR|O_SYNC))<=0)
	{
			LOGE("cannot open '/dev/amba_streammem'\n\r");
			return -1;
	}

	kadr = mmap(0, poolinfo->size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (kadr == MAP_FAILED)
	{
		int errsv = errno;

		LOGE("cannot mmap (%d:%s)\n\r",errsv,strerror(errsv));
		close(fd);
		return -1;
	}

	G_libSamIPC_status.iavpool_mmap_offset = (int)((u32)kadr - (u32)(poolinfo->base_addr));
	LOGE("mmap %x to %p with size=%x successfully!!\n\r", poolinfo->base_addr, kadr, poolinfo->size);

	close(fd);
	return 0;
}

//Do memory unmap
static int do_munmap(void)
{
	int rval;
	struct i_libsamipc_framer_buf_info *poolinfo=&(G_libSamIPC_status.iavpool);

	rval = munmap((void *)(poolinfo->base_addr+G_libSamIPC_status.iavpool_mmap_offset), poolinfo->size);
	if(rval < 0){
		int errsv = errno;

		LOGE("cannot munmap (%d:%s)\n\r",errsv,strerror(errsv));
	}

	return rval;
}

static void local_handle_stopenc(int Stream_type) {
	Exam_framer_encframe_status_t *encframe=NULL;
	encframe=&G_libSamIPC_status.encframe[ENC_STREAM_ID(Stream_type)];
	pthread_mutex_lock(&encframe->mutex);
	encframe->enc_ValidFrames = -1;
	if(encframe->wait_frm>0)
		pthread_cond_signal(&encframe->cond);
	pthread_mutex_unlock(&encframe->mutex);
}

/****************************************************
 * Server function impl
 ****************************************************/
#define ________Linux_Side_Service_Implement________
bool_t lu_libsamipc_framer_encframe_ready_1_svc(struct lu_libsamipc_framer_frameinfo *arg,
		int *res, struct svc_req *rqstp)
{
	Exam_framer_encframe_status_t *encframe=NULL;

	DBGMSG("%s:\n\r",__func__);
	DBGMSG("\t data_type=%x\n\r",arg->data_type);
	DBGMSG("\t frame_num=%x\n\r",arg->frame_num);
	DBGMSG("\t pts=%ld\n\r",arg->pts);
	DBGMSG("\t bit_values=%x\n\r",arg->bit_values);
	DBGMSG("\t start_addr=%x\n\r",arg->start_addr);
	DBGMSG("\t base_addr=%x\n\r",arg->base_addr);
	DBGMSG("\t limit_addr=%x\n\r",arg->limit_addr);
	DBGMSG("\t size=%x\n\r",arg->size);
	DBGMSG("\t type=%x\n\r",arg->type);

	if((arg->type==EXAM_FRAMER_VIDEO_ENCSTREAM) ||
	   (arg->type==EXAM_FRAMER_AUDIO_ENCSTREAM)) {
		encframe=&G_libSamIPC_status.encframe[ENC_STREAM_ID(arg->type)];
	} else {
		LOGE("%s: Unknown stream type %x \n\r",__func__,arg->type);
	}

	if(encframe!=NULL){
		pthread_mutex_lock(&encframe->mutex);
		memcpy(&(encframe->enc_framedata),arg,sizeof(struct lu_libsamipc_framer_frameinfo));
		if(encframe->enc_ValidFrames<0){
			encframe->enc_ValidFrames=1;
		} else {
			encframe->enc_ValidFrames++;
			if(encframe->wait_frm>0)
				pthread_cond_signal(&encframe->cond);
		}
		pthread_mutex_unlock(&encframe->mutex);
	}

	if(G_libSamIPC_status.enc_frameready_cb!=NULL){
		int offset = G_libSamIPC_status.iavpool_mmap_offset;

		(*G_libSamIPC_status.enc_frameready_cb)(arg->type, (Exam_framer_frameinfo_t *)&(encframe->enc_framedata),
			arg->size,offset,G_libSamIPC_status.enc_frameready_userdata);
	}

	*res = 0; //done

	return 1;
}

bool_t lu_libsamipc_framer_notify_1_svc(u_int *arg, void *res, struct svc_req *rqstp)
{
	u_int msg = *arg;

	DBGMSG("%s: msg=%x\n\r",__func__,*arg);

	switch(msg){
	case LU_LIBSAMIPC_FRAMER_VOUT_STOPENC:
		local_handle_stopenc(EXAM_FRAMER_VIDEO_ENCSTREAM);
		break;
	case LU_LIBSAMIPC_FRAMER_AOUT_STOPENC:
		local_handle_stopenc(EXAM_FRAMER_AUDIO_ENCSTREAM);
		break;
	case LU_LIBSAMIPC_FRAMER_VIN_READDONE:
	case LU_LIBSAMIPC_FRAMER_VIN_STOPDEC:
	case LU_LIBSAMIPC_FRAMER_VIN_STARTDEC:
	case LU_LIBSAMIPC_FRAMER_VIN_DECERR:
	case LU_LIBSAMIPC_FRAMER_AIN_READDONE:
	case LU_LIBSAMIPC_FRAMER_AIN_STOPDEC:
	case LU_LIBSAMIPC_FRAMER_AIN_STARTDEC:
	case LU_LIBSAMIPC_FRAMER_AIN_DECERR:
		if(G_libSamIPC_status.dec_notify_cb!=NULL) {
			(*G_libSamIPC_status.dec_notify_cb)(msg,G_libSamIPC_status.dec_notify_userdata);
		} else {
			printf("%s: Got %x, but dec_notify_cb is NULL. Skip!\n\r",__FUNCTION__,msg);
		}
		break;
	default:
		LOGE("MSG is Not supported\n\r");
		break;
	}

	return 1;
}

/**
 * operation should be blocked until config is ready.
 */
bool_t lu_libsamipc_framer_get_decode_config_1_svc(int *arg,
		struct lu_libsamipc_framer_media_config *res, struct svc_req *rqstp)
{
	int err_count=0;
	Exam_framer_media_config_t *mconf;

	//printf("%s: *arg=%x\n\r",__FUNCTION__,*arg);

	mconf = &G_libSamIPC_status.dec_mconf;

	while(mconf->type==0xffffffff){
		if(err_count > 100){
			printf("%s: Reach MAX Error count!!\n\r",__FUNCTION__);
			break;
		}
		err_count++;
		usleep(10000);
	}

	res->type = mconf->type;
	res->brate = mconf->brate;
	res->brate_min = mconf->brate_min;
	res->vid = mconf->vid;
	res->width = mconf->width;
	res->height = mconf->height;
	res->rate = mconf->rate;
	res->scale = mconf->scale;
	res->entropy_mode = mconf->entropy_mode;
	res->idr_interval = mconf->idr_interval;
	res->aid = mconf->aid;
	res->channels = mconf->channels;
	res->samples = mconf->samples;
	res->audio_format = mconf->audio_format;
	res->vcfno = mconf->vcfno;
	res->acfno = mconf->acfno;
	res->mode = mconf->mode;
	res->M = mconf->M;
	res->N = mconf->N;
	res->ar_x = mconf->ar_x;
	res->ar_y = mconf->ar_y;
	res->frmsz_a = mconf->frmsz_a;
	res->color_style = mconf->color_style;
	res->itlc_mode = mconf->itlc_mode;
	res->misc_no = mconf->misc_no;

	return 1;
}

/**
 * operation should be blocked until info is ready.
 *
 * the frame_num and PTS are suggested to start from 0.
 * app has to take care the convertion of these values.
 */
bool_t lu_libsamipc_framer_get_decframe_info_1_svc(int *arg,
		struct lu_libsamipc_framer_frameinfo *res, struct svc_req *rqstp)
{
	Exam_framer_frameinfo_t finfo = {0};
	int rval;

	DBGMSG("%s: *arg=%x\n\r",__func__,*arg);

	finfo.type=res->type;

	//callback to app
	if(G_libSamIPC_status.dec_finfo_cb==NULL){
		printf("dec_finfo_cb is NULL!\n\r");
		res->type = 0xFFFFFFFF;
		res->bit_values = 0x00ffffff; //EOS
		return 1;
	}
	rval = (*G_libSamIPC_status.dec_finfo_cb)(*arg, &finfo, G_libSamIPC_status.dec_finfo_userdata);

	//prepare output
	if(rval<0){
		printf("dec_finfo_cb returns fail!\n\r");
		res->type = 0xFFFFFFFF;
		res->bit_values = 0x00ffffff; //EOS
		return 1;
	}

	res->size = finfo.size;
	res->data_type = finfo.data_type;
	res->frame_num = finfo.frame_num;
	res->pts = finfo.pts;
	res->bit_values = finfo.bit_values;
	res->completed = finfo.completed;

	return 1;
}

/**
 * operation should be blocked until data is ready.
 *
 * the requested frame data size might less than single frame. (Due to ring buffer)
 * app's callback should take care this case. (remember the status of previous read)
 **/
bool_t lu_libsamipc_framer_get_decframe_data_1_svc(struct lu_libsamipc_framer_frameinfo *arg,
		int *res, struct svc_req *rqstp)
{
	u8 *wp;

	wp = (u8 *)(arg->start_addr+G_libSamIPC_status.iavpool_mmap_offset);

	//callback to app
	if(G_libSamIPC_status.dec_fdata_cb==NULL){
		printf("dec_fdata_cb is NULL!\n\r");
		*res = -1;
	} else {
		*res = (*G_libSamIPC_status.dec_fdata_cb)(arg->type, wp, arg->size,G_libSamIPC_status.dec_fdata_userdata);
	}

	return 1;
}

/**
 * Set system time (Call from iTron)
 */
bool_t lu_libsamipc_set_systemtime_1_svc(struct timeval *tv, void *res, struct svc_req *rqstp)
{	
	printf("[libSamIPC] Set system time from iTron. sec:%d, usec:%d\r\n", tv->tv_sec, tv->tv_usec);

	return 1;
}

/**
 * Check module status
 */
bool_t lu_libsamipc_check_module_status_1_svc(int *nStatID, int *res, struct svc_req *rqstp)
{	
	switch(*nStatID) {
	case 0:		//Module initialize
		*res = 1;
	default:
		*res = 0;
	}

	return 1;
}

/**
 * Handle message from iTron 
 *  
 **/
bool_t lu_libsamipc_ipc_notify_1_svc(struct lu_message_s *message, void *res, struct svc_req *rqstp)
{	
	printf("[libSamIPC] Handled a message from iTron. MsgID: 0x%X, param1: 0x%X, param2: 0x%X\r\n", 
		   message->msg_id, message->param1, message->param2);

	if(G_lu_Notify_Callback != NULL) {
		Notify_t notify;
		memset((char*)&notify, 0, sizeof(Notify_t));
	
		notify.msg_id = message->msg_id;
		notify.param1 = message->param1;
		notify.param2 = message->param2;
		memcpy(notify.resv, message->resv, 52);

		if(G_lu_Notify_Callback) G_lu_Notify_Callback(&notify);
	}

	return 1;
}


/*
 * Daemon-related initialization.
 */
#define ________LibSamIPC_Framer_Functions________
//Check if there is any valid frame (nonblocking)
int libSamIPC_framer_is_EncFrameValid(int Stream_type)
{
	int rval=0;
	Exam_framer_encframe_status_t *encframe=NULL;

	DBGMSG("%s\n\r",__func__);
	if(!G_libSamIPC_status.inited)
		return -EXAM_FRAMER_ERR_NOT_INITED;

	encframe=&G_libSamIPC_status.encframe[ENC_STREAM_ID(Stream_type)];
	if(pthread_mutex_trylock(&encframe->mutex)!=0){
		return 0;
	}

	rval=encframe->enc_ValidFrames;
	if(rval>0){
		rval=encframe->enc_framedata.size;
		if(rval==0){ //frame size is 0 ??
			LOGE("%d:Got a frame with size==0!!\n\r",Stream_type);
			rval=1; //return 1 to indecate frame ready
		}
	} else if(rval<0){
		encframe->enc_ValidFrames=0; //reset for next time
	}

	pthread_mutex_unlock(&encframe->mutex);

	DBGMSG("%s: %d\n\r",__func__,rval);
	return rval;
}

//Check if there is any valid frame (blocking)
int libSamIPC_framer_wait_EncFrameValid(int Stream_type)
{
	int rval=0;
	Exam_framer_encframe_status_t *encframe=NULL;

	DBGMSG("%s\n\r",__func__);
	if(!G_libSamIPC_status.inited)
		return -EXAM_FRAMER_ERR_NOT_INITED;

	encframe=&G_libSamIPC_status.encframe[ENC_STREAM_ID(Stream_type)];
	pthread_mutex_lock(&encframe->mutex);

	rval=encframe->enc_ValidFrames;
	if(rval==0) {
		encframe->wait_frm++;
		pthread_cond_wait(&encframe->cond, &encframe->mutex);
		if(encframe->wait_frm>0)
			encframe->wait_frm--;
		rval=encframe->enc_ValidFrames;
	}
	if(rval>0){
		rval=encframe->enc_framedata.size;
		if(rval==0){
			LOGE("%d:Got a frame with size==0!!\n\r",Stream_type);
			rval=1; //return 1 to indecate frame ready
		}
	} else if(rval<0){
		encframe->enc_ValidFrames=0; //reset for next time
	}

	pthread_mutex_unlock(&encframe->mutex);

	DBGMSG("%s: %d\n\r",__func__,rval);
	return rval;
}

//struct i_libsamipc_framer_frameinfo
//{
//	unsigned int data_type; /**< data type, default STRM_SYSTEM_BITS */
//	unsigned int frame_num;
//	unsigned long pts;
//	unsigned int bit_values; /* pic_type(3)|level_idc(3)|ref_idc(1)|pic_struct(1)|pic_size(24) */
//	unsigned int start_addr;
//	unsigned int base_addr;
//	unsigned int limit_addr;
//};

int libSamIPC_framer_get_EncFrameDataInfo(int Stream_type, Exam_framer_frameinfo_t *frameInfo)
{
	int offset = G_libSamIPC_status.iavpool_mmap_offset;
	Exam_framer_encframe_status_t *encframe=NULL;

	if(!libSamIPC_framer_is_EncFrameValid(Stream_type)){
		return false;
	}

	encframe=&G_libSamIPC_status.encframe[ENC_STREAM_ID(Stream_type)];
	memcpy(frameInfo,&(encframe->enc_framedata),sizeof(Exam_framer_frameinfo_t));
	frameInfo->start_addr += offset;
	frameInfo->base_addr += offset;
	frameInfo->limit_addr += offset;

	return true;
}

//Caller needs to handle recycle issue
int libSamIPC_framer_get_EncFrameData(int Stream_type, u8 **FrameData, unsigned int *DataLength)
{
	int offset = G_libSamIPC_status.iavpool_mmap_offset;
	struct lu_libsamipc_framer_frameinfo *finfo = NULL;
	Exam_framer_encframe_status_t *encframe=NULL;

	if(!libSamIPC_framer_is_EncFrameValid(Stream_type)){
		return false;
	}

	encframe=&G_libSamIPC_status.encframe[ENC_STREAM_ID(Stream_type)];
	finfo=&(encframe->enc_framedata);

	//get related addr at mmap
	*FrameData = (u8 *)(finfo->start_addr + offset);
	*DataLength = encframe->enc_framedata.size;

	return true;
}

//copy current valid frame to caller's FrameDataBuf.
//Caller needs to make sure the FrameDataBuf is enough for current valid frame size.
int libSamIPC_framer_copy_EncFrameData(int Stream_type, u8 *FrameDataBuf, unsigned int *DataLength)
{
	int offset = G_libSamIPC_status.iavpool_mmap_offset;
	struct lu_libsamipc_framer_frameinfo *finfo=NULL;
	Exam_framer_encframe_status_t *encframe=NULL;
	u8 *FrameData=NULL;
	u8 *buf_wp=FrameDataBuf;
	int len;

	DBGMSG("%s\n\r",__func__);

	encframe = &G_libSamIPC_status.encframe[ENC_STREAM_ID(Stream_type)];
	finfo = &(encframe->enc_framedata);

	FrameData = (u8 *)(finfo->start_addr + offset);
	len = encframe->enc_framedata.size;

	if((finfo->start_addr+len) >= finfo->limit_addr){ //recycle
		int tmp_len;

		tmp_len = finfo->limit_addr - finfo->start_addr;

		memcpy(buf_wp,FrameData,tmp_len);

		len -= tmp_len;
		FrameData = (u8 *)(finfo->base_addr + offset);
		buf_wp += tmp_len;
	}

	memcpy(buf_wp,FrameData,len);

	*DataLength = encframe->enc_framedata.size;
	libSamIPC_framer_notify_read_done(Stream_type);

	return true;
}

//Notify Itron current frame is done
int libSamIPC_framer_notify_read_done(int Stream_type)
{
	enum clnt_stat stat;
	unsigned int msg;
	Exam_framer_encframe_status_t *encframe=NULL;

	DBGMSG("%s\n\r",__func__);
	if(Stream_type == EXAM_FRAMER_VIDEO_ENCSTREAM){
		msg = I_LIBSAMIPC_FRAMER_VOUT_READDONE;
	} else if(Stream_type == EXAM_FRAMER_AUDIO_ENCSTREAM){
		msg = I_LIBSAMIPC_FRAMER_AOUT_READDONE;
	} else {
		LOGE("%s: invalid type %d\n", __FUNCTION__, Stream_type);
		return false;
	}

	stat=i_libsamipc_framer_notify_1(&msg,NULL,IPC_i_libsamipc);
	if (stat != IPC_SUCCESS) {
		LOGE("%s: ipc error %d (%s)\n", __FUNCTION__, stat, ipc_strerror(stat));
		return false;
	}

	encframe = &G_libSamIPC_status.encframe[ENC_STREAM_ID(Stream_type)];
	pthread_mutex_lock(&encframe->mutex);
	encframe->enc_ValidFrames--;
	pthread_mutex_unlock(&encframe->mutex);

	return true;
}

int libSamIPC_framer_decode_op(u32 cmd)
{
	enum clnt_stat stat;
	unsigned int msg;

	//printf("%s, cmd=%u\n\r",__FUNCTION__,cmd);

	switch(cmd){
	case EXAM_FRAMER_DEC_START:
		msg = I_LIBSAMIPC_FRAMER_DEC_START;
		break;
	case EXAM_FRAMER_DEC_STOP:
		msg = I_LIBSAMIPC_FRAMER_DEC_STOP;
		break;
	default:
		LOGE("%s: unsupported cmd %x",__FUNCTION__,cmd);
		return false;
	}

	stat=i_libsamipc_framer_notify_1(&msg,NULL,IPC_i_libsamipc);
	if (stat != IPC_SUCCESS) {
		LOGE("%s: ipc error %d (%s)\n", __FUNCTION__, stat, ipc_strerror(stat));
		return false;
	}

	return true;
}

int libSamIPC_framer_reg_frameready_cb(frame_ready_cb cb, void *userdata)
{
	G_libSamIPC_status.enc_frameready_cb = cb;
	G_libSamIPC_status.enc_frameready_userdata = userdata;

	return 0;
}

int libSamIPC_framer_reg_dec_finfo_cb(get_dec_frame_info_cb cb, void *userdata)
{
	G_libSamIPC_status.dec_finfo_cb = cb;
	G_libSamIPC_status.dec_finfo_userdata = userdata;

	return 0;
}

int libSamIPC_framer_reg_dec_fdata_cb(get_dec_frame_data_cb cb, void *userdata)
{
	G_libSamIPC_status.dec_fdata_cb = cb;
	G_libSamIPC_status.dec_fdata_userdata = userdata;

	return 0;
}

int libSamIPC_framer_reg_dec_notify_cb(get_dec_notify_cb cb, void *userdata)
{
	G_libSamIPC_status.dec_notify_cb = cb;
	G_libSamIPC_status.dec_notify_userdata = userdata;

	return 0;
}

int libSamIPC_framer_get_EncMediaConfig(int EncStream_id, Exam_framer_media_config_t *mconf_buf)
{
	enum clnt_stat stat;
	int type = EncStream_id;
	struct i_libsamipc_framer_media_config mconf;

	if(mconf_buf==NULL){
		LOGE("%s: mconf_buf is NULL\n\r",__FUNCTION__);
		return -1;
	}

	stat=i_libsamipc_framer_get_encode_config_1(&type,&mconf,IPC_i_libsamipc);
	if (stat != IPC_SUCCESS) {
		LOGE("%s: ipc error %d (%s)\n", __FUNCTION__, stat, ipc_strerror(stat));
		return false;
	}

	mconf_buf->brate = mconf.brate;
	mconf_buf->brate_min = mconf.brate_min;
	mconf_buf->vid = mconf.vid;
	mconf_buf->width = mconf.width;
	mconf_buf->height = mconf.height;
	mconf_buf->rate = mconf.rate;
	mconf_buf->scale = mconf.scale;
	mconf_buf->entropy_mode = mconf.entropy_mode;
	mconf_buf->idr_interval = mconf.idr_interval;
	mconf_buf->aid = mconf.aid;
	mconf_buf->channels = mconf.channels;
	mconf_buf->samples = mconf.samples;
	mconf_buf->audio_format = mconf.audio_format;
	mconf_buf->vcfno = mconf.vcfno;
	mconf_buf->acfno = mconf.acfno;
	mconf_buf->mode = mconf.mode;
	mconf_buf->M = mconf.M;
	mconf_buf->N = mconf.N;
	mconf_buf->ar_x = mconf.ar_x;
	mconf_buf->ar_y = mconf.ar_y;
	mconf_buf->frmsz_a = mconf.frmsz_a;
	mconf_buf->color_style = mconf.color_style;
	mconf_buf->itlc_mode = mconf.itlc_mode;
	mconf_buf->misc_no = mconf.misc_no;
	mconf_buf->type = mconf.type;

	if(0){
		printf("%s, config value:\n\r",__FUNCTION__);
		printf("\t type=%x\n\r",mconf_buf->type);
		printf("\t brate=%d\n\r",mconf_buf->brate);
		printf("\t brate_min=%d\n\r",mconf_buf->brate_min);
		printf("\t vid=%x\n\r",mconf_buf->vid);
		printf("\t width=%u\n\r",mconf_buf->width);
		printf("\t height=%u\n\r",mconf_buf->height);
		printf("\t rate=%u\n\r",mconf_buf->rate);
		printf("\t scale=%u\n\r",mconf_buf->scale);
		printf("\t entropy_mode=%u\n\r",mconf_buf->entropy_mode);
		printf("\t idr_interval=%u\n\r",mconf_buf->idr_interval);
		printf("\t aid=%x\n\r",mconf_buf->aid);
		printf("\t channels=%u\n\r",mconf_buf->channels);
		printf("\t samples=%u\n\r",mconf_buf->samples);
		printf("\t audio_format=%u\n\r",mconf_buf->audio_format);
		printf("\t vcfno=%u\n\r",mconf_buf->vcfno);
		printf("\t acfno=%u\n\r",mconf_buf->acfno);
		printf("\t mode=%u\n\r",mconf_buf->mode);
		printf("\t M=%u\n\r",mconf_buf->M);
		printf("\t N=%u\n\r",mconf_buf->N);
		printf("\t ar_x=%u\n\r",mconf_buf->ar_x);
		printf("\t ar_y=%u\n\r",mconf_buf->ar_y);
		printf("\t frmsz_a=%u\n\r",mconf_buf->frmsz_a);
		printf("\t color_style=%u\n\r",mconf_buf->color_style);
		printf("\t itlc_mode=%u\n\r",mconf_buf->itlc_mode);
		printf("\t misc_no=%u\n\r",mconf_buf->misc_no);
	}

	return 0;
}

int libSamIPC_framer_set_DecMediaConfig(int DecStream_id, Exam_framer_media_config_t *mconf_buf)
{
	Exam_framer_media_config_t *mconf;

	//printf("%s: DecStream_id=%x\n\r",__func__,DecStream_id);

	mconf = &G_libSamIPC_status.dec_mconf;

	if(mconf_buf==NULL){
		LOGE("%s: mconf_buf is NULL\n\r",__FUNCTION__);
		return -1;
	}

	mconf->brate = mconf_buf->brate;
	mconf->brate_min = mconf_buf->brate_min;
	mconf->vid = mconf_buf->vid;
	mconf->width = mconf_buf->width;
	mconf->height = mconf_buf->height;
	mconf->rate = mconf_buf->rate;
	mconf->scale = mconf_buf->scale;
	mconf->entropy_mode = mconf_buf->entropy_mode;
	mconf->idr_interval = mconf_buf->idr_interval;
	mconf->aid = mconf_buf->aid;
	mconf->channels = mconf_buf->channels;
	mconf->samples = mconf_buf->samples;
	mconf->audio_format = mconf_buf->audio_format;
	mconf->vcfno = mconf_buf->vcfno;
	mconf->acfno = mconf_buf->acfno;
	mconf->mode = mconf_buf->mode;
	mconf->M = mconf_buf->M;
	mconf->N = mconf_buf->N;
	mconf->ar_x = mconf_buf->ar_x;
	mconf->ar_y = mconf_buf->ar_y;
	mconf->frmsz_a = mconf_buf->frmsz_a;
	mconf->color_style = mconf_buf->color_style;
	mconf->itlc_mode = mconf_buf->itlc_mode;
	mconf->misc_no = mconf_buf->misc_no;
	mconf->type = mconf_buf->type;

	return 0;
}

/******************************************************************************/

int libSamIPC_framer_enable(int Stream_type)
{
	enum clnt_stat stat;
	unsigned int res;

	printf("[libSamIPC] Stream(%d) enabled!\r\n", Stream_type);
	DBGMSG("%s\n\r",__func__);
	stat=i_libsamipc_framer_lock_1(&Stream_type,&res, IPC_i_libsamipc);
	if (stat != IPC_SUCCESS) {
		LOGE("%s: ipc error %d (%s)\n", __FUNCTION__, stat, ipc_strerror(stat));
		return false;
	}

	return true;
}

int libSamIPC_framer_disable(int Stream_type)
{
	enum clnt_stat stat;
	unsigned int res;

	printf("[libSamIPC] Stream(%d) disabled!\r\n", Stream_type);
	DBGMSG("%s\n\r",__func__);
	if(IPC_i_libsamipc == NULL){
		LOGE("[libSamIPC]: Exam_framer_disable : IPC_i_libsamipc is NULL !!!!");
		return true;
	}
	stat=i_libsamipc_framer_unlock_1(&Stream_type,&res,IPC_i_libsamipc);
	if (stat != IPC_SUCCESS) {
		LOGE("%s: ipc error %d (%s)\n", __FUNCTION__, stat, ipc_strerror(stat));
		return false;
	}

	return true;
}

/****************************** libSamIPC frammer wrapper API **************************/
int libSamIPC_streaming_init()
{
	
}

int libSamIPC_streaming_deinit()
{
	
}
/******************************* LibSamIPC Interface Functions *************************/
#define ________LibSamIPC_Interface_Functions________
int libSamIPC_init(void)
{
	int j;

	if(G_libSamIPC_status.inited){ //already inited
		return true;
	}

	memset(&G_libSamIPC_status,0,sizeof(Exam_framer_status_t));
	G_libSamIPC_status.dec_mconf.type=0xffffffff; //init value

	for(j=0; j<ENC_STREAM_NUM; j++) {
		if(pthread_mutex_init(&G_libSamIPC_status.encframe[j].mutex,NULL)!=0){
			LOGE("Fail to create enc[%d] mutex!!\n\r", j);
			return false;
		}
		if(pthread_cond_init(&G_libSamIPC_status.encframe[j].cond, NULL)!=0) {
			LOGE("Fail to create enc[%d] cond!!\n\r", j);
			return false;
		}
	}

	libSamIPC_init_IPC_Clnt();
	if(libSamIPC_init_IPC_Svc()<0) {
		LOGE("Exam_framer_init_IPC_Svc() failed!!\n\r");
		return false;
	}

	//map iavpool
	if(do_mmap()<0){
		LOGE("Fail to do mmap!!\n\r");
		return false;
	}

#if 0
	{
		//CopyRight check
		enum clnt_stat stat;		
		int result = 0;
		if(IPC_i_libsamipc == NULL){
			LOGE("[libSamIPC]: %s : IPC_i_libsamipc is NULL !!!!", __FUNCTION__);
			return false;
		}
	
		memset((void*)p, 0, sizeof(struct ADSInfo_s));
		stat = i_libsamipc_cp_check_1(NULL, &result, IPC_i_libsamipc);
		if (stat != IPC_SUCCESS) {
			LOGE("%s: ipc error %d (%s)\n", __FUNCTION__, stat, ipc_strerror(stat));
			libSamIPC_release();
			return false;
		}
		
		if(result == 0) {
			LOGE("[libSamIPC] Platform check failed!\r\n");
			libSamIPC_release();
			return false;
		}		
	}
#endif

	DBGMSG("Exam_framer_init done.\n\r");
	G_libSamIPC_status.inited=true;

	{	//Test code
		char msg[128] = {0};
		struct DeviceSpec_s spec;
		struct SystemStatus_s status;

		memset((char*)&spec, 0, sizeof(DeviceSpec_s));
		memset((char*)&status, 0, sizeof(SystemStatus_s));
		libSamIPC_get_device_spec(&spec);
		libSamIPC_get_system_status(&status);

		sprintf(msg, "[libSamIPC] >>> Spec.fw_ver:%s  ID:%s, sta.wifi:%d, sta.gps:%d, sta.ir:%d\r\n",
				spec.fw_ver, spec.serialno, status.wifi, status.gps, status.ir);
		libSamIPC_printk(msg);
		printf(msg);

	}
	return true;
}

/*
 * Daemon-related cleanup.
 */
int libSamIPC_release(void)
{
	int j;
	if(!(G_libSamIPC_status.inited)){ //already released
		return true;
	}

	libSamIPC_release_IPC_Clnt();
	if(libSamIPC_release_IPC_Svc()<0) {
		LOGE("Exam_framer_release_IPC_Svc() failed!!\n\r");
		return false;
	}

	for(j=0; j<ENC_STREAM_NUM; j++) {
		pthread_mutex_destroy(&G_libSamIPC_status.encframe[j].mutex);
		pthread_cond_destroy(&G_libSamIPC_status.encframe[j].cond);
	}

	do_munmap();

	LOGE("libSamIPC_release done.\n\r");
	G_libSamIPC_status.inited=false;
	return true;
}

int libSamIPC_streaming_enable(int stream_type)
{
	return libSamIPC_framer_enable(stream_type);
}

int libSamIPC_streaming_disable(int stream_type)
{
	return libSamIPC_framer_disable(stream_type);
}

int libSamIPC_register_notify_callback(NotifyCallback_t pfnNotifyCallback)
{
	G_lu_Notify_Callback = pfnNotifyCallback;
}

int libSamIPC_send_notify(PNotify_t pNotify)
{
	enum clnt_stat stat;	
	struct i_message_s msg;
	unsigned int res;

	DBGMSG("%s\n\r",__func__);
	if(IPC_i_libsamipc == NULL){
		LOGE("[libSamIPC]: Exam_framer_disable : IPC_i_libsamipc is NULL !!!!");
		return true;
	}

	memset((void*)&res, 0, sizeof(IPCResult_s));
	memset((char*)&msg, 0, sizeof(struct i_message_s));
	msg.msg_id = pNotify->msg_id;
	msg.param1 = pNotify->param1;
	msg.param2 = pNotify->param2;
	memcpy(msg.resv, pNotify->resv, 52);
	stat = i_libsamipc_ipc_notify_1(&msg, &res, IPC_i_libsamipc);
	if (stat != IPC_SUCCESS) {
		LOGE("%s: ipc error %d (%s)\n", __FUNCTION__, stat, ipc_strerror(stat));
		return false;
	}

	return true;
}

int libSamIPC_printk(char *msg)
{
	enum clnt_stat stat;
	unsigned int res;
	struct i_charbuffer_s charbuf;

	DBGMSG("%s\n\r",__func__);
	if(IPC_i_libsamipc == NULL){
		LOGE("[libSamIPC]: Exam_framer_disable : IPC_i_libsamipc is NULL !!!!");
		return true;
	}

	memset((char*)&charbuf, 0, sizeof(struct i_charbuffer_s));
	sprintf(charbuf.buf, "%s", msg);

	stat = i_libsamipc_ipc_printk_1(&charbuf, &res, IPC_i_libsamipc);
	if (stat != IPC_SUCCESS) {
		LOGE("%s: ipc error %d (%s)\n", __FUNCTION__, stat, ipc_strerror(stat));
		return false;
	}

	return true;
}

int libSamIPC_get_device_spec(struct DeviceSpec_s *spec)
{
	enum clnt_stat stat;
	unsigned int res = 0;	

	DBGMSG("%s\n\r",__func__);
	if(IPC_i_libsamipc == NULL){
		LOGE("[libSamIPC]: Exam_framer_disable : IPC_i_libsamipc is NULL !!!!");
		return true;
	}

	stat = i_libsamipc_get_devicespec_1(NULL, spec, IPC_i_libsamipc);
	if (stat != IPC_SUCCESS) {
		LOGE("%s: ipc error %d (%s)\n", __FUNCTION__, stat, ipc_strerror(stat));
		return false;
	}

	return true;
}

int libSamIPC_get_system_status(struct SystemStatus_s *sysStatus)
{
	enum clnt_stat stat;
	unsigned int res = 0;	

	DBGMSG("%s\n\r",__func__);
	if(IPC_i_libsamipc == NULL){
		LOGE("[libSamIPC]: Exam_framer_disable : IPC_i_libsamipc is NULL !!!!");
		return true;
	}

	stat = i_libsamipc_get_systemstatus_1(NULL, sysStatus, IPC_i_libsamipc);
	if (stat != IPC_SUCCESS) {
		LOGE("%s: ipc error %d (%s)\n", __FUNCTION__, stat, ipc_strerror(stat));
		return false;
	}

	return true;
}

int libSamIPC_getting(struct CommParam_s *p)
{
	enum clnt_stat stat;
	int prarmID = p->id;
	
	DBGMSG("%s\n\r",__func__);
	if(IPC_i_libsamipc == NULL){
		LOGE("[libSamIPC]: Exam_framer_disable : IPC_i_libsamipc is NULL !!!!");
		return true;
	}

	stat = i_libsamipc_getting_1(&prarmID, p,IPC_i_libsamipc );
	if (stat != IPC_SUCCESS) {
		LOGE("%s: ipc error %d (%s)\n", __FUNCTION__, stat, ipc_strerror(stat));
		return false;
	}

	return true;
}

int libSamIPC_setting(struct CommParam_s *p)
{
	enum clnt_stat stat;	
	struct IPCResult_s res;

	DBGMSG("%s\n\r",__func__);
	if(IPC_i_libsamipc == NULL){
		LOGE("[libSamIPC]: Exam_framer_disable : IPC_i_libsamipc is NULL !!!!");
		return true;
	}

	memset((void*)&res, 0, sizeof(struct IPCResult_s));
	stat = i_libsamipc_setting_1(p, &res, IPC_i_libsamipc);
	if (stat != IPC_SUCCESS) {
		LOGE("%s: ipc error %d (%s)\n", __FUNCTION__, stat, ipc_strerror(stat));
		return false;
	}

	return res.resp;
}

int libSamIPC_control(struct CtrlCommand_s *p)
{
	enum clnt_stat stat;
	struct IPCResult_s res;

	DBGMSG("%s\n\r", __func__);
	if(IPC_i_libsamipc == NULL){
		LOGE("[libSamIPC]: %s : IPC_i_libsamipc is NULL !!!!", __FUNCTION__);
		return true;
	}

	memset((void*)&res, 0, sizeof(struct IPCResult_s));
	stat = i_libsamipc_control_1(p, &res, IPC_i_libsamipc);
	if (stat != IPC_SUCCESS) {
		LOGE("%s: ipc error %d (%s)\n", __FUNCTION__, stat, ipc_strerror(stat));
		return false;
	}

	return res.resp;
}

int libSamIPC_get_gsensorinfo(struct GSensorInfo_s *p)
{
	enum clnt_stat stat;

	DBGMSG("%s\n\r", __func__);
	if(IPC_i_libsamipc == NULL){
		LOGE("[libSamIPC]: %s : IPC_i_libsamipc is NULL !!!!", __FUNCTION__);
		return true;
	}

	memset((void*)p, 0, sizeof(struct GSensorInfo_s));
	stat = i_libsamipc_get_gsensorinfo_1(NULL, p, IPC_i_libsamipc);
	if (stat != IPC_SUCCESS) {
		LOGE("%s: ipc error %d (%s)\n", __FUNCTION__, stat, ipc_strerror(stat));
		return false;
	}

	return true;
}

int libSamIPC_get_gpsinfo(struct GPSInfo_s *p)
{
	enum clnt_stat stat;

	DBGMSG("%s\n\r", __func__);
	if(IPC_i_libsamipc == NULL){
		LOGE("[libSamIPC]: %s : IPC_i_libsamipc is NULL !!!!", __FUNCTION__);
		return true;
	}

	memset((void*)p, 0, sizeof(struct GPSInfo_s));
	stat = i_libsamipc_get_gpsinfo_1(NULL, p, IPC_i_libsamipc);
	if (stat != IPC_SUCCESS) {
		LOGE("%s: ipc error %d (%s)\n", __FUNCTION__, stat, ipc_strerror(stat));
		return false;
	}

	return true;
}

/******************* For MobileWitness ODM Project **********************/
/* Get ADS information */
int libSamIPC_get_adsinfo(struct ADSInfo_s *p)
{
	enum clnt_stat stat;

	DBGMSG("%s\n\r", __func__);
	if(IPC_i_libsamipc == NULL){
		LOGE("[libSamIPC]: %s : IPC_i_libsamipc is NULL !!!!", __FUNCTION__);
		return true;
	}

	memset((void*)p, 0, sizeof(struct ADSInfo_s));
	stat = i_libsamipc_get_adsinfo_1(NULL, p, IPC_i_libsamipc);
	if (stat != IPC_SUCCESS) {
		LOGE("%s: ipc error %d (%s)\n", __FUNCTION__, stat, ipc_strerror(stat));
		return false;
	}

	return true;
}
	  
/* Get MobileLink information */
int libSamIPC_get_moblielinkinfo(struct MobileLinkInfo_s *p)
{
	enum clnt_stat stat;

	DBGMSG("%s\n\r", __func__);
	if(IPC_i_libsamipc == NULL){
		LOGE("[libSamIPC]: %s : IPC_i_libsamipc is NULL !!!!", __FUNCTION__);
		return true;
	}

	memset((void*)p, 0, sizeof(struct MobileLinkInfo_s));
	stat = i_libsamipc_get_mobilelinkinfo_1(NULL, p, IPC_i_libsamipc);
	if (stat != IPC_SUCCESS) {
		LOGE("%s: ipc error %d (%s)\n", __FUNCTION__, stat, ipc_strerror(stat));
		return false;
	}

	return true;
}

int libSamIPC_get_dvrclientinfo(struct DVRClientInfo_s *p)
{
	enum clnt_stat stat;

	DBGMSG("%s\n\r", __func__);
	if(IPC_i_libsamipc == NULL){
		LOGE("[libSamIPC]: %s : IPC_i_libsamipc is NULL !!!!", __FUNCTION__);
		return true;
	}

	memset((void*)p, 0, sizeof(struct DVRClientInfo_s));
	stat = i_libsamipc_get_dvrclientinfo_1(NULL, p, IPC_i_libsamipc);
	if (stat != IPC_SUCCESS) {
		LOGE("%s: ipc error %d (%s)\n", __FUNCTION__, stat, ipc_strerror(stat));
		return false;
	}

	return true;
}

int libSamIPC_send_message(unsigned short msg, char* param)
{
	
	enum clnt_stat stat;
	unsigned int res;
	struct SendMessageToItron2_s MsgInfo;

	if(IPC_i_libsamipc == NULL){
		LOGE("[libSamIPC]: Exam_framer_disable : IPC_i_libsamipc is NULL !!!!");
		return true;
	}

	memset((char*)&MsgInfo, 0, sizeof(struct SendMessageToItron2_s));
	MsgInfo.msg = msg;

	if(param != NULL)
		strncpy(MsgInfo.buf, param, sizeof(MsgInfo.buf)-1);

	stat = i_libsamipc_ipc_send_msessage_1(&MsgInfo, &res, IPC_i_libsamipc);
	if (stat != IPC_SUCCESS) {
		LOGE("%s: ipc error %d (%s)\n", __FUNCTION__, stat, ipc_strerror(stat));
		return false;
	}

	return true;
}

int libSamIPC_receive_message(struct DeveiceStatusInfo *p)
{
	enum clnt_stat stat;

	DBGMSG("%s\n\r", __func__);
	if(IPC_i_libsamipc == NULL){
		LOGE("[libSamIPC]: %s : IPC_i_libsamipc is NULL !!!!", __FUNCTION__);
		return true;
	}

	memset((void*)p, 0, sizeof(struct DeveiceStatusInfo));
	stat = i_libsamipc_ipc_receive_msessage_1(NULL, p, IPC_i_libsamipc);
	if (stat != IPC_SUCCESS) {
		LOGE("%s: ipc error %d (%s)\n", __FUNCTION__, stat, ipc_strerror(stat));
		return false;
	}

	return true;
}

int libSamIPC_get_video_quality(struct IpcCommdata_s *p)
{
	enum clnt_stat stat;

	DBGMSG("%s\n\r", __func__);
	if(IPC_i_libsamipc == NULL){
		LOGE("[libSamIPC]: %s : IPC_i_libsamipc is NULL !!!!", __FUNCTION__);
		return true;
	}

	memset((void*)p, 0, sizeof(struct IpcCommdata_s));
	stat = i_libsamipc_ipc_get_video_quality_1(NULL, p, IPC_i_libsamipc);
	if (stat != IPC_SUCCESS) {
		LOGE("%s: ipc error %d (%s)\n", __FUNCTION__, stat, ipc_strerror(stat));
		return false;
	}

	return true;
}

int libSamIPC_get_video_alarm_msg(struct IpcCommdata_s *p)
{
	enum clnt_stat stat;

	DBGMSG("%s\n\r", __func__);
	if(IPC_i_libsamipc == NULL){
		LOGE("[libSamIPC]: %s : IPC_i_libsamipc is NULL !!!!", __FUNCTION__);
		return true;
	}

	memset((void*)p, 0, sizeof(struct IpcCommdata_s));
	stat = i_libsamipc_ipc_get_alarm_msg_1(NULL, p, IPC_i_libsamipc);
	if (stat != IPC_SUCCESS) {
		LOGE("%s: ipc error %d (%s)\n", __FUNCTION__, stat, ipc_strerror(stat));
		return false;
	}

	return true;
}



