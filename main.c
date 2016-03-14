/*
 * Test tool for example_framer_impl.
 *
 * Authors:
 *	Keny Huang <skhuang@ambarella.com>
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
 * Copyright (C) 2009-2012, Ambarella Inc.
 */

/**
 * This is the test module for libambastreaming
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>

#include <pthread.h>
#include "libsamipc_framer.h"
#include "libsamipc_impl.h"
#include "ipcgen/i_libsamipc.h"
#include "ipcgen/lu_libsamipc.h"
#include <sys/time.h>

#include "AVBuffer.h"

#ifndef LOGE
#define LOGE printf
#endif

/*************** IPC Operations **************/
#define ________IPC_OPERATION________
static int got_first_pts = 0;
static unsigned long first_pts = 0;
static unsigned long latest_pts = 0;
static unsigned long pts_offset = 0;

static int got_first_fn = 0;
static unsigned int first_fn = 0;
static unsigned int latest_fn = 0;
static unsigned int fn_offset = 0;

/*************** Decode related functions ****************/
#define ________DECODE_RALATED_FUNCTIONS________

/**
 * this will be called when uItron wants next frame info.
 * caller needs to make sure the frameinfo is not NULL
 */
int dec_frame_info_cb(int type, Exam_framer_frameinfo_t* frameinfo, void* userdata)
{
	int rval;
	frame_info_t finfo;
#if 0
	if(infptr_a==NULL){
		printf("%s: input fptr is NULL\n\r",__FUNCTION__);
		frameinfo->type = 0xFFFFFFFF;
		return -1;
	}

	rval = fread(&finfo,1,sizeof(frame_info_t),infptr_a);
	if(rval!=sizeof(frame_info_t)){
		printf("%s: Fail to read from input file. want %d, read %d\n\r",__FUNCTION__,sizeof(frame_info_t),rval);
		if(feof(infptr_a)){
			pts_offset = latest_pts - first_pts + got_first_pts;
			fn_offset = latest_fn - first_fn + 1;
			printf("due to EOF, loop from begining!\n\r" \
				"PTS: offset=%lu, latest=%lu, first=%lu, ft=%d\n\r" \
				"FN: offset=%u, latest=%u, first=%u\n\r", \
				pts_offset, latest_pts, first_pts, got_first_pts, \
				fn_offset, latest_fn, first_fn);
			fseek(infptr_a,sizeof(Exam_framer_media_config_t),SEEK_SET);
			rval = fread(&finfo,1,sizeof(frame_info_t),infptr_a);
			if(rval!=sizeof(frame_info_t)){
				printf("Fail to read from input file. Stop!\n\r");
				return -1;
			}
			if(0){
				printf("finfo: data_type=%x\n\r",finfo.data_type);
				printf("\t frame_num=%d\n\r",finfo.frame_num);
				printf("\t pts=%lu\n\r",finfo.pts);
				printf("\t bit_values=%x\n\r",finfo.bit_values);
			}
		} else {
			printf("due to fatal error!! Stop!\n\r");
			return -1;
		}
	}

	if(got_first_pts==0){ //1st frame
		first_pts = finfo.pts;
		got_first_pts = 1;
	} else if (got_first_pts==1){ //2nd frame
		got_first_pts = finfo.pts - first_pts; //single frame time
	}

	if(got_first_fn==0){
		first_fn = finfo.frame_num;
		got_first_fn = 1;
	}
	frameinfo->data_type = finfo.data_type;
	frameinfo->frame_num = finfo.frame_num + fn_offset;
	frameinfo->pts = finfo.pts + pts_offset;
	frameinfo->bit_values = finfo.bit_values;

	latest_pts = frameinfo->pts;
	latest_fn = frameinfo->frame_num;

	if(0){
		printf("finfo: data_type=%x\n\r",finfo.data_type);
		printf("\t frame_num=%d\n\r",finfo.frame_num);
		printf("\t pts=%lu\n\r",finfo.pts);
		printf("\t bit_values=%x\n\r",finfo.bit_values);
	}
#endif
	return sizeof(frame_info_t);
}

/**
 * this will be called when uItron wants next frame data.
 * caller needs to make sure the data_buf has enough space for read_length
 */
int dec_frame_data_cb(int type, u8 *data_buf, unsigned int read_length, void* userdata)
{
	int rval = 0;
#if 0
	if(infptr_a==NULL){
		printf("%s: input fptr is NULL\n\r",__FUNCTION__);
		return -1;
	}

	rval = fread(data_buf,1,read_length,infptr_a);
	if(rval!= read_length){
		printf("%s: Error to read from input file. want %d, read %d\n\r",__FUNCTION__,read_length,rval);
	}
#endif
	return rval;
}

/**
 * this will be called when uItron wants the notify something for decode flow.
 */
int dec_notify_cb(unsigned int msg, void* userdata)
{
#if 0
	switch(msg){
	case EXAM_FRAMER_AIN_STOPDEC: //audio dec stop
		if(infptr_a!=NULL){
			printf("%s: Got EXAM_FRAMER_AIN_STOPDEC\n\r",__FUNCTION__);
			//Jump to first frame for next decode start
			fseek(infptr_a,sizeof(Exam_framer_media_config_t),SEEK_SET);

			//reset frame info
			got_first_pts = 0;
			first_pts = 0;
			latest_pts = 0;
			pts_offset = 0;

			got_first_fn = 0;
			first_fn = 0;
			latest_fn = 0;
			fn_offset = 0;
		}
		break;
	default:
		printf("%s: Got %x. Skip!\n\r",__FUNCTION__,msg);
		break;
	}
#endif
	return 0;
}

#define ________IPC_MODULE________
/**
 * frame data ready notify callback function. Notify from iTron.
 * 
 * @param type 
 * @param framedata 
 * @param DataLength 
 * @param mmap_offset 
 * @param userdata 
 */
static void frameready_op(int type, Exam_framer_frameinfo_t* framedata, unsigned int DataLength, int mmap_offset, void* userdata)
{
	u8 *frame_rp = NULL;
	buffer_info_t *bufinfo = NULL;
	unsigned int len = DataLength;
	frame_info_t finfo;
	int bufType = 0;

	//LOGE("%s: cur_framer_size = %d, freespace = %d\r\n", __FUNCTION__, len, AVBuf_get_freespace(bufType));

	if(type == EXAM_FRAMER_VIDEO_ENCSTREAM){
		bufType = VIDEO_BUFFER;

		if(len > AVBuf_get_freespace(bufType)){
			LOGE("libSamIPC_framer: Video Buffer full!! frame will be dropped.\n\r");
			return;
		}
	} else if(type == EXAM_FRAMER_AUDIO_ENCSTREAM) {
		bufType = AUDIO_BUFFER;

		if(len > AVBuf_get_freespace(bufType)){
			LOGE("libSamIPC_framer: Audio Buffer full!! frame will be dropped.\n\r");
			return;
		}
	} else {
		LOGE("libSamIPC_framer: unsupported bitstream type %d.\n\r",type);
		return;
	}

	//write frame info
	finfo.data_type = framedata->data_type;
	finfo.frame_num = framedata->frame_num;
	finfo.pts = framedata->pts;
	finfo.bit_values = framedata->bit_values;
	//printf("%s: frame %d, ftype %d, size %u, pts=%lu\n\r", __FUNCTION__,
	   //finfo.frame_num,((finfo.bit_values&0xe0000000)>>29),DataLength,finfo.pts);

	AVBuf_write_data(bufType, &finfo, sizeof(frame_info_t), 0);

	//write frame data
	frame_rp = (u8*)(framedata->start_addr + mmap_offset);
	if((framedata->start_addr+len) > framedata->limit_addr){ //recycle
		int tlen;

		tlen = framedata->limit_addr - framedata->start_addr;

		AVBuf_write_data(bufType, frame_rp, tlen, 0);		

		len -= tlen;
		frame_rp = (u8 *)(framedata->base_addr + mmap_offset);
	}

	AVBuf_write_data(bufType, frame_rp, len, 1);	
}

int ipc_module_init()
{
	int rval;

	/* init IPC module */
	if(!libSamIPC_init()){
		LOGE("Fail to init libSamIPC_framer!\n\r");
		return -1;
	}
	LOGE("main: libSamIPC_framer inited!\n\r");
	printf("int:%d, long:%d\n\r",sizeof(unsigned int),sizeof(unsigned long));

	/* Regester frameready callback */
	rval = libSamIPC_framer_reg_frameready_cb(frameready_op,NULL);
	if(rval<0){
		printf("%s: error at %d\n",__FUNCTION__,__LINE__);
	}

	/* register dec callbacks */
	rval = libSamIPC_framer_reg_dec_finfo_cb(dec_frame_info_cb,NULL);
	if(rval<0){
		printf("%s: error at %d\n",__FUNCTION__,__LINE__);
	}

	rval = libSamIPC_framer_reg_dec_fdata_cb(dec_frame_data_cb,NULL);
	if(rval<0){
		printf("%s: error at %d\n",__FUNCTION__,__LINE__);
	}

	rval = libSamIPC_framer_reg_dec_notify_cb(dec_notify_cb,NULL);
	if(rval<0){
		printf("%s: error at %d\n",__FUNCTION__,__LINE__);
	}

	return 0;
}

void ipc_module_deinit()
{
#if 0
	if(infptr_a!=NULL) {
		libSamIPC_framer_decode_op(EXAM_FRAMER_DEC_STOP);
	}
#endif

	libSamIPC_framer_disable(EXAM_FRAMER_VIDEO_ENCSTREAM);
	libSamIPC_framer_notify_read_done(EXAM_FRAMER_VIDEO_ENCSTREAM);
	libSamIPC_framer_disable(EXAM_FRAMER_AUDIO_ENCSTREAM);
	libSamIPC_framer_notify_read_done(EXAM_FRAMER_AUDIO_ENCSTREAM);
	libSamIPC_release();
}

/******************* Test program ******************/
#define ________APPLICTIONS________
#if defined(_API_TEST)
void api_test_proc()
{
	while(1) {
		char ch;
		printf("======================================================\r\n");
		printf("d/D: Get device spec\r\n g/G: Get GPS information\r\n s/S: Get system status\r\n ");
		printf("c/C: Send control command\r\n n/N: Send notity msg to iTron\r\n");
		printf("Choice:");

		ch = getchar();
		if(ch == 'q' || ch == 'Q') {
			break;
		}
		
		if(ch == 'd' || ch == 'D') {
			struct DeviceSpec_s spec;
			printf("===== Get device spec ======\r\n");
			libSamIPC_get_device_spec(&spec);
			printf("    product_id: 0x%X\r\n", spec.product_id); 
			printf("    fw_ver    : %s\r\n", spec.fw_ver); 
			printf("    Serial_no : %s\r\n", spec.serialno);
			printf("    WarrantyNo: %s\r\n", spec.warranty_no);			
			printf("=============================\r\n");			
		}

		if(ch == 'g' || ch == 'G') {
			struct GPSInfo_s gpsInfo;
			printf("====== Get GPS info ========\r\n");
			libSamIPC_get_gpsinfo(&gpsInfo);
			printf("  GS-X   : %d\r\n", gpsInfo.gsensor.x);
			printf("  GS-Y   : %d\r\n", gpsInfo.gsensor.y);
			printf("  GS-Z   : %d\r\n", gpsInfo.gsensor.z);
			printf("    valid: %c\r\n", gpsInfo.validReady);
			printf("    lgt  : %f\r\n", gpsInfo.longitude);
			printf("    lat  : %f\r\n", gpsInfo.latitude);
			printf("    mph  : %d\r\n", gpsInfo.mph);
			printf("    date : %d\r\n", gpsInfo.utc_date);
			printf("    time : %d\r\n", gpsInfo.utc_time);
			printf("=============================\r\n");
		}

		if(ch == 's' || ch == 'S') {
			struct SystemStatus_s sysStat;
			libSamIPC_get_system_status(&sysStat);
			printf("====== Get system status ======\r\n");
			printf("    Card_capacity : %dMB\r\n", sysStat.card_capacity);
			printf("    Card_freespace: %dMB\r\n", sysStat.card_freespace);
			printf("    battery:        %d\%\r\n", sysStat.battery);
			printf("    av-in:          %d\r\n",   sysStat.av_in);
			printf("    Charge:         %d\r\n",   sysStat.charge);
			printf("    GPS:            %d\r\n",   sysStat.gps);
			printf("    WiFi:           %d\r\n",   sysStat.wifi);
			printf("    Mic:            %d\r\n",   sysStat.mic);
			printf("    LCD:            %d\r\n",   sysStat.lcd);
			printf("    AppMode:        %d\r\n",   sysStat.mode);
			printf("    ErrCode:        %d\r\n",   sysStat.err_code);
			printf("===============================\r\n");
		}

		if(ch == 'c' || ch == 'C') {
			struct CtrlCommand_s cmd;

			cmd.id = 0xF0;
			cmd.param1 = 0x1234;
			sprintf((char*)cmd.data, "Hello, Please receive this control command! (from Linux)");
			libSamIPC_control(&cmd);

			printf(">>>>>>>> Sended a control command to iTron!(0xF0/0x1234/Hello....)\r\n");
		}

		if(ch == 'n' || ch == 'N') {
			Notify_t noti;

			noti.msg_id = 0x1234;
			noti.param1 = 0x5678;
			noti.param2 = 0x9abc;
			libSamIPC_send_notify(&noti);

			printf(">>>>>>> Sended a notify message to iTorn(0x1234/0x5678/0x9abc)\r\n");
		}		
	}
}
#endif

#if defined(_FRAMER_TEST)
void framer_test_proc()
{
	frame_info_t frmInfo;
	u8 * framedata;
	unsigned int DataLength = 0, got = 0;
	unsigned int v_c=0, a_c=0;

	framedata = (u8 *)malloc(150*1024);
	if(framedata==NULL){
		printf("cannot create frame data buffer!!\n");
	}

	/* Loop to read out frame data */
	for(got=0;;got=0){
		#if 1
		if(AVBuf_read_video_frame(&frmInfo, framedata, &DataLength)) {
			//do your operation here (skip data read in example)
			v_c++;
			if((v_c&0x000000ff) == 0x000000ff){
				printf("V: %d frames\n\r",v_c);
			}
			got |= 1;
		}

		if(AVBuf_read_audio_frame(&frmInfo, framedata, &DataLength)) {
			//do your operation here (skip data read in example)
			a_c++;
			if((a_c&0x000000ff) == 0x000000ff){
				printf("A: %d frames\n\r", a_c);
			}
			got |= 2;
		}
		#endif
		if(got==0){
			usleep(500000);
		}
	}
}
#endif

#if defined(_P2PCLIENT)
#include "P2PClient/P2PClient.h"
void P2PClient_proc()
{
	char ch;
	char buf[20];
	int a;
	P2PClient_init();
	while(1) {
		//scanf("%d", &a);
		//printf("0x%x\r\n", a);
		//P2PClient_test(a, NULL);
		//ch = getchar();
		//if(ch == 'b') {
			//Set bitratef
		//}
		usleep(5000);
	}
}
#endif

#if defined(_DVRCLIENT)
#include "DVRClient/DVRClient.h"
#define DVRCLIENT_LOG_PATH	"/tmp/fuse_a/"
#define DVRCLIENT_APP_VER	"1.0.0"
void DVRClient_proc()
{
	struct DVRClientInfo_s	dvrInfo;
	memset(&dvrInfo, 0, sizeof(DVRClientInfo_s));
	libSamIPC_get_dvrclientinfo(&dvrInfo);
	printf(">>>> Starting DVRClient. devID:%s, devName:%s, svrIP:%s, svrPort:%d, localPort:%d\r\n",
		   dvrInfo.devID, dvrInfo.devName, dvrInfo.svrip, dvrInfo.svrport, dvrInfo.localport);
	DVRClient_init(dvrInfo.devID, dvrInfo.devName, dvrInfo.svrip, dvrInfo.svrport, dvrInfo.localport, DVRCLIENT_LOG_PATH, DVRCLIENT_APP_VER);
	while(1) {
		usleep(5000);
	}
}
#endif

static void app_exit(void)
{
#if defined(_P2PCLIENT)
	P2PClient_deinit();
#endif

#if defined(_DVRCLIENT)
	DVRClient_deinit();
#endif

	ipc_module_deinit();
	AVBuf_deinit();
}

void signalHandlerShutdown(int sig) {
	LOGE("libSamIPC_framer Got ShutDown signal!\n\r");
	app_exit();
	exit(0);
}
/*****
 * init and then read out data frames
 *****/
int main(int argc, char** argv)
{	
	int rval;	
	
	/* Allow ourselves to be shut down gracefully by a signal */
	signal(SIGTERM, signalHandlerShutdown);
	signal(SIGHUP, signalHandlerShutdown);
	signal(SIGUSR1, signalHandlerShutdown);
	signal(SIGQUIT, signalHandlerShutdown);
	signal(SIGINT, signalHandlerShutdown);
	signal(SIGKILL, signalHandlerShutdown);
	
	system("modprobe g_ether");
	system("ifconfig -a");
	system("udhcpc -i usb0");

	if(AVBuf_init() < 0) {
		goto __done;
	}

	if(ipc_module_init() < 0) {
		goto __done;
	}

#if defined(_API_TEST)
	api_test_proc();
#endif

#if defined(_FRAMER_TEST)
	printf(">>>>> Enable frmaer module now!\r\n");
	libSamIPC_framer_enable(EXAM_FRAMER_VIDEO_ENCSTREAM);
	libSamIPC_framer_enable(EXAM_FRAMER_AUDIO_ENCSTREAM);
	printf(">>>>> Running framer test program.... \r\n");
	framer_test_proc();
#elif defined(_P2PCLIENT)
	printf(">>>>> Enable frmaer module now!\r\n");
	//libSamIPC_framer_enable(EXAM_FRAMER_VIDEO_ENCSTREAM);
	//libSamIPC_framer_enable(EXAM_FRAMER_AUDIO_ENCSTREAM);
	P2PClient_proc();
#elif defined(_DVRCLIENT)	//For CMSV6
	printf(">>>>> Enable frmaer module now!\r\n");
	//libSamIPC_framer_enable(EXAM_FRAMER_VIDEO_ENCSTREAM);
	//libSamIPC_framer_enable(EXAM_FRAMER_AUDIO_ENCSTREAM);
	DVRClient_proc();
#endif

	printf(">>>>> Program exit! <<<<<\r\n");

__done:	
	app_exit();

	return 0;
}


