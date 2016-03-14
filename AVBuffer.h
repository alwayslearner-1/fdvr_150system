#ifndef __AVBUFFER_H__
#define __AVBUFFER_H__

#ifdef  __cplusplus
extern "C" {
#endif

#define VIDEO_ENC_FRAMEBUFFER_SIZE (1024*1024) //1MB
#define AUDIO_ENC_FRAMEBUFFER_SIZE (64*1024) //64KB

typedef struct buffer_info_s {
	unsigned char *base;
	unsigned char *limit;
	unsigned char *wp;
	unsigned char *rp;
	unsigned int  size;
	int frames;
	pthread_mutex_t mutex;
} buffer_info_t;

typedef struct frame_buffer_s {
	buffer_info_t vbuf;
	buffer_info_t abuf;
    int init;
}frame_buffer_t;


typedef struct frame_info_s {
	unsigned int data_type; /**< data type, default STRM_SYSTEM_BITS */
	unsigned int frame_num;
	unsigned long pts;
	unsigned int bit_values; /* pic_type(3)|level_idc(3)|ref_idc(1)|pic_struct(1)|pic_size(24) */
} frame_info_t;

/******************* API *****************/
int AVBuf_init();
void AVBuf_deinit();

int AVBuf_get_video_frames();
int AVBuf_get_audio_frames();

#define VIDEO_BUFFER  0
#define AUDIO_BUFFER  1
int AVBuf_get_freespace(int bufType);
void AVBuf_write_data(int bufType, void *data, unsigned int size, int frame_flag);
int AVBuf_read_video_frame(frame_info_t *frameInfo, void *pData, unsigned int *data_size);
int AVBuf_read_audio_frame(frame_info_t *frameInfo, void *pData, unsigned int *data_size);



#ifdef  __cplusplus
}
#endif
#endif //__AVBUFFER_H__
