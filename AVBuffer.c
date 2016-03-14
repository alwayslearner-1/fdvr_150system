#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>

#include "AVBuffer.h"

//#define AVBUFFER_DEBUG
#if defined(AVBUFFER_DEBUG)
#define LOG     printf
#else
#define LOG(...)
#endif

#ifndef LOGE
#define LOGE printf
#endif

static inline void read_from_buffer(buffer_info_t *buf, void *data, unsigned size)
{
	unsigned int cp_len = size;
	unsigned char *wp = (unsigned char *)data;

	if((buf->rp+size) > (buf->limit)){ //recycle
		int tlen;

		tlen= buf->limit - buf->rp;
		if(wp!=NULL){
			memcpy(wp,buf->rp,tlen);
			wp += tlen;
		}
		pthread_mutex_lock(&buf->mutex);
		buf->rp = buf->base;
		buf->size -= tlen;
		pthread_mutex_unlock(&buf->mutex);
		cp_len -= tlen;
	}

	if(wp!=NULL){
		memcpy(wp,buf->rp,cp_len);
	}
	pthread_mutex_lock(&buf->mutex);
	buf->rp += cp_len;
	buf->size -= cp_len;
	pthread_mutex_unlock(&buf->mutex);
}

static inline void write_to_buffer(buffer_info_t *buf, void *data, unsigned size)
{
	unsigned int cp_len = size;
	unsigned char *rp = (unsigned char *)data;

	if((buf->wp+size) > (buf->limit)){ //recycle
		int tlen;

		tlen= buf->limit - buf->wp;
		memcpy(buf->wp,rp,tlen);

		pthread_mutex_lock(&buf->mutex);
		buf->wp = buf->base;
		buf->size += tlen;
		pthread_mutex_unlock(&buf->mutex);
		rp += tlen;
		cp_len -= tlen;
	}

	memcpy(buf->wp,rp,cp_len);
	pthread_mutex_lock(&buf->mutex);
	buf->wp += cp_len;
	buf->size += cp_len;
	pthread_mutex_unlock(&buf->mutex);
}

/********************** API ********************/
static frame_buffer_t G_buffer;
int AVBuf_init()
{
    memset(&G_buffer, 0, sizeof(frame_buffer_t));

	/* init frame buffer */
	G_buffer.vbuf.base = (unsigned char *)malloc(VIDEO_ENC_FRAMEBUFFER_SIZE);
	if(!G_buffer.vbuf.base){
		LOGE("Fail to create video buffer!\n\r");
		return -1;
	}
	G_buffer.vbuf.limit=G_buffer.vbuf.base+VIDEO_ENC_FRAMEBUFFER_SIZE;
	G_buffer.vbuf.wp=G_buffer.vbuf.base;
	G_buffer.vbuf.rp=G_buffer.vbuf.base;
	G_buffer.vbuf.size=0;
	if(pthread_mutex_init(&G_buffer.vbuf.mutex,NULL)!=0){
		LOGE("Fail to create video mutex!\n\r");
	}

	G_buffer.abuf.base = (unsigned char *)malloc(AUDIO_ENC_FRAMEBUFFER_SIZE);
	if(!G_buffer.abuf.base){
		LOGE("Fail to create audio buffer!\n\r");
		free(G_buffer.vbuf.base);
		return -1;
	}
	G_buffer.abuf.limit=G_buffer.abuf.base+AUDIO_ENC_FRAMEBUFFER_SIZE;
	G_buffer.abuf.wp=G_buffer.abuf.base;
	G_buffer.abuf.rp=G_buffer.abuf.base;
	G_buffer.abuf.size=0;
    G_buffer.init = 1;
	if(pthread_mutex_init(&G_buffer.abuf.mutex,NULL)!=0){
		LOGE("Fail to create audio mutex!\n\r");
	}

    return 0;
}

void AVBuf_deinit()
{
    if(G_buffer.vbuf.base!=NULL){
		free(G_buffer.vbuf.base);
	}
	if(G_buffer.abuf.base!=NULL){
		free(G_buffer.abuf.base);
	}
    memset((void*)&G_buffer, 0, sizeof(frame_buffer_t));
}

int AVBuf_get_video_frames()
{
    if(G_buffer.init) {
        return G_buffer.vbuf.frames;
    } else {
        return 0;
    }
}

int AVBuf_get_audio_frames()
{
    if(G_buffer.init) {
        return G_buffer.abuf.frames;
    } else {
        return 0;
    }
}

int AVBuf_get_freespace(int bufType)
{
    int freespace = 0;

    if(bufType == VIDEO_BUFFER) {
        freespace = VIDEO_ENC_FRAMEBUFFER_SIZE - G_buffer.vbuf.size;
    } else if(bufType == AUDIO_BUFFER) {
        freespace = AUDIO_ENC_FRAMEBUFFER_SIZE - G_buffer.abuf.size;
    }

	if(freespace < 0) freespace = 0;

    return freespace;
}

void AVBuf_write_data(int bufType, void *data, unsigned int size, int frame_flag)
{
    LOG("[AVBuf] Leave %s\r\n", __FUNCTION__);
    if(G_buffer.init) {
        buffer_info_t *buf;
        if(bufType == VIDEO_BUFFER) {
            buf = &G_buffer.vbuf;
        } else {
            buf = &G_buffer.abuf;
        }
        write_to_buffer(buf, data, size);

        if(frame_flag) {
            pthread_mutex_lock(&buf->mutex);
            buf->frames++;
            pthread_mutex_unlock(&buf->mutex);
        }
    }
    LOG("[AVBuf] Leave %s\r\n", __FUNCTION__);
}

int AVBuf_read_video_frame(frame_info_t *frmInfo, void *pData, unsigned int *size)
{
    int ret = 0;
    LOG("[AVBuf] Enter %s\r\n", __FUNCTION__);
    if(AVBuf_get_video_frames() > 0) {
        int dlen = 0, rval = 0;

        read_from_buffer(&G_buffer.vbuf, frmInfo, sizeof(frame_info_t));
        dlen = frmInfo->bit_values & 0x00ffffff;
		rval = (frmInfo->bit_values & 0xe0000000) >> 29;
        read_from_buffer(&G_buffer.vbuf, pData, dlen);
        *size = dlen;

        pthread_mutex_lock(&G_buffer.vbuf.mutex);
		G_buffer.vbuf.frames--;
        pthread_mutex_unlock(&G_buffer.vbuf.mutex);

		//printf("VIDEO:===>G_buffer.vbuf.frames = %d\r\n", G_buffer.vbuf.frames);

        ret = dlen;
    }
    LOG("[AVBuf] Leave %s\r\n", __FUNCTION__);
    return ret;
}

int AVBuf_read_audio_frame(frame_info_t *frmInfo, void *pData, unsigned int *size)
{
    int ret = 0;
    if(AVBuf_get_audio_frames() > 0) {
        int dlen = 0, rval = 0;

        read_from_buffer(&G_buffer.abuf, frmInfo, sizeof(frame_info_t));
        dlen = frmInfo->bit_values & 0x00ffffff;
		rval = (frmInfo->bit_values & 0xe0000000) >> 29;
        read_from_buffer(&G_buffer.abuf, pData, dlen);
        *size = dlen;

        pthread_mutex_lock(&G_buffer.abuf.mutex);
		G_buffer.abuf.frames--;
        pthread_mutex_unlock(&G_buffer.abuf.mutex);

		//printf("AUDIO:===>G_buffer.abuf.frames = %d\r\n", G_buffer.abuf.frames);

        ret = dlen;
    }
    return ret;
}
