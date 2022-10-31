#include <curl/curl.h>
#include <string.h>
char hugedata[512000];
 
struct ctl {
    char *buffer;
    curl_off_t size;
    curl_off_t position;
};
 
size_t read_callback(char *buffer, size_t size, size_t nitems, void *arg)
{
    struct ctl *p = (struct ctl *) arg;
    curl_off_t sz = p->size - p->position;

    nitems *= size;
    if(sz > nitems)
    sz = nitems;
    if(sz)
    memcpy(buffer, p->buffer + p->position, sz);
    p->position += sz;
    return sz;
}
 
int seek_callback(void *arg, curl_off_t offset, int origin)
{
    struct ctl *p = (struct ctl *) arg;

    switch(origin) {
    case SEEK_END:
    offset += p->size;
    break;
    case SEEK_CUR:
    offset += p->position;
    break;
    }

    if(offset < 0)
    return CURL_SEEKFUNC_FAIL;
    p->position = offset;
    return CURL_SEEKFUNC_OK;
}
 

int main(){
    CURL *easy = curl_easy_init();
    curl_mime *mime = curl_mime_init(easy);
    curl_mimepart *part = curl_mime_addpart(mime);
    struct ctl hugectl;

    hugectl.buffer = hugedata;
    hugectl.size = sizeof hugedata;
    hugectl.position = 0;
    curl_mime_data_cb(part, hugectl.size, read_callback, seek_callback, NULL,
                    &hugectl);
}