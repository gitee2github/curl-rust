#include <curl/curl.h>
int main(){
    CURLSHcode sh;
    CURLSH *share = curl_share_init();
    sh = curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT);
    if(sh)
    printf("Error: %s\n", curl_share_strerror(sh));
    curl_share_cleanup(share);
}