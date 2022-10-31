#include <curl/curl.h>
int main(){
    /* init a multi stack */
    CURLM *multi_handle = curl_multi_init();
    
    curl_multi_cleanup(multi_handle);
}