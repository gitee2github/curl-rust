#include <curl/curl.h>
int main(){
    CURL *curl = curl_easy_init();
    if(curl) {
    int decodelen;
    char *decoded = curl_easy_unescape(curl, "%63%75%72%6c", 12, &decodelen);
    if(decoded) {
        /* do not assume printf() works on the decoded data! */
        printf("Decoded: %s\n", decoded); 
        /* ... */
        curl_free(decoded);
    }
    curl_easy_cleanup(curl);
    }
}
