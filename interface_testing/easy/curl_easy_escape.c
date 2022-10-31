#include <curl/curl.h>
int main(){
    CURL *curl = curl_easy_init();
    if(curl) {
    char *output = curl_easy_escape(curl, "data to convert", 15);
    if(output) {
        printf("Encoded: %s\\n", output);
        curl_free(output);
    }
    }
}