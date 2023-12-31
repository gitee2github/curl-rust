#include <curl/curl.h>
int main(){
    CURL *curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://www.example.com/");
        CURLcode res = curl_easy_perform(curl);

        if(CURLE_OK == res) {
        char *ct;
        /* ask for the content-type */
        res = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &ct);

        if((CURLE_OK == res) && ct)
            printf("We received Content-Type: %s\n", ct);
        }

        /* always cleanup */
        curl_easy_cleanup(curl);
    }
}