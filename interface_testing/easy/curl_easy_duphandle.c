#include <curl/curl.h>
int main(){
    CURL *curl = curl_easy_init();
    CURL *nother;
    if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    nother = curl_easy_duphandle(curl);
    res = curl_easy_perform(nother);
    curl_easy_cleanup(nother);
    curl_easy_cleanup(curl);
    }
}