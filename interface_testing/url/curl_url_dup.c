#include <curl/curl.h>
int main(){
    CURLUcode rc;
    CURLU *url = curl_url();
    CURLU *url2;
    rc = curl_url_set(url, CURLUPART_URL, "https://example.com", 0);
    if(!rc) {
    url2 = curl_url_dup(url); /* clone it! */
    curl_url_cleanup(url2);
    }
    curl_url_cleanup(url);
}