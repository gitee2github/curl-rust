#include <curl/curl.h>
int main(){
    CURLUcode rc;
    CURLU *url = curl_url();
    rc = curl_url_set(url, CURLUPART_URL, "https://example.com", 0);
    if(!rc) {
    char *scheme;
    /* change it to an FTP URL */
    rc = curl_url_set(url, CURLUPART_SCHEME, "ftp", 0);
    rc = curl_url_get(url, CURLUPART_SCHEME, &scheme, 0);
    printf("the scheme is %s\n", scheme);
    curl_free(scheme);
    }
    curl_url_cleanup(url);
}