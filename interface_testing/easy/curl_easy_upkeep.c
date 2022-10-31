#include <curl/curl.h>
int main(){
    CURL *curl = curl_easy_init();
    if(curl) {
    /* Make a connection to an HTTP/2 server. */
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    
    /* Set the interval to 30000ms / 30s */
    curl_easy_setopt(curl, CURLOPT_UPKEEP_INTERVAL_MS, 30000L);
    
    curl_easy_perform(curl);
    
    /* Perform more work here. */
    
    /* While the connection is being held open, curl_easy_upkeep() can be
        called. If curl_easy_upkeep() is called and the time since the last
        upkeep exceeds the interval, then an HTTP/2 PING is sent. */
    curl_easy_upkeep(curl);
    
    /* Perform more work here. */
    
    /* always cleanup */
    curl_easy_cleanup(curl);
    }
}
