#include <curl/curl.h>

// gcc curl_multi_cleanup.c -L/home/hanxj/1020/curl/build/lib -lcurl -lnghttp2 -lgsasl -lpsl -lssl -lcrypto -lssl -lcrypto -lz -ldl -pthread -o curl_multi_cleanup

int main()
{
    /* init a multi stack */
    CURLM *multi_handle = curl_multi_init();
    /* remove all easy handles, then: */
    CURLMcode res = curl_multi_cleanup(multi_handle);

    // error codes ref: https://curl.se/libcurl/c/libcurl-errors.html
    if ((int)res == 0)
    {
        printf("All fine. Proceed as usual.\n");
    }
    else
    {
        fprintf(stderr, "Something wrong, code %d.\n", (int)res);
    }

    return 0;
}