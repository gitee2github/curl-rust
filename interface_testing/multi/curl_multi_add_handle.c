#include <curl/curl.h>

int main()
{
    CURL *easy_handle1 = curl_easy_init();
    CURL *easy_handle2 = curl_easy_init();
    /* init a multi stack */
    CURLM *multi_handle = curl_multi_init();
    int still_running;

    curl_easy_setopt(easy_handle1, CURLOPT_URL, "https://www.example.com/");
    curl_easy_setopt(easy_handle1, CURLOPT_HEADER, 0);
    curl_easy_setopt(easy_handle2, CURLOPT_URL, "http://www.php.net/");
    curl_easy_setopt(easy_handle2, CURLOPT_HEADER, 0);

    /* add individual transfers */
    curl_multi_add_handle(multi_handle, easy_handle1);
    curl_multi_add_handle(multi_handle, easy_handle2);

    do
    {
        CURLMcode mc = curl_multi_perform(multi_handle, &still_running);

        if (!mc && still_running)
            /* wait for activity, timeout or "nothing" */
            mc = curl_multi_poll(multi_handle, NULL, 0, 1000, NULL);

        if (mc)
        {
            fprintf(stderr, "curl_multi_poll() failed, code %d.\n", (int)mc);
            break;
        }

        /* if there are still transfers, loop! */
    } while (still_running);

    curl_multi_remove_handle(multi_handle, easy_handle1);
    curl_multi_remove_handle(multi_handle, easy_handle2);

    /* remove all easy handles, then: */
    curl_multi_cleanup(multi_handle);
    curl_easy_cleanup(easy_handle1);
    curl_easy_cleanup(easy_handle2);
}