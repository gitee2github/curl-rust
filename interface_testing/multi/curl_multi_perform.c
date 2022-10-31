#include <curl/curl.h>
int main()
{
  CURLM *multi_handle = curl_multi_init();

  int still_running;
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
}