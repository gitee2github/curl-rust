#include <curl/curl.h>
int main(){
    const struct curl_easyoption *opt = curl_easy_option_by_id(CURLOPT_URL);
    if(opt) {
    printf("This option wants type %x\n", opt->type);
    }
}