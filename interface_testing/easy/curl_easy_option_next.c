#include <curl/curl.h>
int main(){
    /* iterate over all available options */
    const struct curl_easyoption *opt;
    opt = curl_easy_option_next(NULL);
    while(opt) {
    printf("Name: %s\n", opt->name);
    opt = curl_easy_option_next(opt);
    }
}