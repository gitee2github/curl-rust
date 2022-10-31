#include <curl/curl.h>
int main(){
    const struct curl_easyoption *opt = curl_easy_option_by_name("URL");
    if(opt) {
    printf("This option wants CURLoption %x\n", (int)opt->id);
    }
}