#include <stdio.h>
#include <string.h>

void cmd_encrypt(int argc, char *argv[]);
void cmd_decrypt(int argc, char *argv[]);
void cmd_list_keys(int argc, char *argv[]);
void cmd_export_cert(int argc, char *argv[]);
void cmd_import_cert(int argc, char *argv[]);

static void usage(const char *prog) 
{
    fprintf(stderr,
        "Usage: %s <command> [options]\n\n"
        "Commands:\n"
        "  encrypt <file> [--slot N] [--port /dev/ttyACM0]\n"
        "  decrypt <file.pgp> [--port /dev/ttyACM0]\n",
        prog);
}

int main(int argc, char *argv[]) 
{
    if (argc < 2) 
    { 
        usage(argv[0]); 
        return 1; 
    }

    if (strcmp(argv[1], "encrypt") == 0) 
    {
        cmd_encrypt(argc-1, argv+1); 
    }
    else if (strcmp(argv[1], "decrypt") == 0)  
    {
        cmd_decrypt(argc-1, argv+1);
    }
    else 
    { 
        usage(argv[0]); 
        return 1; 
    }

    return 0;
}