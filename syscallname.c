#include <stdio.h>
#include <string.h>
#include <stdlib.h>

FILE *file;

void read_file()
{
    file = fopen("/usr/include/x86_64-linux-gnu/asm/unistd_64.h", "r");
}

char *ltrim(char *str, const char *seps)
{
    size_t totrim;
    if (seps == NULL)
    {
        seps = "\t\n\v\f\r ";
    }
    totrim = strspn(str, seps);
    if (totrim > 0)
    {
        size_t len = strlen(str);
        if (totrim == len)
        {
            str[0] = '\0';
        }
        else
        {
            memmove(str, str + totrim, len + 1 - totrim);
        }
    }
    return str;
}

char *rtrim(char *str, const char *seps)
{
    int i;
    if (seps == NULL)
    {
        seps = "\t\n\v\f\r ";
    }
    i = strlen(str) - 1;
    while (i >= 0 && strchr(seps, str[i]) != NULL)
    {
        str[i] = '\0';
        i--;
    }
    return str;
}

char *trim(char *str, const char *seps)
{
    return ltrim(rtrim(str, seps), seps);
}

char *get_sys_call_name(int number, char* name)
{
    if (file == NULL)
    {
        read_file();
    }
    char buffer[1024];
    char number_str[4];
    sprintf(number_str, "%u", number);
    rewind(file);
    int current_pos = ftell(file);
    int next_line;
    int cmp_result;

    while (!feof(file))
    {
        char *token;
        fgets(buffer, sizeof(buffer), file);
        token = strtok(buffer, " ");
        cmp_result = strcmp(token, "#define");
        if (cmp_result != 0)
        {
            continue;
        }
        token = strtok(NULL, " ");
        char syscall_name[32];
        strcpy(syscall_name, token);
        token = strtok(NULL, " ");
        trim(token, NULL);
        if (strcmp(token, number_str) == 0)
        {
            if (strspn(syscall_name, "__NR_") != 5){
                continue;
            }
            ltrim(syscall_name, "__NR_");
            strcpy(name, syscall_name);
            break;
        }
        memset(buffer, 0, 1024);
    }
}