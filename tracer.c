#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "syscallname.c"

#define MAX_NUM_DIGITS 12

struct system_calls
{
    int ptr;
    char *name;
    int count;
};

struct system_calls *syscalls;

int do_child(int argc, char *argv[])
{
    char *args[argc + 1];
    memcpy(args, argv, argc * sizeof(char *));
    args[argc] = NULL;

    /* 
       Se inicia el tracking con PTRACE_TRACEME.
s
       Con SIGSTOP el padre podrá continuar con la ejecución del execvp,
       que creará el proceso.
    */

    ptrace(PTRACE_TRACEME);
    kill(getpid(), SIGSTOP);
    return execvp(args[0], args);
}

int wait_for_syscall(pid_t child)
{
    int status;
    while (1)
    {

        /* 
           Con PTRACE_SYSCALL haremos un trace del hijo hasta que entre o salga
           de una llamada al sistema.

           Con waitpid esperamos a que el hijo termine su ejecución, entre a 
           una llamada al sistema o salga de una.
        */

        ptrace(PTRACE_SYSCALL, child, 0, 0);
        waitpid(child, &status, 0);

        /*
           Debido al PTRACE_O_TRACESYSGOOD de do_trace, el hijo solo se
           detendrá cuando interactúe con una llamada al sistema. Cuando esto
           ocurra, retornaremos 0.

           Si el hijo terminó su ejecución, retornamos 1. 

           Si ocurren otras acciones que no interesan, se repite el ciclo.
        */

        if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
        {
            return 0;
        }
        if (WIFEXITED(status))
        {
            return 1;
        }
    }
}

int add_call(int total_syscalls, int ID, char *sysname)
{
    int i;
    for (i = 0; i < total_syscalls; i++)
    {
        if ((*(syscalls + i)).ptr == ID)
        {
            (*(syscalls + i)).count++;
            return total_syscalls;
        }
    }
    if (total_syscalls == 0)
    {
        syscalls = (struct system_calls *)malloc(sizeof(struct system_calls) * 20);
    }
    else
    {
        int mod = i % 20;
        if (mod == 0)
        {
            struct system_calls *syscalls_temp = (struct system_calls *)realloc(syscalls,
                                                                                sizeof(struct system_calls) * (i + 20));
            if (syscalls_temp == NULL)
            {
                free(syscalls);
                exit(1);
            }
            else
            {
                syscalls = syscalls_temp;
            }
        }
    }
    (syscalls + i)->ptr = ID;
    (syscalls + i)->count = 1;
    (syscalls + i)->name = (char *)malloc(32 * sizeof(char));
    get_sys_call_name(ID, (syscalls + i)->name);
    total_syscalls++;
    return total_syscalls;
}

void print_info(int total_syscalls)
{
    char size[MAX_NUM_DIGITS - 6];
    int fill_digits, diff_len_name;
    printf("+-------+-------------------+------+\n");
    printf("|ID\t|Syscall            |Amount|");
    printf("\n+-------+-------------------+------+\n");
    for (int i = 0; i < total_syscalls; i++)
    {
        printf("|%d\t|%s", (*(syscalls + i)).ptr, (*(syscalls + i)).name);
        diff_len_name = 19 - (int)strlen((*(syscalls + i)).name);
        for (int j = 0; j < diff_len_name; j++)
        {
            printf(" ");
        }
        printf("|%d", (*(syscalls + i)).count);
        sprintf(size, "%d", (*(syscalls + i)).count);
        fill_digits = MAX_NUM_DIGITS - 6 - (int)strlen(size);
        for (int k = 0; k < fill_digits; k++)
        {
            printf(" ");
        }
        printf("|\n");
    }
    printf("+-------+-------------------+------+\n");
    free(syscalls);
}

int do_trace(pid_t child, int mode)
{
    int status, syscall, retval, diff_len_name, fill_digits, total_syscalls;
    char size[MAX_NUM_DIGITS];
    total_syscalls = 0;

    char *buffer_name = (char *)malloc(sizeof(char) * 32);

    /* Con el waitpid nos esperaremos a que el hijo active el SIGSTOP. */

    waitpid(child, &status, 0);

    /* 
       Con PTRACE_O_TRACESYSGOOD definimos que solo nos interesa las llamadas
       al sistema, y no todas las demás razones por las que el SIGTRAP (causado 
       por el ptrace) puede detener al hijo. 
    */

    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);

    while (1)
    {

        /* 
           Al entrar en el loop, wait_for_syscall nos determinará si ya 
           terminó el proceso. También esperamos con esto a una llamada al
           sistema.
        */

        if (wait_for_syscall(child) != 0)
        {
            if (mode == 0)
            {
                printf("+-------------------+------+\n");
            }
            else
            {
                print_info(total_syscalls);
            }
            break;
        }

        /*
           Al entrar en una llamada al sistema vamos a encontrar el número
           de la llamada.

           Con PTRACE_PEEKUSER buscaremos una palabra de los registros, que 
           se encuentra en el registro "%rax" (funciona con ORIG_RAX).
        */

        syscall = ptrace(PTRACE_PEEKUSER, child, sizeof(long) * ORIG_RAX);
        if (mode == 0)
        {
            get_sys_call_name(syscall, buffer_name);
            printf("|%d\t|%s", syscall, buffer_name);
            diff_len_name = 19 - (int)strlen(buffer_name);
            for (int i = 0; i < diff_len_name; i++)
            {
                printf(" ");
            }
            printf("|");
        }
        else
        {
            total_syscalls = add_call(total_syscalls, syscall, NULL);
        }

        /* 
           Igual que el primer wait_for_syscall, pero con este esperamos al
           valor de retorno.
        */

        if (wait_for_syscall(child) != 0)
        {
            if (mode == 0)
            {
                printf("            |\n+-------+-------------------+------------+\n");
            }
            else
            {
                print_info(total_syscalls);
            }
            break;
        }

        /*
           Al terminar la llamada, vamos a encontrar el dato de retorno, que
           se encuentra en el registro %rax.
        */

        retval = ptrace(PTRACE_PEEKUSER, child, sizeof(long) * RAX);
        if (mode == 0)
        {
            sprintf(size, "%d", retval);
            fill_digits = MAX_NUM_DIGITS - (int)strlen(size);
            printf("%d", retval);
            for (int i = 0; i < fill_digits; i++)
            {
                printf(" ");
            }
            printf("|\n");
        }
    }

    return 0;
}

int main(int argc, char *argv[])
{

    /* No se indicó el programa para el tracking. */

    if (argc < 3)
    {
        printf("Uso: %s programa modo\n", *argv);
        exit(1);
    }

    int mode = atoi(*(argv + argc - 1));
    if (mode != 0 && mode != 1)
    {
        printf("Modo: '0' y '1'\n");
        exit(1);
    }

    if (mode == 0)
    {
        printf("+-------+-------------------+------------+\n");
        printf("|ID\t|Syscall            |Return Value|");
        printf("\n+-------+-------------------+------------+\n");
    }

    /* 
       Con fork crearemos una copia del proceso. debido a que una va a tener
       asignado un valor en child, una copia será el tracer (padre) y la otra
       el tracee (hijo).
    */

    pid_t child = fork();

    /* Empieza el tracing. */

    if (child == 0)
    {
        return do_child(argc - 2, argv + 1);
    }
    else
    {
        return do_trace(child, mode);
    }
}