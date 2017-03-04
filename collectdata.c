
/*
    collectdata
        1. Reads a trace file genereated by strace/perf
        2.
        3. Outputs a CSV containing the data set (training/testing)


    For example,
        #   CMD       safe
            firefox   1
            mirai     0
            filezilla 1

    Depends on ps
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct process{
    char uid[100];
    int pid;
    int ppid;
    int c;
    int sz;
    int rss;
    int psr;
    char stime[20];
    char tty[20];
    char time[20];
    char cmd[100];
};

struct syscall{
    float timestamp;
    float duration;
    char process[50];
    int pid;
    char syscall[400];
    int safe;
};

typedef struct proccess_file_record{
    char process[50];
    int safe;
}proc;

void printHelp();
void generateForAllProcs();
void generateFromPerf(char *procs_filename,char *perf_filename,char *training_filename,char* process);
void generateFromStrace(char *procs_filename,char *strace_filename,char *training_filename,char *process);
void saveTrainingData(struct syscall *syscalls,int length, char *training_filename);
int listContains(proc *proclist,int proclistsize,char process[],int *safe);

int main(int argc,char *argv[]){
    if(argc==1){
        printHelp();
        exit(0);
    }
    else if(argc>=2){
        if(strcmp(argv[1],"-training")==0){
            if(strcmp(argv[2],"-allprocs")==0){
                generateForAllProcs();
            }
            else if(strcmp(argv[2],"-procs")==0){
                if(strcmp(argv[4],"-iperf")==0){
                    if(strcmp(argv[6],"-o")==0){
                        if(strcmp(argv[8],"-p")==0){
                            generateFromPerf(argv[3],argv[5],argv[7],argv[9]); // procsfile, perffile, trainingfile, process
                        }
                        else{
                            fprintf(stderr,"Invalid option \"%s\"\n",argv[8]);
                            exit(1);
                        }
                    }
                    else{
                        fprintf(stderr,"Invalid option \"%s\"\n",argv[6]);
                        exit(1);
                    }
                }
                else if(strcmp(argv[4],"-istrace")==0){
                    if(strcmp(argv[6],"-o")==0){
                        if(strcmp(argv[8],"-p")==0){
                            generateFromStrace(argv[3],argv[5],argv[7],argv[9]); // procsfile, stracefile, trainingfile, process
                        }
                        else{
                            fprintf(stderr,"Invalid option \"%s\"\n",argv[8]);
                            exit(1);
                        }
                    }
                    else{
                        fprintf(stderr,"Invalid option \"%s\"\n",argv[6]);
                        exit(1);
                    }
                }
                else{
                    fprintf(stderr,"Invalid option \"%s\"\n",argv[4]);
                    exit(1);
                }
            }
            else{
                fprintf(stderr,"Invalid option \"%s\"\n",argv[2]);
                exit(1);
            }
        }
        else{
            fprintf(stderr,"Invalid option \"%s\"\n",argv[1]);
            exit(1);
        }
    }
    else{
        fprintf(stderr,"Invalid command syntax\n");
        printHelp();
        exit(1);
    }
    return 0;
}

void printHelp(){
    printf("Note: Run the program with administrator privileges\n");
    printf("Usage: collectdata options\n");
    printf("Options:\n");
    // ./collectdata -training -allprocs (all safe)
    // ./collectdata -training -procs <filename> -i <filename> -o <filename>

    printf("\n");
}

// TO DO: Fix/Check this function
void generateForAllProcs(){
    int i;
    int lines;
    char dummy[500];
    char temp[100];
    FILE *psFile;
    FILE *perfFile;
    struct process *processes;
    struct syscall *syscalls;

    /* List all processes and related information */
    //system("sudo ps -A > ps.dat");
    system("sudo ps -A -F > ps.dat");
    psFile=fopen("ps.dat","r");
    if(psFile!=NULL){
        // 1. Count number of lines (processes) - first line has column names
        lines=0;
        while(fgets(dummy,500,psFile)!=NULL){
            lines++;
        }
        printf("#processes: %d\n",(lines-1));
        processes=(struct process*)malloc((lines-1)*sizeof(struct process));
        rewind(psFile);
        // 2. Store process info
        lines=0;
        fgets(dummy,500,psFile); // Ignore first line - column names
        while(fgets(dummy,500,psFile)!=NULL){
            sscanf(dummy,"%s %d %d %d %d %d %d %s %s %s %s\n",
                processes[lines].uid,&processes[lines].pid,&processes[lines].ppid,&processes[lines].c,&processes[lines].sz,&processes[lines].rss,&processes[lines].psr,
                processes[lines].stime,processes[lines].tty,processes[lines].time,processes[lines].cmd);
            //printf("%s %d %d %d %d %d %d %s %s %s %s\n",
            //    processes[lines].uid,processes[lines].pid,processes[lines].ppid,processes[lines].c,processes[lines].sz,processes[lines].rss,processes[lines].psr,
            //    processes[lines].stime,processes[lines].tty,processes[lines].time,processes[lines].cmd);
            lines++;
        }
        fclose(psFile);
        system("sudo rm -f ps.dat");

        /* Trace syscalls */
        system("sudo perf trace > perf.dat");
        perfFile=fopen("perf.dat","r");
        if(perfFile!=NULL){
            // 1. Count number of lines (syscalls)
            lines=0;
            while(fgets(dummy,500,perfFile)!=NULL){
                lines++;
            }
            printf("#syscalls: %d\n",lines);
            syscalls=(struct syscall*)malloc(lines*sizeof(struct syscall));
            rewind(perfFile);
            // 2. Store syscall info
            lines=0;
            while(fgets(dummy,500,perfFile)!=NULL){
                sscanf(dummy,"%f %*c %f %*s %s %s",
                    &syscalls[lines].timestamp,&syscalls[lines].duration,
                    temp,syscalls[lines].syscall);
                //Split process and pid
                i=0;
                while(temp[i]!='/'&&temp[i]!='\0'){
                    i++;
                }
                strcpy(syscalls[lines].process,temp);
                syscalls[lines].process[i]='\0';
                i++;
                syscalls[lines].pid=atoi(temp+i);
                //
                i=0;
                while(syscalls[lines].syscall[i]!='('&&temp[i]!='\0'){
                    i++;
                }
                memcpy(syscalls[lines].syscall+i,"\0",1);
                syscalls[lines].safe=1;
                //printf("%f %f %s %d %s %d\n",
                //    syscalls[lines].timestamp,syscalls[lines].duration,
                //    syscalls[lines].process,syscalls[lines].pid,syscalls[lines].syscall,
                //    syscalls[lines].safe);
                lines++;
            }
            fclose(perfFile);
            //saveTrainingData(syscalls,lines??????????);
        }
        else{
            fprintf(stderr,"Error opening file \"perf.dat\"\n");
            exit(1);
        }
    }
    else{
        fprintf(stderr,"Error opening file \"ps.dat\"\n");
        exit(1);
    }
}

void generateFromPerf(char *procs_filename,char *perf_filename,char *training_filename,char* process){
    int i;
    int line_cnt;
    int char_cnt;
    char dummy[500];
    char temp[200];
    int temp_pid;
    int safe;

    FILE *procs_file;
    proc *procs;
    int procs_cnt;

    FILE *perf_file;
    struct syscall *syscalls;
    int perf_cnt;

    // Open procs file
    procs_file=fopen(procs_filename,"r");
    if(procs_file!=NULL){
        // Read procs file
        procs_cnt=0;
        fgets(dummy,200,procs_file); // Ignore first line - column names
        while(fgets(dummy,200,procs_file)!=NULL){
            procs_cnt++;
        }
        printf("#processes in file: %d\n",procs_cnt);
        procs=(proc*)malloc(procs_cnt*sizeof(proc));
        rewind(procs_file);
        // Store procs
        procs_cnt=0;
        fgets(dummy,200,procs_file); // Ignore first line - column names
        while(fgets(dummy,200,procs_file)!=NULL){
            sscanf(dummy,"%s %d\n",procs[procs_cnt].process,&procs[procs_cnt].safe);
            procs_cnt++;
        }
        fclose(procs_file);

        #ifdef DEBUG
            int cnt;
            for(cnt=0; cnt<procs_cnt; cnt++){
                printf("[DEBUG] %s %d\n",procs[cnt].process,procs[cnt].safe);
            }
        #endif

        // Open perf file
        perf_file=fopen(perf_filename,"r");
        if(perf_file!=NULL){
            // Read perf file
            perf_cnt=0;
            while(fgets(dummy,500,perf_file)!=NULL){
                perf_cnt++;
            }
            printf("#syscalls(before applying filter): %d\n",perf_cnt);
            syscalls=(struct syscall*)malloc(perf_cnt*sizeof(struct syscall));
            rewind(perf_file);
            // Store syscalls
            i=0;
            line_cnt=0;
            while(fgets(dummy,500,perf_file)!=NULL){
                sscanf(dummy,"%*f %*c %*f %*s %s",temp);
                // Split process and pid
                char_cnt=0;
                while(temp[char_cnt]!='/'&&temp[char_cnt]!='\0'){
                    char_cnt++;
                }
                memcpy(temp+char_cnt,"\0",1);
                temp_pid=atoi(temp+char_cnt);
                // Check if process exists in process list (apply filter)
                if(listContains(procs,procs_cnt,temp,&safe)==1){
                    sscanf(dummy,"%f %*c %f %*s %*s %s",
                        &syscalls[i].timestamp,&syscalls[i].duration,
                        syscalls[i].syscall);
                    strcpy(syscalls[i].process,temp);
                    syscalls[i].pid=temp_pid;
                    //Split syscall and arguments
                    char_cnt=0;
                    while(syscalls[i].syscall[char_cnt]!='('&&syscalls[i].syscall[char_cnt]!='\0'){
                        char_cnt++;
                    }
                    memcpy(syscalls[i].syscall+char_cnt,"\0",1);
                    syscalls[i].safe=safe;
                    //printf("%f %f %s %d %s %d\n",
                    //    syscalls[i].timestamp,syscalls[i].duration,
                    //    syscalls[i].process,syscalls[i].pid,syscalls[i].syscall,
                    //    syscalls[i].safe);
                    i++;
                }
                line_cnt++;
            }
            printf("#syscalls(after applying filter): %d\n",i);
            fclose(perf_file);
            saveTrainingData(syscalls,i,training_filename);
        }
        else{
            fprintf(stderr,"Error opening file \"%s\"\n",perf_filename);
            exit(1);
        }
    }
    else{
        fprintf(stderr,"Error opening file \"%s\"\n",procs_filename);
        exit(1);
    }
}

void generateFromStrace(char *procs_filename,char *strace_filename,char *training_filename,char *process){
    int i;
    int line_cnt;
    int char_cnt;
    char dummy[500];
    char temp[200];
    int temp_pid;
    int safe;

    FILE *procs_file;
    proc *procs;
    int procs_cnt;

    FILE *strace_file;
    struct syscall *syscalls;
    int strace_cnt;

    // Open procs file
    procs_file=fopen(procs_filename,"r");
    if(procs_file!=NULL){
        // Read procs file
        procs_cnt=0;
        fgets(dummy,200,procs_file); // Ignore first line - column names
        while(fgets(dummy,200,procs_file)!=NULL){
            procs_cnt++;
        }
        printf("#processes in file: %d\n",procs_cnt);
        procs=(proc*)malloc(procs_cnt*sizeof(proc));
        rewind(procs_file);
        // Store procs
        procs_cnt=0;
        fgets(dummy,200,procs_file); // Ignore first line - column names
        while(fgets(dummy,200,procs_file)!=NULL){
            sscanf(dummy,"%s %d\n",procs[procs_cnt].process,&procs[procs_cnt].safe);
            procs_cnt++;
        }
        fclose(procs_file);

        #ifdef DEBUG
            int cnt;
            for(cnt=0; cnt<procs_cnt; cnt++){
                printf("[DEBUG] %s %d\n",procs[cnt].process,procs[cnt].safe);
            }
        #endif

        if(listContains(procs,procs_cnt,process,&safe)==1){
            // Open strace file
            strace_file=fopen(strace_filename,"r");
            if(strace_file!=NULL){
                // Read strace file
                strace_cnt=0;
                while(fgets(dummy,500,strace_file)!=NULL){
                    strace_cnt++;
                }
                printf("#syscalls(before applying filter): %d\n",strace_cnt);
                syscalls=(struct syscall*)malloc(strace_cnt*sizeof(struct syscall));
                rewind(strace_file);
                // Store syscalls
                i=0;
                while(fgets(dummy,500,strace_file)!=NULL){
                    sscanf(dummy,"%d %f %s",&syscalls[i].pid,&syscalls[i].timestamp,syscalls[i].syscall);
                    //Split syscall and arguments
                    char_cnt=0;
                    while(syscalls[i].syscall[char_cnt]!='('&&syscalls[i].syscall[char_cnt]!='\0'){
                        char_cnt++;
                    }
                    memcpy(syscalls[i].syscall+char_cnt,"\0",1);
                    syscalls[i].safe=safe;
                    strcpy(syscalls[i].process,process);
                    syscalls[i].duration=-1;
                    i++;
                }
                printf("#syscalls(after applying filter): %d\n",i);
                fclose(strace_file);
                saveTrainingData(syscalls,i,training_filename);
            }
            else{
                fprintf(stderr,"Error opening file \"%s\"\n",strace_filename);
                exit(1);
            }
        }
        else{
            fprintf(stderr,"Process \"%s\" not found in process file\n",process);
            exit(1);
        }
    }
    else{
        fprintf(stderr,"Error opening file \"%s\"\n",procs_filename);
        exit(1);
    }
}

int listContains(proc *proclist,int proclistsize,char process[],int *safe){
    int i;
    for(i=0; i<proclistsize; i++){
        if(strcmp(proclist[i].process,process)==0){
            *safe=proclist[i].safe;
            return 1;
        }
    }
    return 0;
}

void saveTrainingData(struct syscall *syscalls,int length,char *training_filename){
    int i;
    FILE *training_file;
    training_file=fopen(training_filename,"w");
    if(training_file!=NULL){
        fprintf(training_file,"#Timestamp\tDuration\tProcess\tpid\tSyscall\tSafe\n");
        for(i=0; i<length; i++){
            fprintf(training_file,"%f, %f, %s, %d, %s, %d\n",syscalls[i].timestamp,syscalls[i].duration,
                syscalls[i].process,syscalls[i].pid,syscalls[i].syscall,syscalls[i].safe);
        }
        fclose(training_file);
        printf("Training set was saved in file \"%s\"\n",training_filename);
    }
    else{
        fprintf(stderr,"Error opening file \"%s\"\n",training_filename);
        exit(1);
    }
}

