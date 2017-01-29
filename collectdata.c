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

typedef struct proccessfilerecord{
    char process[50];
    int safe;
}proc;

void printHelp();
void generateForAllProcs();
void generateForSpecificProcs(char *filename);
void saveTrainingData(struct syscall *syscalls,int length);
int listContains(proc *proclist,int proclistsize,char process[],int *safe);

int main(int argc,char *argv[]){
    if(argc<2){
        printHelp();
        exit(0);
    }
    else if(argc>=2){
        if(strcmp(argv[1],"-training")==0){
            if(strcmp(argv[2],"-allprocs")==0){
                generateForAllProcs();
            }
            else if(strcmp(argv[2],"-procsfile")==0){
                generateForSpecificProcs(argv[3]);
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
    // ./collectdata -training -allprocs (all procs safe)
    // ./collectdata -training -procsfile filename (procs.list)

    printf("\n");
}

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

void generateForSpecificProcs(char *filename){
    int i;
    int line_cnt;
    int char_cnt;
    char dummy[500];
    char temp[200];
    int temp_pid;
    int safe;
    FILE *proclistfile;
    FILE *perfFile;
    proc *proclist;
    int proclistsize;
    struct syscall *syscalls;

    /* List selected processes */
    proclistfile=fopen(filename,"r");
    if(proclistfile!=NULL){
        // 1. Count lines of lines(processes in file)
        line_cnt=0;
        fgets(dummy,100,proclistfile); // Ignore first line - column names
        while(fgets(dummy,100,proclistfile)!=NULL){
            line_cnt++;
        }
        printf("#processes in file: %d\n",line_cnt);
        proclistsize=line_cnt;
        proclist=(proc*)malloc(proclistsize*sizeof(proc));
        rewind(proclistfile);
        // 2. Store processes of list
        line_cnt=0;
        while(fgets(dummy,500,proclistfile)!=NULL){
            sscanf(dummy,"%s %d\n",proclist[line_cnt].process,&proclist[line_cnt].safe);
            line_cnt++;
        }
        fclose(proclistfile);

        /* List selected processes and related information */
        // Needed?

        /* Trace syscalls */
        system("sudo perf trace > perf.dat");
        perfFile=fopen("perf.dat","r");
        if(perfFile!=NULL){
            // 1. Count number of lines(syscalls)
            line_cnt=0;
            while(fgets(dummy,500,perfFile)!=NULL){
                line_cnt++;
            }
            printf("#syscalls(before applying filter): %d\n",line_cnt);
            syscalls=(struct syscall*)malloc(line_cnt*sizeof(struct syscall));
            rewind(perfFile);
            // 2. Store syscall info
            i=0;
            line_cnt=0;
            while(fgets(dummy,500,perfFile)!=NULL){
                sscanf(dummy,"%*f %*c %*f %*s %s",temp);
                // Split process and pid
                char_cnt=0;
                while(temp[char_cnt]!='/'&&temp[char_cnt]!='\0'){
                    char_cnt++;
                }
                memcpy(temp+char_cnt,"\0",1);
                temp_pid=atoi(temp+char_cnt);
                // Check if process exists in file's list
                if(listContains(proclist,proclistsize,temp,&safe)==1){
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
            fclose(perfFile);
            saveTrainingData(syscalls,i);
        }
        else{
            fprintf(stderr,"Error opening file \"perf.dat\"\n");
            exit(1);
        }
    }
    else{
        fprintf(stderr,"Error opening file \"%s\"\n",filename);
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

void saveTrainingData(struct syscall *syscalls,int length){
    int i;
    FILE *output;
    output=fopen("training.dat","w");
    if(output!=NULL){
        fprintf(output,"Timestamp\tDuration\tProcess\tpid\tSyscall\tSafe\n");
        for(i=0; i<length; i++){
            fprintf(output,"%f\t%f\t%s\t%d\t%s\t%d\n",syscalls[i].timestamp,syscalls[i].duration,
                syscalls[i].process,syscalls[i].pid,syscalls[i].syscall,syscalls[i].safe);
        }
        fclose(output);
        printf("Training set was saved in file \"training.dat\"\n");
    }
    else{
        fprintf(stderr,"Error opening file \"%s\"\n","training.dat");
        exit(1);
    }
}






