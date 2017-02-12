#include <stdio.h>
#include <stdlib.h>

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

void printHelp();
void allProcsSafe();
void modifyCmd(char *cmd);

int main(int argc,char *argv[]){
    if(argc<2){ // mkproclist
        printHelp();
        exit(0);
    }
    else if(argc==2){
        if(strcmp(argv[1],"-allsafe")==0){ // mkproclist -all
            allProcsSafe();
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
    printf("\nNote: Run the program with administrator privileges\n");
    printf("Usage: mkproclist options\n");
    printf("Options:\n");

    printf("\n");
}

void allProcsSafe(){
    int i;
    int cnt;
    char dummy[500];
    FILE *psFile;
    struct process *processes;
    FILE *output;

    /* List all processes and related information */
    system("sudo ps -A -F > ps.dat");
    psFile=fopen("ps.dat","r");
    if(psFile!=NULL){
        // 1. Count number of lines (processes) - first line has column names
        cnt=0;
        while(fgets(dummy,500,psFile)!=NULL){
            cnt++;
        }
        printf("#processes: %d\n",(cnt-1));
        processes=(struct process*)malloc((cnt-1)*sizeof(struct process));
        rewind(psFile);
        // 2. Store process info
        cnt=0;
        fgets(dummy,500,psFile); // Ignore first line - column names
        while(fgets(dummy,500,psFile)!=NULL){
            sscanf(dummy,"%s %d %d %d %d %d %d %s %s %s %s\n",
                processes[cnt].uid,&processes[cnt].pid,&processes[cnt].ppid,&processes[cnt].c,&processes[cnt].sz,&processes[cnt].rss,&processes[cnt].psr,
                processes[cnt].stime,processes[cnt].tty,processes[cnt].time,processes[cnt].cmd);
            //printf("%s %d %d %d %d %d %d %s %s %s %s\n",
            //    processes[lines].uid,processes[lines].pid,processes[lines].ppid,processes[lines].c,processes[lines].sz,processes[lines].rss,processes[lines].psr,
            //    processes[lines].stime,processes[lines].tty,processes[lines].time,processes[lines].cmd);
            modifyCmd(processes[cnt].cmd);
            cnt++;
        }
        fclose(psFile);
        system("sudo rm -f ps.dat");
        // 3. Output file
        output=fopen("procs.list","w");
        if(output!=NULL){
            fprintf(output,"CMD Safe\n");
            for(i=0; i<cnt; i++){
                fprintf(output,"%s %d\n",processes[i].cmd,1);
            }
            fclose(output);
        }
        else{
            fprintf(stderr,"Error opening file \"%s\"\n","procs.list");
            exit(1);
        }
        printf("Process list was written to file \"%s\"\n","procs.list");
    }
    else{
        fprintf(stderr,"Error opening file \"ps.dat\"\n");
        exit(1);
    }
}

void modifyCmd(char *cmd){
    char temp[100];
    int temp_cnt;
    int i;
    int last=0;
    int last_offset;

    // Case 1
    if(cmd[0]=='['){
        i=1;
        while(cmd[i]!=']'){
            i++;
        }
        for(temp_cnt=0; temp_cnt<i-1; temp_cnt++){
            temp[temp_cnt]=cmd[temp_cnt+1];
        }
        temp[temp_cnt]='\0';
        for(temp_cnt=0; temp_cnt<i; temp_cnt++){
            cmd[temp_cnt]=temp[temp_cnt];
        }
    }

    // Case 2
    if(cmd[0]=='/'){
        last_offset=0;
        i=1;
        do{
            while(cmd[i]!='/'&&cmd[i]!='\0'){
                i++;
            }
            if(cmd[i]=='/'){
                last_offset=i;
                i++;
            }
            if(cmd[i]=='\0'){
                last=1;
            }

        }while(last==0);
        for(temp_cnt=0; temp_cnt<i-last_offset+1; temp_cnt++){
            cmd[temp_cnt]=cmd[last_offset+1+temp_cnt];
        }
    }
}

