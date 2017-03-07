
/*
    sequences
        1.
        2.
        3.


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

struct syscall{
    float timestamp;
    float duration;
    char process[50];
    int pid;
    char syscall[400];
    int safe;
    int val;
};

void printHelp();
void generateSequences(char *in_filename, char *out_filename, int length);
int listContains(char **syscall_list,int length,char *syscall);
int getVal(char **syscall_list,int length,int *val,char *syscall);

int main(int argc,char *argv[]){
    if(argc==1){
        printHelp();
        exit(0);
    }
    else if(argc==6){
        if(strcmp(argv[1],"-i")==0){
            if(strcmp(argv[3],"-o")==0){
                generateSequences(argv[2],argv[4],atoi(argv[5]));
            }
            else{
                fprintf(stderr,"Invalid option \"%s\"\n",argv[3]);
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
    printf("Usage: gensequences options\n");
    printf("Options:\n");
    // ./gensequences -i <filename> -o <filename> <sequence_length>

    printf("\n");
}

void generateSequences(char *in_filename, char *out_filename, int length){
    FILE *in_file;
    FILE *out_file;
    char dummy[500];
    struct syscall *syscalls;
    int syscall_cnt;
    int i,j;

    // 1. READ
    in_file=fopen(in_filename,"r");
    if(in_file!=NULL){
        syscall_cnt=0;
        fgets(dummy,200,in_file); // Ignore first line - column names
        while(fgets(dummy,200,in_file)!=NULL){
            syscall_cnt++;
        }
        printf("#syscalls: %d\n",(syscall_cnt));
        syscalls=(struct syscall*)malloc(syscall_cnt*sizeof(struct syscall));

        syscall_cnt=0;
        fgets(dummy,500,in_file); // Ignore first line - column names
        while(fgets(dummy,500,in_file)!=NULL){
            sscanf(dummy,"%*f%*c %*f%*c %*s %*d%*c %s %d\n",syscalls[syscall_cnt].syscall,&syscalls[syscall_cnt].safe);
            syscall_cnt++;
        }
        fclose(in_file);

        // 2. Transform text to num
        char **syscall_list;
        int *val;
        syscall_list=(char**)malloc(1000*sizeof(char*)); // for 1k different syscalls
        for(i=0; i<1000; i++){
            syscall_list[i]=(char*)malloc(100*sizeof(char)); // for 100 character syscalls
        }
        val=(int*)malloc(1000*sizeof(int));

        //read list
        FILE *syscall_list_file;
        syscall_list_file=fopen("syscall.list","r");
        int c=0;
        while(fgets(dummy,200,syscall_list_file)!=NULL){
            sscanf(dummy,"%s %d\n",syscall_list[c],&val[c]); // ?
            c++;
        }
        rewind(syscall_list_file);

        //add new syscalls

        int list_cnt=c;
        for(i=0; i<syscall_cnt; i++){
            if(!listContains(syscall_list,list_cnt,syscalls[i].syscall)){
                strcpy(syscall_list[list_cnt],syscalls[i].syscall);
                val[list_cnt]=list_cnt;
                list_cnt++;
            }
        }
        printf("#unique syscalls: %d\n",(list_cnt));

        //write list
        //FILE *syscall_list_file; // syscall val
        syscall_list_file=fopen("syscall.list","w");
        for(i=0; i<list_cnt; i++){
            fprintf(syscall_list_file,"%s %d\n",syscall_list[i],val[i]);
        }
        fclose(syscall_list_file);

        for(i=0; i<syscall_cnt; i++){
            syscalls[i].val=getVal(syscall_list,list_cnt,val,syscalls[i].syscall);
        }

        // 3. WRITE
        out_file=fopen(out_filename,"w");
        if(out_file!=NULL){

            for(i=0; i<syscall_cnt-length; i++){

                for(j=0; j<length; j++){
                    fprintf(out_file,"%d, ",syscalls[i+j].val);
                }
                fprintf(out_file,"%d\n",syscalls[i].safe);

            }
            fclose(out_file);
            printf("Training set was saved in file \"%s\"\n",out_filename);
        }
        else{
            fprintf(stderr,"Error opening file \"%s\"\n",out_filename);
            exit(1);
        }
    }
    else{
        fprintf(stderr,"Error opening file \"%s\"\n",in_filename);
        exit(1);
    }
}

int listContains(char **syscall_list,int length,char *syscall){
    int i;
    for(i=0; i<length; i++){
        if(strcmp(syscall_list[i],syscall)==0){
            return 1;
        }
    }
    return 0;
}

int getVal(char **syscall_list,int length,int *val,char *syscall){
    int i;
    for(i=0; i<length; i++){
        if(strcmp(syscall_list[i],syscall)==0){
            return val[i];
        }
    }
    fprintf(stderr,"val for syscall not found\n");
    exit(1);
    return 0;
}
