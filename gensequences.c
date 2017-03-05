
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
};

void printHelp();
void generateSequences(char *in_filename, char *out_filename, int length);

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
        rewind(in_file);

        syscall_cnt=0;
        fgets(dummy,500,in_file); // Ignore first line - column names
        while(fgets(dummy,500,in_file)!=NULL){
            sscanf(dummy,"%*f%*c %*f%*c %*s %*d%*c %s %d\n",syscalls[syscall_cnt].syscall,&syscalls[syscall_cnt].safe);
            syscall_cnt++;
        }
        fclose(in_file);

        // 2. WRITE
        out_file=fopen(out_filename,"w");
        if(out_file!=NULL){

            for(i=0; i<syscall_cnt-length; i++){

                for(j=0; j<length; j++){
                    fprintf(out_file,"%s, ",syscalls[i].syscall);
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
