#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

void createKeyFile(char *filename);

int main(int argc,char *argv[]){
    if(argc==1){
        createKeyFile("psk.key");
    }
    else if(argc==2){
        createKeyFile(argv[1]);
    }
    return 0;
}

void createKeyFile(char *filename){
    FILE *file;
    file=fopen(filename,"wb+");
    if(file!=NULL){
        srand(time(NULL));
        uint8_t num;
        int i;
        for(i=0; i<128; i++){
            num=rand()%(UINT8_MAX+1);
            fwrite(&num,1,1,file);
        }
        fclose(file);
        printf("Key file \"%s\" created\n",filename);
    }
    else{
        fprintf(stderr,"Error creating/overwriting file!\n");
        exit(1);
    }
}
