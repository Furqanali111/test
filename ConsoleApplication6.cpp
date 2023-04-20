#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>     /* atoi */

struct dataset {
  char tempBuffer[2048];
  char input[20];
  int credits;
};


int getMenu(){
  int value;
  char input[2];
  printf("\n--- Menu ---\n");
  printf("[1] Peek for 50 Credits\n");
  printf("[2] Poke for 100 Credits\n");
  printf("[-1] Quit\n");
  printf("> ");
  scanf("%2s", &input);
  value = atoi(input);
  printf("Input %d \n", value);
  return value;
}

void peek(void){
      int value;
      char input[5];
      char tmp[10];
      printf("How far to peek > ");
      scanf("%3s", input);
      value = atoi(input);
      sprintf(tmp, "%%%d$llx", value);
      printf("%s\n", tmp);
      printf("You Peek ahead and see ", tmp, "\n");
      printf(tmp);
}

int vuln(void){
  //Important,  keep he stack in the correct sequence
  struct dataset thedata={"", "",100};
  int choice; //Menu Choice.
  
  while (thedata.credits > 0) {
    printf("\nYou have %u Credits\n", thedata.credits);
    printf("Data is '%s'\n", thedata.input);
    choice = getMenu();
    printf("Choice was %d\n", choice);
    if (choice == 1){
      thedata.credits -= 50;
      peek();
    }
    else if (choice == 2){
      thedata.credits -= 100;
      printf("What to Poke >");
      fflush(stdout);
      read(0, thedata.tempBuffer, 2048);

      //And copy
      printf("Message Stored\n");
      strcpy(thedata.input, thedata.tempBuffer);
    }
    else if (choice == -1){
      printf("Quitting\n");
      return 0;
    }
    else {
      printf("You do Nothing\n");
    }

  }
  printf("\nNo Credits left.. Exiting\n");
  return 0;
}


int main(int argc, char* argv[]){
  setbuf(stdout, NULL);
  printf("1) Use the Source Luke \n");
  printf("2) Everything is for a reason \n");
  printf("3) Dissassemble./ PEDA / GEF..\n");
  printf("4) Think about the stack!\n");
  return vuln();
}
