// Program takes input as .cap file only.. 1st convert to hex file then analyses the global header and packet header,Data resp
// program takes command line argument as .cap file
// commands to run on linux platform 
// gcc tcpcap.c -o op
// ./op bgp.cap
//	OR
// ./op http_witp_jpegs.cap


//NOTE Program gives whole details of global header and 1st 20 packets header and data in it....but one can view all packets by changing count in for loop below



#include<stdio.h>
#include<string.h>
#include<math.h>
#include<time.h>
void mkstr(FILE *fp,char *str);
void singlebyte(FILE *fp,char *str);
long int findval(char revstr[20]);
void display(char str[20]);
void mkaddr(FILE *fp,char *str);
int findint(char c)
{

    int k=c;
    if(c=='A')

    return 10;
    else if(c=='B')
    return 11;
    else if(c=='C')
    return 12;
    else if(c=='D')
    return 13;
    else if(c=='E')
    return 14;
    else if(c=='F')
    return 15;
    else
    return k-48;
}
int hex2ascii(char c,char d)
{
    int high=findint(c)*16;
    int low=findint(d);
    return high+low;


}

long int fourhextodec(char a,char b,char c,char d,char e,char f,char g,char h)
{
     long int h1,h2,h3,h4,h5,h6,h7,h8;
     h1=findint(a);
     h1=h1*powl(16,7);
     h2=findint(b);
     h2=h2*powl(16,6);
     h3=findint(c);
     h3=h3*powl(16,5);
     h4=findint(d);
     h4=h4*powl(16,4);
     h5=findint(e);
     h5=h5*4096;
     h6=findint(f)*256;
     h7=findint(g)*16;
     h8=findint(h);

     return h1+h2+h3+h4+h5+h6+h7+h8;

}
int hex2int(char c)
{
    int first = c/16-3;
    int second = c%16;
    int result = first*10 + second;
    if(result>9)
    result--;
    return result;

}
void revert(char *str,char *revstr)
{
    int k,l,len;
    char c;



      for(k=strlen(str)-1,l=0;k>=0;k--)
     {
	 if((int)str[k]>127)
	 str[k]=0;

	 if(k%2==0)
	 {
	  //  c=str[k];
	    revstr[l]=str[k];
	    l++;
	    revstr[l]=c;
	    l++;

	 }
	 else
	 {
	     c=str[k];
	 }


     }

     revstr[l]='\0';

}

void convert(char filename[20])
{
  int n, count;
  FILE *fpi,*fpo;

  fpi = fopen(filename, "rb");
  fpo = fopen("ip1.txt", "w");
  count=0;
  while ( (n=fgetc(fpi)) != EOF)
  {
    int i;
    for (i=0; i<2; i++)
    {
      unsigned char b = (n & 0xF0) >> 4;
      if ( b < 10 )
	fputc(b + '0', fpo);
      else
	fputc(b-10 + 'A', fpo);
      n <<= 4;
    }
    count++;

 //   if (!(count % 16))
//      fputc('\n', fpo);
 //   else
      fputc(' ', fpo);
  }

  fclose(fpo);
  fclose(fpi);
  printf("\n\nFile successfully created///");

}

int main(int argc,char *argv[])
{
   int length,buf,h,y,o,i,j,k,l,v1,v2;
   long int plen,timesec,mcsec,size;
   char filename[20],c,str[20],revstr[20],b1;
    time_t fnw;
    struct tm  ts;
    char shtime[80];

   FILE *fp;

   //printf("\nEnter Name of Capture File   :  (must be .cap format)   :");
   //scanf("%s",filename);
   convert(argv[1]);          //converting cap file to hex text file named "ip1.txt"


   fp=fopen("ip1.txt","r");    //opening ip1.txt file which contain text in hexadecimal


   //Finding global header as format is Global Header|Header1|data1|Header2|data2|header3|data3...

   printf("\n\n GLOBAL HEADER \n\n");
   mkstr(fp,str);
 //  printf("%s",str);
   if(strcmp(str,"D4C3B2A1")==0)                 //next comaprison of unique identity no...not all unique ids are checked
   {
      printf("\nWinDump Capture File");
   }
    else
   {
	printf("\nwireshark or other Capture File");
    }		
   mkstr(fp,str);
  length=strlen(str);
  v1=v2=0;                             //next finding version of .cap file
   for(i=0;i<length;i++)
  {
      if(i%2!=0)
      {
	 y=hex2ascii(buf,str[i]);
	 if(i<4)
	 {
	     v1=v1+y;
	 }
	 else
	 {
	     v2=v2+y;
	 }
      }
      else
      {
	  buf=str[i];

      }


  }
     printf("\nversion is %d.%d",v1,v2);
     mkstr(fp,str);                           //next 00 00 00 00
     mkstr(fp,str);                           //next 00 00 00 00
     mkstr(fp,str);                           //next max length of packets in file

     //strrev(str);
     strcpy(revstr,"");
     revert(str,revstr);	
     plen=findval(revstr);
     printf("\nMaximum length of captured packets  :%ld",plen);
     mkstr(fp,str);
     if(strcmp(str,"01000000")==0)                         //check for ethernet,frame relay or other etc
     printf("\nData link layer protocol is Ethernet");
     else	 
	printf("\nData link layer protocol other than ethernet"); 


     //end of global header

 	for(o=0;o<20;o++)	
	{
     printf("\n\nPacket Seq no ==> %d \n",o+1);

	strcpy(revstr,"");
     mkstr(fp,str);
     revert(str,revstr);
     timesec=findval(revstr);
     printf("\nPacket timestamp in sec == %ld\n",timesec);

    fnw=(time_t)timesec;
    ts = *localtime(&fnw);
    strftime(shtime, sizeof(shtime), "Unix Timestamp  : %a %Y-%m-%d %H:%M:%S %Z", &ts);
    printf("%s\n", shtime);



     strcpy(revstr,"");
     mkstr(fp,str);
     revert(str,revstr);
     mcsec=findval(revstr);
     printf("\nPacket timestamp  in msec== %ld",mcsec);
     strcpy(revstr,"");

     mkstr(fp,str);
     revert(str,revstr);
     size=findval(revstr);
     printf("\nData Packet size ==> %ld",size);
     mkstr(fp,str);
     mkaddr(fp,str);
     printf("\nEthernet  Source address is   :  ");
     display(str);
     mkaddr(fp,str);
     printf("\nEthernet Destination address is   :   ");
     display(str);
     //data of size bytes
     printf("\nData contained in packet in ASCII\n\n");
     for(i=0;i<size-12;i++)
     {
	 singlebyte(fp,str);
	    for(j=0;j<strlen(str);j++)
	    {
		if(j%2!=0)
		{
			y=hex2ascii(b1,str[j]);
			if(y<126 && y>32)
			{
			printf("%c",y);
		       //	fputc(y,fw);

			}
			else
			{
			   y='.';
			   printf(".");
	   // fputc('.',fw);
			}

		}
		else
		{
			b1=str[j];

		}


	   }


	       }
	printf("\n\n");
}

   fclose(fp);


}
void display(char str[20])
{
    int i;
    for(i=0;i<strlen(str);i++)
    {
       if(i%2==0)
       {
	  printf("%c",str[i]);
       }
       else
       {
	  printf("%c",str[i]);
	  if(i!=strlen(str)-1)
	  printf(":");
       }
    }


}
long int findval(char revstr[20])
{
      long int y;
	 y=fourhextodec(revstr[0],revstr[1],revstr[2],revstr[3],revstr[4],revstr[5],revstr[6],revstr[7]);
      return y;

}
void mkstr(FILE *fp,char *str)
{
   char c;
   int i,j;
   for(i=0,j=0;i<12;i++)
   {
     c=fgetc(fp);
     if(c=='\n')
     i--;
     if(c!=' ' && c!='\n')
     {
	str[j]=c;
	j++;
     }

   }

   str[j++]='\0';
}
void mkaddr(FILE *fp,char *str)
{
   char c;
   int i,j;
   for(i=0,j=0;i<18;i++)
   {
     c=fgetc(fp);
     if(c=='\n')
     i--;
     if(c!=' ' && c!='\n')
     {
	str[j]=c;
	j++;
     }

   }

   str[j++]='\0';
}
void singlebyte(FILE *fp,char *str)
{
   char c;
   int i,j;
   for(i=0,j=0;i<3;i++)
   {
     c=fgetc(fp);
     if(c=='\n')
     i--;
     if(c!=' ' && c!='\n')
     {
	str[j]=c;
	j++;
     }

   }

   str[j++]='\0';
}

