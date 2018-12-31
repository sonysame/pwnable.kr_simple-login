# pwnable.kr_simple-login
\#pwnable 
\#fake_ebp

###main function
```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _BYTE *v4; // [esp+18h] [ebp-28h]
  char s; // [esp+1Eh] [ebp-22h]
  unsigned int v6; // [esp+3Ch] [ebp-4h]

  memset(&s, 0, 0x1Eu);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  printf("Authenticate : ");
  _isoc99_scanf("%30s", &s);
  memset(&input, 0, 0xCu);
  v4 = 0;
  v6 = Base64Decode((int)&s, &v4);
  if ( v6 > 0xC )
  {
    puts("Wrong Length");
  }
  else
  {
    memcpy(&input, v4, v6);
    if ( auth(v6) == 1 )
      correct();
  }
  return 0;
}
```

###auth function
```cpp
_BOOL4 __cdecl auth(unsigned int arg0)
{
  char v3; // [esp+14h] [ebp-14h]
  char *s2; // [esp+1Ch] [ebp-Ch]
  int v5; // [esp+20h] [ebp-8h]

  memcpy(&v5, &input, arg0);
  s2 = (char *)calc_md5((int)&v3, 12);
  printf("hash : %s\n");
  return strcmp("f87cd601aa7fedca99018a8be88eda34", s2) == 0;
}
```

###correct function
```cpp
void __noreturn correct()
{
  if ( input == 0xDEADBEEF )
  {
    puts("Congratulation! you are good!");
    system("/bin/sh");
  }
  exit(0);
}
```

We have  the <u>**system("/bin/sh")**</u> gadget, which we can use to get a shell. The address of this gadget is fixed.

If we want to go to the system("/bin/sh" ) gadget, we have to know which string is encoded to **f87cd601aa7fedca99018a8be88eda34** in md5 encoding.

However, it is impossible to decode in md5. Therefore, we have to think about other ways. We get user's input and it is stored in the variable input which is in bss area. 

Length Check is done using the result of **Base64Decode((int)&s, &v4)**, which returns the length of the input's Base64Decode result.
And this should not be larger than 12. Base64Decode can reduce the size of the original data(ex, 4bytes to 3bytes). Therefore the input can be larger than 12! When I tried this, the maximum length of the input is 17bytes. 


>The vulnerabilty is here!
In main function, the input variable is the result of Base64Decode of the real input. In auth function,  **memcpy(&v5, &input, arg0)** does copy the input variable data into the variable v5. However, the size of v5 is only 8bytes, and the maximum size of the variable input is 12. We can overwrite 12bytes in maximum. This means that we can overwrite the EBP and make a fake EBP!

We can write the address of the **system("/bin/sh")** gadget into the input variable and use the fixed address of the input variable as a fake EBP!

The payload is **base64.b64enode(system gadget address+dummy+variable input address-4)**

DONE!

