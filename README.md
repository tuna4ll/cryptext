Cryptext Advanced Security Suite

simple encryption tool. works as a single exe file. no install needed.

<img width="275" height="183" alt="image" src="https://github.com/user-attachments/assets/b157501f-83dd-485c-b9aa-71bef1cf69e4" />

what it does
you put a secret message inside an encrypted exe file and send that file to someone. when they run it and enter the correct password the real message appears.

features

real and optional decoy password  
real password shows the real message  
decoy password shows a fake message (optional)

this can help if someone forces you to reveal a password.

security protections  
can detect debugging attempts  
can detect virtual machines  
can delete itself if suspicious activity is detected

encryption
uses AES 256 CBC  
uses Argon2id for strong key derivation  
cleans memory after use

usage

1 run cryptext.exe  
2 enter the real message and real password  
3 choose if you want a decoy message (y/n)  
4 choose the output file name for example secret  
5 send the generated exe file

warning

entering the wrong password may cause the file to delete itself  
the message only exists encrypted inside the generated exe
