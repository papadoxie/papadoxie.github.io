# Here's a LIBC
## Write-up of the PicoCTF Binary Exploitation Challenge


<img	src="Challenge Description.png"
		alt="Challenge Description"
/>


## Setup

3 files are provided to us for the challenge and the address
to the server is also provided.

Lets download the files and try to run the binary

<img	src="Setup0.png"
		alt="Challenge Description"
/>

We get a crash
This occurs because our linker is a newer version than the libc provided

<img	src="Setup1.png"
		alt="Challenge Description"
/>


We can fix this using pwninit which will automatically take care of this

<img	src="Setup2.png"
		alt="Challenge Description"
/>

This fixed the problem

<img	src="Setup3.png"
		alt="Challenge Description"
/>


## Analysis

Lets open the binary in Ghidra and take a look at whats going on

<img	src="Analysis0.png"
		alt="Challenge Description"
/>

There is no input being taken in the main function but we see another function
Lets check it out

<img	src="Analysis1.png"
		alt="Challenge Description"
/>

This looks like what we are looking for
As we can see there is no bound checking on the scanf input
We can easily overflow the buffer since scanf will take an input until it encounters a newline

<img	src="Analysis2.png"
		alt="Challenge Description"
/>

Sure enough, we get a segmentation fault and the program crashes

Lets check the protections on the binaries

<img	src="Analysis3.png"
		alt="Challenge Description"
/>

The stack is not executable so we can't execute shellcode pushed onto it
PIE is off for vuln meaning addresses won't change for the binary on each execution
This means we can easily leak an address from libc and use it to return to libc


## Exploitation
