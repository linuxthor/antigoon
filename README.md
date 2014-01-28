antigoon
========

Calculates SHA256 hash of Kernel system call table and checks for changes. Under most circumstances the syscall table should be static so a change may indicate the presence of a rootkit or other hooking code.

Proof of concept/demo. Not a finished security tool! This method can be bypassed!

(Syscall table locating code isn't mine and not sure who the original author is as I've seen it in a few places..) 
