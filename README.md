# ShellcodeEncoder
Little perl script to generate a self-modifying shellcode
For the moment, only the xor operation is supported, which means the generated shellcode will be xor-encoded and the decoder will also use the xor operation.

Ex: if the shellcode is in the file myshellcode, the command `./shellcode_encoder.pl myshellcode 10` will generate a self-modifying shellcode that performs a xor 10 to encode and decode

You can also specify a file containing forbidden bytes. Forbidden bytes are bytes you do not want to appear in your shellcode. If one of those bytes is foudn in the generated shellcode, the script will warn you. The forbidden bytes must be separated by a line feed.