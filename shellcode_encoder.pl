#!/bin/perl


use strict;
use warnings;


die("Usage: $0 <shellcode_file> xor_value [<forbidden_bytes>]") if ($#ARGV + 1 < 2);

open(my $fh, '<', $ARGV[0]) or die("Couldn't open file $ARGV[0]");

my $length = -s $ARGV[0];
my $decoder_length = 24;
my $total_length = $length + $decoder_length;
my $shellcode = sprintf("\\xeb\\x11\\x5e\\x83\\x%.2x\\x%.2x\\x48\\x31\\xc9\\xb1" .
			"\\x36\\x83\\x34\\x0e\\x%.2x\\xe0\\xfa\\xeb\\x05\\xe8" .
			"\\xea\\xff\\xff\\xff", $length, $ARGV[1], $ARGV[1]);

my $old_separator = $/;
local $/ = \1;

while (my $byte = <$fh>) {
    $shellcode = $shellcode . sprintf("\\x%.2x", ord($byte) ^ $ARGV[1]);
}


print("Encoded shellcode:\n$shellcode\n");

local $/ = $old_separator;


if ($#ARGV + 1 == 3) {
    print("\n");
    open(my $fh_forbidden_chars, '<', $ARGV[2]) or die("Couldn't open file $ARGV[2]");

    my @forbidden_bytes;
    while (my $byte = <$fh_forbidden_chars>) {
	chop($byte);
        push(@forbidden_bytes, $byte);
    }
    
    my $shellcode_copy = $shellcode;
    $shellcode_copy =~ tr/\\x//d;
    $shellcode_copy = pack("H2" x $total_length, unpack("(A2)*", $shellcode_copy));

    my $char_index = index($shellcode_copy, "\x00");
    if ($char_index != -1 && $char_index != $total_length - 1) {
	printf("Null byte detected at index %d\n", $char_index);
    }
    
    for my $byte (@forbidden_bytes) {
	$char_index = index($shellcode_copy, $byte);
        if ($char_index != -1) {
	    my $byte_length = length($byte);
	    printf("Forbidden char \\x" . join("\\x", unpack("(H2)*", $byte)) . " found at index %d\n", $char_index);
	}
    }
}
