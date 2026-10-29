#!/usr/bin/perl
# Linux kernel credentials of the accepted UDS passed as descriptor 3.
# No caller bytes are read. SOL_SOCKET comes from the native Socket module;
# SO_PEERCRED=17 and struct ucred's three 32-bit ints are Linux UAPI.
use strict;
use warnings;
use Socket qw(SOL_SOCKET);
@ARGV == 0 or die "fixed peer helper\n";
$^O eq 'linux' or die "linux peer helper required\n";
length(pack('i3',0,0,0)) == 12 or die "unsupported ucred ABI\n";
open(my $socket, '+<&=3') or die "accepted socket required\n";
my $raw = getsockopt($socket, SOL_SOCKET, 17);
defined($raw) && length($raw) == 12 or die "kernel peer credentials unavailable\n";
my ($pid,$uid,$gid) = unpack('i3',$raw);
$pid > 0 && $uid >= 0 && $gid >= 0 or die "invalid kernel peer credentials\n";
print "$pid $uid $gid\n";
