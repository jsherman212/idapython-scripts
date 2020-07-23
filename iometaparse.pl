#!/usr/bin/perl

# desc: takes output from `iometa -ASn kernelcache` and generates an IDAPython
# script to symbolicate some of the kexts
#
# usage: ./iometaparse <iometaoutput>

if(!$ARGV[0]){
    die("No input file\n");
}

open(INPUTFILE, "<$ARGV[0]") or die("Couldn't open $ARGV[0]\n");
open(OUTPUTFILE, ">iometaparse-script.py") or die("Couldn't make script.py output file");

while(my $line = <INPUTFILE>){
    chomp($line);
    
    my $cur_param_num = 0;

    if($line =~ /func=(0x[[:xdigit:]]+)\s+overrides=(0x[[:xdigit:]]+)\s+pac=0x[[:xdigit:]]+\s+((([\w\d_]+)::[\w\d_~]+)\((([\w\d_\*\(\)]+,?\s*)+)?)?\)/gm){
        my $vmaddr = $1;
        my $override_vmaddr = $2;
        my $classname = $5;
        my $funcname = $4;
        my $params = $6;

        my @separated_params = split(',', $params);
        
        if(($vmaddr ne $override_vmaddr) and $vmaddr ne "0xffffffffffffffff" ){
            $funcname =~ s/~/DTOR_/;
            print(OUTPUTFILE "set_name($vmaddr, \"$funcname\")\n");
        }
    }
}
