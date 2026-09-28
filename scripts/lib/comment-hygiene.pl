#!/usr/bin/env perl
# Comment-hygiene scanner behind check.sh. check.ps1 runs the same algorithm in
# PowerShell; both read scripts/lib/comment-hygiene.rules and both must pass the
# fixture self-test, which is what keeps them in step.
#
# Usage: perl comment-hygiene.pl <rules-file> <root> < NUL-separated paths
# Prints one `path:line<TAB>text` per offence (line 0 = the file name) and
# exits 0; the caller decides what a non-empty answer means.
use strict;
use warnings;
use utf8;
use Encode qw(decode);

binmode STDOUT, ':encoding(UTF-8)';

my ($rules_path, $root) = @ARGV;
die "usage: comment-hygiene.pl <rules-file> <root>\n" unless defined $root;

my %rule;
open my $rf, '<:encoding(UTF-8)', $rules_path or die "cannot read $rules_path: $!\n";
while (my $l = <$rf>) {
  $l =~ s/\r?\n\z//;
  next if $l =~ /^\s*(?:#|\z)/;
  my ($key, $value) = split /=/, $l, 2;
  die "malformed rule line: $l\n" unless defined $value;
  $rule{$key} = $value;
}
close $rf;
for my $key (qw(anywhere comment exempt filename slash hash hashnames exclude)) {
  die "rule '$key' missing from $rules_path\n" unless exists $rule{$key};
}

my $anywhere = qr/$rule{anywhere}/;
my $comment  = qr/$rule{comment}/;
my $exempt   = qr/$rule{exempt}/;
my $filename = qr/$rule{filename}/;
my %slash     = map { $_ => 1 } split ' ', $rule{slash};
my %hash      = map { $_ => 1 } split ' ', $rule{hash};
my %hashnames = map { $_ => 1 } split ' ', $rule{hashnames};
my @exclude   = split ' ', $rule{exclude};
my $opener    = qr/^\s*(?:\/[\/*]+!?|\*+|<#|#+)?\s*/;

sub is_offence {
  my ($text) = @_;
  return $text =~ $anywhere || ($text =~ $comment && $text !~ $exempt);
}

my @found;
my $input = do { local $/; <STDIN> } // '';
PATH: for my $raw_path (sort grep { length } split /\0/, $input) {
  my $path = decode('UTF-8', $raw_path);
  for my $prefix (@exclude) {
    next PATH if index($path, $prefix) == 0;
  }
  push @found, [$path, 0, $path] if $path =~ $filename;

  my ($base) = $path =~ m{([^/]+)\z};
  my ($ext) = $base =~ /\.([^.]+)\z/;
  my $style = $hashnames{$base} ? '#'
    : !defined $ext ? undef
    : $slash{$ext} ? '//'
    : $hash{$ext} ? '#'
    : undef;
  next unless defined $style;

  open my $fh, '<:raw', "$root/$raw_path" or next;
  my ($line_no, $in_block, $prev) = (0, 0, undef);
  while (my $raw = <$fh>) {
    $line_no += 1;
    my $line = decode('UTF-8', $raw);
    $line =~ s/\r?\n\z//;
    $line =~ s/^\x{FEFF}// if $line_no == 1;
    (my $trimmed = $line) =~ s/^\s+//;

    my $text;
    if ($in_block) {
      $text = $line;
      $in_block = 0 if index($line, $style eq '//' ? '*/' : '#>') >= 0;
    } elsif ($style eq '//' && index($trimmed, '/*') == 0) {
      $text = $trimmed;
      $in_block = 1 if index($trimmed, '*/', 2) < 0;
    } elsif ($style eq '#' && index($trimmed, '<#') == 0) {
      $text = $trimmed;
      $in_block = 1 if index($trimmed, '#>', 2) < 0;
    } else {
      my $at = index($line, $style);
      $text = substr($line, $at) if $at >= 0;
    }

    my $hit = $line =~ $anywhere || (defined $text && is_offence($text));
    # A marker broken across two comment lines: judge the seam, but only a hit
    # that neither half produces alone, so one offence is not reported twice.
    if (!$hit && defined $text && defined $prev && $prev =~ /(\S+)\s*\z/) {
      my $tail = $1;
      (my $body = $text) =~ s/$opener//;
      $hit = !is_offence($tail) && is_offence("$tail $body");
    }
    push @found, [$path, $line_no, $trimmed] if $hit;
    $prev = $text;
  }
  close $fh;
}

print "$_->[0]:$_->[1]\t$_->[2]\n" for @found;
