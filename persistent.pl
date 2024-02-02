package Embed::Persistent;

use strict;

our %AppCache;

sub valid_package_name {
    my ($string) = @_;
    $string =~ s/([^A-Za-z0-9\/])/sprintf("_%2x",unpack("C",$1))/eg;

    # Second pass only for words starting with a digit
    $string =~ s|/(\d)|sprintf("/_%2x",unpack("C",$1))|eg;

    # Dress it up as a real package name
    $string =~ s|/|::|g;
    return "Embed" . $string;
}

sub run_psgi {
    my ( $filename, $env ) = @_;

    my $package = valid_package_name($filename);
    my $mtime   = -M $filename;

    my $app;

    if ( exists $AppCache{$package} && $AppCache{$package}{mtime} == $mtime ) {
        $app = $AppCache{$package}{app};
    } else {
        local *FH;
        open FH, $filename or die "open '$filename' $!";
        local ($/) = undef;
        my $code = <FH>;
        close FH;

        # Wrap the code into a subroutine inside our unique package
        {
            # Hide our variables within this block
            my ( $filename, $env, $package, $mtime );

            $app = eval $code;
        }

        die $@ if $@;

        $AppCache{$package} = {
            mtime => $mtime,
            app   => $app,
        };
    }

    my $res = eval { $app->($env) };
    die $@ if $@;
    return $res;
}

1;

 __END__
