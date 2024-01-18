#!/bin/sh

aclocal \
&& automake --gnu --add-missing \
&& autoconf

libtoolize -c -f -i

# paranoia: sometimes autoconf doesn't get things right the first time
rm -rf autom4te.cache
autoreconf --verbose --install --symlink --force -I ./m4
#autoreconf --verbose --install --symlink --force
#autoreconf --verbose --install --symlink --force
