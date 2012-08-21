===========
vmod_access
===========

----------------------
Varnish Access Module
----------------------

:Author: Olivier Grange-Labat
:Date: 2012-08-21
:Version: 0.9
:Manual section: 3

SYNOPSIS
========

import access;

DESCRIPTION
===========

Implements cookie-based access control.

FUNCTIONS
=========

access
------

Prototype
        ::

                access(STRING SERVICE, STRING COOKIE_NAME, STRING SALT)
Return value
	BOOL
Description
	Returns true if a request with a valid, not expired service is sent,
        false otherwise.
Example
        ::

        if (req.url ~ "^/protected/")
        {
                if (access.check("myservice", "__acc", "salt used for checksum"))
                {       
                        // access granted
                }
                else
                {
                        // access denied
                }
        }

INSTALLATION
============

The source tree is based on autotools to configure the building, and
does also have the necessary bits in place to do functional unit tests
using the varnishtest tool.

Usage::

 ./configure VARNISHSRC=DIR [VMODDIR=DIR]

`VARNISHSRC` is the directory of the Varnish source tree for which to
compile your vmod. Both the `VARNISHSRC` and `VARNISHSRC/include`
will be added to the include search paths for your module.

Optionally you can also set the vmod install directory by adding
`VMODDIR=DIR` (defaults to the pkg-config discovered directory from your
Varnish installation).

Make targets:

* make - builds the vmod
* make install - installs your vmod in `VMODDIR`
* make check - runs the unit tests in ``src/tests/*.vtc``
