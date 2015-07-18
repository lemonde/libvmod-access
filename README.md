# libvmod-access

 [![Build Status](https://travis-ci.org/lemonde/libvmod-access.svg?branch=master)](https://travis-ci.org/lemonde/libvmod-access)

## Description

Varnish module implementing cookie-based access control.

## Warning

This module is EXPERIMENTAL - do not use in production! It is only for education purpose.

## Setup

1. install required packages for building the module (instructions for Fedora 22)

        $ sudo dnf install automake libtool make varnish varnish-libs-devel python-docutils

2. clone repo

        $ git clone git@github.com:lemonde/libvmod-access.git
        $ cd libvmod-access/

3. switch to master branch (for Varnish 4.0, branch 3.0 is for Varnish 3.0) :

        $ git checkout master

4. build module

        $ ./autogen.sh
        $ ./configure
        $ make

5. run unit tests

        $ make check

6. have fun!

## VCL function

### access.check()

Prototype

        access.check(STRING SERVICE, STRING COOKIE_NAME, STRING SALT)

Return value

		BOOL

Description

        Returns true if a request with a valid cookie is sent, false otherwise.

Example

        if (req.url ~ "^/protected/")
        {
                if (access.check("protected_content", "__access", "salt used for checksum"))
                {       
                        // access granted
                }
                else
                {
                        // access denied
                }
        }

## License

MIT