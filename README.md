# pam_clockwork
A PAM authentication module meant to wrap other PAM modules and only require 
their authentication every so often.

## Building
The requirements are fairly straight forward for this module; you need 
pam-devel, glibc-devel, gcc, and make.

To compile the code, simply run `make`.

## Installation
To install the module for use with PAM, copy if to `/usr/lib64/security/` 
and `/lib/security/`.

After the module is in the required locations, simply modify your PAM auth 
files in `/etc/pam.d/` as needed.

# Configuration
Add something along these lines to your `/etc/pam.d/` file:  

----
auth     required    pam_clockwork.so timeout=3600 debug -- pam_yubico.so id=[Your API Client ID] debug
----

Note that the `--` is required, and lets the module know where to stop 
attempting to parse options for it and where to expect both the module it 
should be loading, and the options for that module to reside.

In the above example, we are wrapping https://github.com/Yubico/yubico-pam[Yubikey authentication] \(for 2 factor) with 
a 1-hour cache. This is extremely useful if you want to require, say, `sudo` to 
have multi-factor, but only want to have to worry about it once a day.

# Options
alwaysok::
Always mark the authentication attempt as successful, even if the module called 
fails authentication, or doesn't exist. This can be extremely useful in making 
sure you don't lock yourself out of your system.

debug::
Enable debug output. This can tell you a lot about what is going on from 
pam_clockwork's perspective.

timeout::
How long, in seconds, should a successful authentication attempt be cached. This 
also specifies how long to ignore attempts at authentication if the maximum 
number of tries for the wrapped module was reached.


