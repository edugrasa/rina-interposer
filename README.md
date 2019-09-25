# RINA Faux Sockets API

Prototype adaptor from BSD Sockets/POSIX API calls to RINA

To build:

    make

On server, run:

    RINA_DIF=normal.DIF RINA_LOCAL_APPL=nc-server LD_PRELOAD=$(pwd)/librina-sockets.so nc -l 1.2.3.4 1234

On client, run:

    RINA_DIF=normal.DIF RINA_LOCAL_APPL=nc-client RINA_REMOTE_APPL=nc-server LD_PRELOAD=$(pwd)/librina-sockets.so nc 1.2.3.4 1234

For more detail, set the `RINA_VERBOSE` (to anything).
