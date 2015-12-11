# QA_Flag
Habib's QA Flagging Tool

since 4.xx(prolly 3.56+) sony protected the qa thing with ecdsa and we cant access it through UM in the gameos(preventing token from being written)

so i just started once to look around qa.i was able to do it on 3.55 but not on 4.xx.
now what i did to make that working was that i accessed HV scm through dm using VUART(packet id=0x900C) and wrote the token.this can be done from linux easily but we want from gameos right?
sooooo I SUCCEEDED!!!

fw independant for 4.21+
for any reason if this doesnt work with the upcoming releases, porting is required
tested on 3.55-4.76
