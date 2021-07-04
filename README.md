# oscp_bof_webpage

I wrote this script in 16 hours so it will be buggy, but if you delete the cache you'll be fine. 


Do your normal steps what you do in a buffer overflow but a bit automated and though a web env. 

I chose the web env to be able to debug from within windows because there is no easy api (that i know of) to remote debug an application. 



To run it:
```bash
git clone https://github.com/esp0xdeadbeef/oscp_bof_webpage
cd oscp_bof_webpage
chmod +x pwn_from_web.py
#(get your <b>*adapter*</b> name you want to bind it to) with `ip a` or `ifconfig`
adapter_name='tun0'
rev_shell_port=443
./pwn_from_web.py $adapter_name $rev_shell_port
```

Go to localhost:5000 and enjoy.


If you did something invalid (i did do that many times, i wont blame you), remove your cache <b>this will reset your variables</b>. 
