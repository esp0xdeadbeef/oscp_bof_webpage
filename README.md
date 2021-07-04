# oscp_bof_webpage

Don't blame it on me if you get hacked, because there is a lot of unsafe variables in the web interface (like `exec()` and `os.popen()`). You can edit the web interface at the bottom of the script. It is default set to `0.0.0.0` and port `5000`.

I wrote this script in 16 hours. It will be buggy.


Do your normal steps in a buffer overflow, but a bit automated and though a web env. 

I chose the web env to be able to debug from within windows because there is no easy API (that I know of) to remote debug an application. If you know a solution or multiple that are open source, please contact me on discord (esp0xdeadbeef#7239).



To run it:
```bash
git clone https://github.com/esp0xdeadbeef/oscp_bof_webpage
cd oscp_bof_webpage
chmod +x pwn_from_web.py
#(get your <b>*adapter*</b> name you want to bind it to) with `ip a` or `ifconfig`
rev_shell_adapter_name='tun0'
rev_shell_port=443
# edit the pwn_from_web all you want and run it: 
./pwn_from_web.py $rev_shell_adapter_name $rev_shell_port
```

Go to `localhost:5000` or whatever you set as your interface and enjoy.


If you did something invalid (i did do that many times, I won't blame you), remove your cache <b>This will reset your variables</b>. 
