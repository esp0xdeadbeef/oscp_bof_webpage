# oscp_bof_webpage

This is an half automated script that will let you set your bof parameters over http and exploit a binary by "only" using your web browser. Do the steps you usually do in a buffer overflow, but a bit automated and through a web environment. 

Use this script in a save envirnoment because there are functions used like eval, exec and os.popen(). I chose the web env to be able to debug from within windows because there is no easy API (that I know of) to remote debug an application. If you know a solution or multiple that are open source, contact me on discord (esp0xdeadbeef#1337).

## building the app

To run it:
```bash
git clone https://github.com/esp0xdeadbeef/oscp_bof_webpage
cd oscp_bof_webpage
chmod +x pwn_from_web.py
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
```

## running the app

Get your reverse shell adapter name, by using `ip a` or `ifconfig` on the attacker machine.

```bash
#(get your <b>*adapter*</b> name you want to bind it to) with `ip a` or `ifconfig`
rev_shell_adapter_name='tun0'
rev_shell_port=443
# echo the ip of your target in the 'ip_target' file or just simply use the web interface.
echo '127.0.0.1' > ip_target
# edit the pwn_from_web all you want and run it: 
./pwn_from_web.py $rev_shell_adapter_name $rev_shell_port
```

Go to `localhost:5000` or whatever you set as your interface and enjoy.

## (optional) remove your cache
If the app is giving 500 errors, remove your cache <b>This will reset your variables</b>. 

By default:

```bash
rm -r /tmp/cache/
```

# Example config

![example config](example.png)