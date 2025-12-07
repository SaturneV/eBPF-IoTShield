# DDOS-DEFLATE

Ddos deflate is a ddos mitigator based on the number of connections that are open.

## Set up nginx

To compare this implementation with our the iot needs to run nginx, to simulate a small HTTP server.

```bash
# Install nginx
sudo apt install nginx -y
# Start nginx
sudo systemctl start nginx
# Optionally to make it start on boot 
sudo systemctl enable nginx

# Check that it is actually running
sudo systemctl status nginx
```

Now that nginx is running we can check if it is accessible from our attacker: 

```bash 
curl http://<VM IP>/
```

You should get receive the default nginx page.

## Set up ddos-deflate

Now let's set up the ddos mitigator ddos-deflate, to do that you can simply run the install.sh script in the ddos-deflate directory. 
It should fetch the ddos-source code online, compile and start it. 
Once started try the following command you should see the ddos status in oour case it is running. 

```bash
ddos -t
```

Here are some of the basics :
```bash 
#Start the service
sudo ddos -d 

#Stop the service
sudo ddos -s

#Get the status 
sudo ddos -t

#Get the ban entries
sudo ddos -b

#Get the whitelisted entries
sudo ddos -i
```

There is also a way to white list some of the ips (which is usefull to compare with our whitelist implementation)

```bash 
# Edit the following file 
vim /etc/ddos/ignore.ip.list
```

```conf
# Here is an example of white list 
10.0.0.0/24
192.168.50.1
```

After that, restart the service :

```bash 
systemctl restart ddos
```

Finally you can uninstall ddos-deflate by running the ./uninstall.sh script.

## Actual test 

Now that everything is set up when can run the actual test.


### Tool used 

The tool used here will create many connections, what ddos-deflate catches.
This tool is ApacheBench (ab) and can be installed as follow on the host (attacker) side :

```bash
sudo apt install apache2-utils -y

#Verify the instalation
ab -v
```

```bash
#Or via homebrew on MACOS
brew install httpd
```

### Test the mitigation

- Start the mitiagation, either ddos-deflate using the -d option or our eBPF filter using the cli.
- From the attacker side open many connection using ab and monitor the results:

```bash 
ab -n 5000 -c 200 -s 3 http://YOUR_VM_IP/

# -n 5000 → number of requests
# -c 200 → parallel connections
# -s 3 → Timeout in second after which the connection is considered lost (otherwise run for a very long time)
```
