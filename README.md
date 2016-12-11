# Certificate Transparency Add-Chain webservice

This tool is a small webapp allowing you to submit certificate chains to 
[Certificate Transparency][ctweb] logs and getting the generated SCTs.

This tool attempts to submit your certificate chains to all the logs 
that may accept them. This is done to increase the difficulty for an 
attacker to hide this certificate to legitimate users and to help reach 
compliance with log diversity requirements that some browsers may have. 
Basically, the more SCTs you have, the better, security-wise.

All SCTs are verified cryptographically and stored by the webservice for 
caching (done) and later control of the actual insertion of the 
certificate chain (todo).

You may serve these SCTs to your users using a TLS extension. Such 
extension is implemented by [nginx-ct][nginx-ct] or [mod_ssl_ct][mod_ssl_ct]. 

There is a [demo site][demo-site], if you want to have a look at this tool.

[ctweb]: https://www.certificate-transparency.org
[nginx-ct]: https://github.com/grahamedgecombe/nginx-ct
[mod_ssl_ct]: https://httpd.apache.org/docs/trunk/mod/mod_ssl_ct.html
[demo-site]: https://www.x-cli.eu/submit

## Usage

### User perspective

Just browse the URL, submit your certificate chain with the form and
click on the buttons to download the SCTs of the queried logs! 
You are done!

### Hosting your own version of the webservice

To run this webservice locally, you will need to download an third-party
file first.

This file is called [log_list.json][log_list]. 
It contains a list of logs, their URL and their public keys.

Once you have this file, running the webservice is a piece of cake:
```
./add_chain_webservice.py -l log_list.json -db /tmp/cert.db
```

You will need at least Python3.5 to run it, although running it on 
earlier versions might be possible with minor tweaks.

Some command-line options allows you to tweak the binding address and 
port, and the throttling mechanism.

```
usage: add_chain_webservice.py [-h] -l LOG_LIST_FILE -db DB_FILE [-H HOST]
                               [-p PORT] [-t THROTTLE] [-b BUCKET]

optional arguments:
  -h, --help            show this help message and exit
  -l LOG_LIST_FILE, --log-list LOG_LIST_FILE
                        log_list.json file from the certificate-
                        transparency.org
  -db DB_FILE, --database DB_FILE
                        Database file in which the SCTs are stored
  -H HOST, --host HOST  IP address to which the webservice will bind
  -p PORT, --port PORT  Port to which the webservice will bind
  -t THROTTLE, --throttle THROTTLE
                        Number of seconds after which the throttling algorithm
                        allows a new query in
  -b BUCKET, --bucket BUCKET
                        Maximum number of queries allowed by the throttling
                        algorithm before depletion
```

[log_list]: https://www.certificate-transparency.org/known-logs/log_list.json

### Using the webservice from command line!

Querying this webapp/webservice from command line is possible. 
You will need a tool that can submit files. For instance, you could do this
with cURL.

```
$ curl -F cert_file=@my_cert.crt https://127.0.0.1:5000/submit
```

You will receive after a while (tens of seconds) a JSON object that 
should be self explanatory.

You may exploit it with [jq][jq] for instance.

[jq]: https://stedolan.github.io/jq/

## Requirements

This tool uses the microframework `flask` for the webapp and the 
`cryptography` library for cryptographic verifications.

You can install these requirements by running the following command:
```
pip install -r requirements.txt
