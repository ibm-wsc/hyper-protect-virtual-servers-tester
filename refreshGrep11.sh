#!/usr/bin/env bash


create_RSA_key() 
{
  echo "creating RSA key for $1 ..." 
  openssl genrsa -out ${1}-key.pem 2048
  echo "creating RSA key for $1 complete"
}
 

create_ca() 
{
  echo "creating ca ..."
  create_RSA_key hpvs-ca

  openssl req -new -x509 -key hpvs-ca-key.pem -out hpvs-ca.pem -days 395 -config ca.cnf -extensions x509_extensions
  echo "creating ca complete"
}

create_servers()
{
  echo "creating servers..."
	local	servers=('qosp54');
	local	ports=('9876');
	local	ssc_ip='9.82.21.99';

  for last_octet in ${servers[*]};
    do for port in ${ports[*]};
      do create_RSA_key grep11-${last_octet}-${port};
        COMMON_NAME=${ssc_ip} openssl req -new -key grep11-${last_octet}-${port}-key.pem -out grep11-${last_octet}-${port}.csr -config serverCsr.cnf
        SUBJECT_ALT_NAME=DNS:${ssc_ip}:${port},IP:${ssc_ip} COMMON_NAME=${ssc_ip}-${port} openssl x509 -sha256 -req -in grep11-${last_octet}-${port}.csr -CA hpvs-ca.pem -CAkey hpvs-ca-key.pem -set_serial 8086 -extfile server.cnf -extensions server -days 390 -outform PEM -out grep11-${last_octet}-${port}.pem
      done ;
   done;

  echo "creating servers complete"
}

create_client_certificate()
{
  echo "creating client certificate ..."
  create_RSA_key client
  openssl req -new -key client-key.pem -out client.csr -config client.cnf
  openssl x509 -req -days 100 -in client.csr -CA hpvs-ca.pem -CAcreateserial -CAkey hpvs-ca-key.pem -out client.pem
  echo "creating client certificate complete"
}

stop_grep11_servers() 
{
	local	host=${1:-"qosp54"};
	local	card=${2:-"04"};
	local	domain=${3:-"0022"};
	local	port=${4:-"9876"};

	hpvs vs show --name grep11-${card}-${domain}-${port} --host ${host} 2>&1 1>/dev/null;
	if [[ $? -eq 0 ]];
	then
		hpvs vs delete --name grep11-${card}-${domain}-${port} --host ${host};
	fi;
}

start_grep11_server() 
{
	local	host=${1:-"qosp54"};
	local	card=${2:-"04"};
	local	domain=${3:-"0022"};
	local	port=${4:-"9876"};
	local	tag=${5:-"1.2.1.1"};
  
	hpvs vs create --name grep11-${card}-${domain}-${port} --repo hpcsKpGrep11_runq --tag ${tag} --crypto_matrix=${card}.${domain} --cpu 2 --ram 2048 --envjsonpath ${HOME}/hpvs/config/grep11/grep11_env_${card}.${domain}.json --ports "{containerport = 9876, protocol = tcp, hostport = ${port}}" --host ${host}

}

start_grep11_servers()  
{
	local	host=${1:-"qosp54"};
	local	card=${2:-"04"};
	local	domain=${3:-"0022"};
	local	port=${4:-"9876"};

	if [[ $(hpvs image list | grep -ic hpcs-grep11-prod) -eq 0 ]];
	then
		hpvs image load --file ~/hpvs/config/grep11/images/hpcsKpGrep11_runq.tar.gz;
	fi;
	start_grep11_server ${host} ${card} ${domain} ${port};
}

# main 

stop_grep11_servers
create_ca
create_servers
# client certificates would normally be placed elsewhere not here.
create_client_certificate
start_grep11_servers

exit
