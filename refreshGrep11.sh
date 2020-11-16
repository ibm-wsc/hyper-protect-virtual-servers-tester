#!/usr/bin/env bash

# This is the file where user variables are entered
source default_variables.env;

function clean_up()
{
	local	ca_name=${1:-"hpvs-ca"}"-key.pem";
	local	keys_dir=${GREP_DIR}/keys;
	local	grep11_json_file='grep11_env_04.0022.json';

	log_and_print "Performing cleanup precoedure.";

	if [[ -r ${ca_name} ]];
	then
		local	cmd="rm -v ${ca_name}";
		log_and_execute "${cmd}";
	fi;

	if [[ -d ${keys_dir} ]];
	then
		local	cmd="rm -rfv ${keys_dir}";
		log_and_execute "${cmd}";
	fi;

	[[ -r ${GREP_DIR}/${grep11_json_file} ]] && rm -vf ${GREP_DIR}/${grep11_json_file};

	stop_grep11_servers;

	printf "\n";
};

function prereq_check()
{
	local	keys_dir=${GREP_DIR}/keys;

	log_and_print "Performing prerequisite check procedure.";
	
	if [[ ! -r ${HOME}/.rnd ]];
	then
		local	cmd="openssl rand -out ${HOME}/.rnd -hex 256";
		log_and_execute "${cmd}";
	fi;

	if [[ ! -d ${keys_dir} ]];
	then
		local	cmd="mkdir -vp ${keys_dir}";
		log_and_execute "${cmd}";
	else
		log_and_print "Directory structure exists and is in tact.";
	fi;
	printf "\n";
};

function log_and_print()
{
	local	output=${1:-"No print parameter provided, when ${FUNCNAME} was called by $_"};
	local	KEEP_TXT_LOG=${2:-${KEEP_TXT_LOG}};
	[[ "${KEEP_TXT_LOG}" == "Y" ]] && echo -e "# "${output} >> "${COMMAND_LOG}";
	echo -e ${output};
};

function log_and_execute()
{
	if [[ $# -gt 0 ]];
	then
		local	cmd=${1};
		[[ "${KEEP_CMD_LOG}" == "Y" ]] && echo ${cmd} >> "${COMMAND_LOG}";
		eval "${cmd}";
	else
		printf "No command parameter provided, please provide a parameter of a command to execute.\n";
		exit 4;
	fi;
};

function create_RSA_key() 
{
	local	keys_dir=${GREP_DIR}/keys;
	local	ca_name=${1:-"hpvs-ca"}".pem";
	local	ca_key=${1:-"hpvs-ca"}"-key.pem";
	local	key_size=${2:-"2048"};

	if [[ ! -r ${ca_name} ]];
	then
		log_and_print "creating RSA key for $1 ...";
		local	cmd="openssl genrsa -out ${keys_dir}/${ca_key} ${key_size}";
		log_and_execute "${cmd}";
		log_and_print "creating RSA key for $1 complete";
	fi;
	printf "\n";
};

function create_ca() 
{
	local	keys_dir=${GREP_DIR}/keys;
#	local	ca_file=${1:-"hpvs-ca"}".pem";
	local	ca_file=${1:-"hpvs-ca"};
	local	pem_file=${1:-"hpvs-ca"}".pem";
	local	key_file=${1:-"hpvs-ca"}"-key.pem";
	local	ca_conf_file=${2:-"ca"}".cnf";
	local	extensions=${3:-"x509_extensions"};
	local	passphrase="test_passphrase";

	log_and_print "creating certificate authority (ca)...";
	create_RSA_key ${ca_file};

	# next we must check for and build the ca_conf file if missing!

	if [[ ! -f "${keys_dir}/${ca_conf_file}" ]];
	then
		cat > "${keys_dir}/${ca_conf_file}" <<EOF
#RANDFILE               = $ENV::HOME/.rnd

[ req ]
default_bits           = 2048
default_keyfile        = keyfile.pem
distinguished_name     = req_distinguished_name
attributes             = req_attributes
prompt                 = no
output_password        = mypass

[ req_distinguished_name ]
C                      = US
ST                     = Nevada
L                      = Las Vegas
O                      = IBM
OU                     = IBM Systems Lab Services
CN                     = SLS HPVS CA
emailAddress           = stuart.tener@ibm.com

[ req_attributes ]
challengePassword              = ${passphrase}

[ x509_extensions ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints       = critical,CA:TRUE

#[ certauth ]
#subjectKeyIdentifier = hash
#authorityKeyIdentifier = keyid:always,issuer:always
#keyUsage = digitalSignature, keyEncipherment, dataEncipherment, keyCertSign, cRLSign
#keyUsage = digitalSignature, keyEncipherment, dataEncipherment, keyCertSign, cRLSign
#basicConstraints = ${ENV::PATHLEN}
EOF
	fi;

	local	cmd="openssl req -new -x509 -key ${keys_dir}/${key_file} -out ${keys_dir}/${pem_file} -days 395 -config ${keys_dir}/${ca_conf_file} -extensions ${extensions}";
	log_and_execute "${cmd}";
	log_and_print "creation of certificate authority (ca) complete";
};

create_servers()
{
	local	keys_dir=${GREP_DIR}/keys;

	local	servers=('qosp54');
	local	ports=('9876');
	local	ssc_ip='9.82.21.99';
	local	server_csr_conf_file="serverCsr.cnf";
	local	serverCSR=${keys_dir}/${server_csr_conf_file};
	local	server_conf_file="server.cnf";
	local	SUBJECT_ALT_NAME=DNS:${ssc_ip}:${port},IP:${ssc_ip};
	local	COMMON_NAME=${ssc_ip}-${port};
	local	ca_name=${1:-"hpvs-ca"}".pem";
	local	ca_key=${1:-"hpvs-ca"}"-key.pem";

	if [[ ! -f "${keys_dir}/${server_csr_conf_file}" ]];
	then
		echo '
# OpenSSL configuration file.
 #

 # Establish working directory.

 dir   = .

 [ ca ]
 default_ca  = CA_default

 [ CA_default ]
 serial   = $dir/serial
 #database  = ${ENV::DIR}/index.txt
 #new_certs_dir  = $dir/newcerts
 #private_key       = $dir/ca.key
 #certificate       = $dir/ca.cer
 default_days  = 365
 default_md  = sha256
 preserve  = no
 email_in_dn  = no
 nameopt   = default_ca
 certopt   = default_ca
 default_crl_days = 45
 policy   = policy_match

 [ policy_match ]
 countryName  = match
 stateOrProvinceName = optional
 organizationName = match
 organizationalUnitName = optional
 commonName  = supplied
 emailAddress  = optional

 [ req ]
 default_md  = sha256
 distinguished_name = req_distinguished_name
 prompt             = no

 [ req_distinguished_name ]
 #countryName = Country
 #countryName_default = US
 #countryName_min = 2
 #countryName_max = 2
 #localityName = Locality
 #localityName_default = Los Angeles
 #organizationName = Organization
 #organizationName_default = IBM
 #commonName = Common Name
 #commonName_max = 64

 C                      = US
 ST                     = Nevada
 L                      = Las Vegas
 O                      = IBM
 OU                     = IBM Systems Lab Services
 CN = ${ENV::COMMON_NAME}
' > "${keys_dir}/${server_csr_conf_file}";
	fi;

	if [[ ! -f "${keys_dir}/${server_conf_file}" ]];
	then
echo '
 # OpenSSL configuration file.
 #

 # Establish working directory.

 dir   = .

 [ ca ]
 default_ca  = CA_default

 [ CA_default ]
 serial   = $dir/serial
 #database  = ${ENV::DIR}/index.txt
 #new_certs_dir  = $dir/newcerts
 #private_key       = $dir/ca.key
 #certificate       = $dir/ca.cer
 default_days  = 365
 default_md  = sha256
 preserve  = no
 email_in_dn  = no
 nameopt   = default_ca
 certopt   = default_ca
 default_crl_days = 45
 policy   = policy_match

 [ policy_match ]
 countryName  = match
 stateOrProvinceName = optional
 organizationName = match
 organizationalUnitName = optional
 commonName  = supplied
 emailAddress  = optional

 [ req ]
 default_md  = sha256
 distinguished_name = req_distinguished_name
 prompt             = no

 [ req_distinguished_name ]
 #countryName = Country
 #countryName_default = US
 #countryName_min = 2
 #countryName_max = 2
 #localityName = Locality
 #localityName_default = Los Angeles
 #organizationName = Organization
 #organizationName_default = IBM
 #commonName = Common Name
 #commonName_max = 64


 C                      = US
 ST                     = Nevada
 L                      = Las Vegas
 O                      = IBM
 OU                     = IBM Systems Lab Services
 CN = ${ENV::COMMON_NAME}
 emailAddress           = stuart.tener@ibm.com

 [ server ]
 basicConstraints = CA:FALSE
 keyUsage = digitalSignature, keyEncipherment, dataEncipherment
 extendedKeyUsage = serverAuth
 nsCertType = server
 crlDistributionPoints = @crl
 subjectAltName = ${ENV::SUBJECT_ALT_NAME}

 [ crl ]
 URI=http://localhost/ca.crl
' > "${keys_dir}/${server_conf_file}"
	fi;

	log_and_print "creating servers...";
	for last_octet in ${servers[*]};
	do
		for port in ${ports[*]};
		do
			create_RSA_key grep11-${last_octet}-${port};
        		COMMON_NAME=${ssc_ip} openssl req -new -key ${keys_dir}/grep11-${last_octet}-${port}-key.pem -out ${keys_dir}/grep11-${last_octet}-${port}.csr -config ${keys_dir}/${server_csr_conf_file};
			if [[ $? -eq 0 ]];
			then
       				SUBJECT_ALT_NAME=DNS:${ssc_ip}:${port},IP:${ssc_ip} COMMON_NAME=${ssc_ip}-${port} openssl x509 -sha256 -req -in ${keys_dir}/grep11-${last_octet}-${port}.csr -CA ${keys_dir}/${ca_name} -CAkey ${keys_dir}/${ca_key} -set_serial 8086 -extfile ${keys_dir}/${server_conf_file} -extensions server -days 390 -outform PEM -out ${keys_dir}/grep11-${last_octet}-${port}.pem;
			else
				printf "The certificate did not build properly above.\n";
				return 1;
			fi;
		done;
	done;
	log_and_print "creating servers complete";
}

create_client_certificate()
{
	local	keys_dir=${GREP_DIR}/keys;
	local	client_conf_file="client.cnf";

	if [[ ! -f "${keys_dir}/${server_conf_file}" ]];
	then
echo '
RANDFILE               = $ENV::HOME/.rnd

[ req ]
default_bits           = 2048
default_keyfile        = keyfile.pem
distinguished_name     = req_distinguished_name
attributes             = req_attributes
prompt                 = no
output_password        = mypass


[ req_distinguished_name ]
C                      = US
ST                     = Nevada
L                      = Las Vegas
O                      = IBM
OU                     = IBM Systems Lab Services
CN                     = Grep11 Client App
emailAddress           = stuart.tener@ibm.com

[ req_attributes ]
challengePassword              = A challenge password

[ x509_extensions ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints       = critical,CA:TRUE

#[ certauth ]
#subjectKeyIdentifier = hash
#authorityKeyIdentifier = keyid:always,issuer:always
#keyUsage = digitalSignature, keyEncipherment, dataEncipherment, keyCertSign, cRLSign
#keyUsage = digitalSignature, keyEncipherment, dataEncipherment, keyCertSign, cRLSign
#basicConstraints = ${ENV::PATHLEN}

' > "${keys_dir}/${client_conf_file}";
	fi;


	log_and_print "creating client certificate ...";
	create_RSA_key client;
	local	cmd="openssl req -new -key ${keys_dir}/client-key.pem -out ${keys_dir}/client.csr -config ${keys_dir}/client.cnf";
	log_and_execute "${cmd}";
	openssl x509 -req -days 100 -in ${keys_dir}/client.csr -CA ${keys_dir}/hpvs-ca.pem -CAcreateserial -CAkey ${keys_dir}/hpvs-ca-key.pem -out ${keys_dir}/client.pem;
	log_and_print "creating client certificate complete";
};

stop_grep11_servers() 
{
	local	host=${1:-"qosp54"};
	local	card=${2:-"04"};
	local	domain=${3:-"0022"};
	local	port=${4:-"9876"};

	if hpvs vs show --name grep11-${card}-${domain}-${port} --host ${host} 2>&1 1>/dev/null;
	then
		# return code was 0
		log_and_print "Deleting virtual server...";
		local	cmd="hpvs vs delete --name grep11-${card}-${domain}-${port} --host ${host}";
		log_and_execute "${cmd}";
#	else
		# return code was non-zero
	fi;
}

start_grep11_server() 
{
	local	host=${1:-"qosp54"};
	local	card=${2:-"04"};
	local	domain=${3:-"0022"};
	local	port=${4:-"9876"};
	local	tag=${5:-"1.2.2"};
	local	keys_dir=${GREP_DIR};
	local	grep11_json_file='grep11_env_04.0022.json';

	if [[ ! -f "${GREP_DIR}/${grep11_json_file}" ]];
	then
		cat > "${GREP_DIR}/${grep11_json_file}" <<EOF
{
    "EP11SERVER_EP11CRYPTO_DOMAIN":"${card}.${domain}",
    "EP11SERVER_EP11CRYPTO_CONNECTION_TLS_CERTFILEBYTES":"@${GREP_DIR}/keys/grep11-${host}-${port}.pem",
    "EP11SERVER_EP11CRYPTO_CONNECTION_TLS_KEYFILEBYTES":"@${GREP_DIR}/keys/grep11-${host}-${port}-key.pem",
    "EP11SERVER_EP11CRYPTO_CONNECTION_TLS_CACERTBYTES":"@${GREP_DIR}/keys/hpvs-ca.pem",
    "EP11SERVER_EP11CRYPTO_CONNECTION_TLS_ENABLED":true,
    "EP11SERVER_EP11CRYPTO_CONNECTION_TLS_MUTUAL":true,
    "EP11SERVER_EP11CRYPTO_ENABLED":true,
    "TLS_GRPC_CERTS_DOMAIN_CRT":"\\n",
    "TLS_GRPC_CERTS_DOMAIN_KEY":"\\n",
    "TLS_GRPC_CERTS_ROOTCA_CRT":"\\n",
    "_comment":"hpvs vs create --name grep11-${card}-${domain}-${port} --repo hpcsKpGrep11_runq --tag ${tag} --crypto_matrix=${card}.${domain} --cpu 2 --ram 2048 --envjsonpath ${HOME}/hpvs/config/grep11/grep11_env_04.0022.json --ports '{containerport = 9876, protocol = tcp, hostport = 9876}' --host ${host}"
}
EOF
	fi;

	local	cmd="hpvs vs create --name grep11-${card}-${domain}-${port} --repo hpcsKpGrep11_runq --tag ${tag} --crypto_matrix=${card}.${domain} --cpu 2 --ram 2048 --envjsonpath ${GREP_DIR}/grep11_env_${card}.${domain}.json --ports \"{containerport = 9876, protocol = tcp, hostport = ${port}}\" --host ${host}";
	log_and_execute "${cmd}";
};

start_grep11_servers()  
{
	local	host=${1:-"qosp54"};
	local	card=${2:-"04"};
	local	domain=${3:-"0022"};
	local	port=${4:-"9876"};
	
	if ! hpvs image list | grep -i 'ibmzcontainers/hpcs-grep11-prod' >/dev/null;
	then
		local	cmd="hpvs image load --file ~/hpvs/config/grep11/images/hpcsKpGrep11_runq.tar.gz";
		log_and_execute "${cmd}";
		# did it work? make a loop that checks 5 times then quits if no love
	fi;
	start_grep11_server ${host} ${card} ${domain} ${port};
};

#	we need to pack the required golang stuff here, uuencode it and then uudecode it
#	in this function so the customer has it absent internet access for more than this
#	text file.
go_lang_test()
{
	local	keys_dir=${GREP_DIR}/keys;
	local	go_dir=~/go/src/github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang;
	local	files=('client.pem' 'client-key.pem' 'hpvs-ca.pem');

	local	ports=('9876');
	local	ssc_ip='9.82.21.99';

	#	need to make sure we add a test and error if nc is not installed or
	#	that.
	for port in ${ports[*]};
	do
		while ! nc -vz ${ssc_ip} ${port};
		do
			sleep 10;
		done;
	done;

	if [[ -d $HOME ]];
	then
		pushd ${go_dir}/certs 2>&1 >/dev/null;
		for file in ${files[*]};
		do
			local	cmd="cp -pr ${keys_dir}/${file} ${go_dir}/certs";
			log_and_execute "${cmd}";
		done;
		popd 2>&1 >/dev/null;

		pushd ${go_dir}/examples 2>&1 >/dev/null;
		local	cmd="go test -v";
		log_and_execute "${cmd}";
		popd 2>&1 >/dev/null;
	fi;
};

# main 
log_and_print "Cleaning up $(date)" "Y";
clean_up;
log_and_print "Starting at $(date)" "Y";
prereq_check;
create_ca;
create_servers;
# client certificates would normally be placed elsewhere not here.
create_client_certificate;
start_grep11_servers;
go_lang_test;
log_and_print "Complete at $(date)" "Y";
