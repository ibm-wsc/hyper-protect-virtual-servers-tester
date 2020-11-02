#!/usr/bin/env bash

# Save PROJECT_DIR to use throughout script as directory where project exists
#export PROJECT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )";
export PROJECT_DIR=~;

# This is the file where user variables are entered
source user_variables.env;

export gitrepo_ssh="git@github.com:person/repo.git";
# Let's name the ssh-key in get after the hostname with a timestamp:
export git_ssl_keyid="";

# Make log variables global
export KEEP_TXT_LOG='Y';
export KEEP_CMD_LOG='Y';
export COMMAND_LOG='HPVS-command-log';

function prereq_check()
{
	# Check if curl exists
	if ! command -v curl &> /dev/null;
	then
		printErr "Please install curl";
		exit 1;
	fi;

	# Check if jq exists
	if ! command -v jq &> /dev/null;
	then
		printErr "Please install jq";
		exit 1;
	fi;

	## If KEEP_LOG is set, make sure a file for logging is set in COMMAND_LOG
	if [[ -n "${KEEP_CMD_LOG}" || -n "${KEEP_TXT_LOG}" ]];
	then
		SECONDS=0;
		while [[ -z "${COMMAND_LOG}" ]];
		do
			if [[ "${SECONDS}" -ge 120 ]];
			then
				printErr "You're taking too long to make up your mind, exiting...";
				exit 1;
			fi ;
			read -t 120 -p "Please enter the name for your logfile : " COMMAND_LOG;
		done;
		# If not an absolute path make the path absolute
		if [[ "${COMMAND_LOG}" != /* ]];
		then
			COMMAND_LOG="${PROJECT_DIR}/${COMMAND_LOG}";
		else
			local	cmd="mkdir -p ${COMMAND_LOG%/*}";
			log_and_execute "${cmd}";
		fi;
		printf "Command log: %s\n" "${COMMAND_LOG}";
		local	cmd="touch ${COMMAND_LOG}";
		log_and_execute "${cmd}";
	else
		printf "No logging will be taking place KEEP_LOG not set to 'Y'\n";
	fi;
}

function printErr()
{
	echo
	cat <<< "$@" 1>&2;
	echo
}

function log_and_print()
{
	local	output=${1:-"No print parameter provided, when ${FUNCNAME} was called by $_"};
	[[ "${KEEP_TXT_LOG}" == "Y" ]] && echo -e "# "${output} >> "${COMMAND_LOG}";
	echo -e ${output};
};

function log_and_execute()
{
	if [[ $# -eq 1 ]];
	then
		local	cmd=${1};
		[[ "${KEEP_CMD_LOG}" == "Y" ]] && echo ${cmd} >> "${COMMAND_LOG}";
		eval "${cmd}";
	fi;
};

function update_image_number()
{
	if [ -z "${IMAGE_NUMBER}" ];
	then
		printErr "IMAGE_NUMBER must be set...";
		exit 1;
	fi;
	export IMAGE_NUMBER="$(( IMAGE_NUMBER + 1 ))";
	log_and_print "Incremented IMAGE_NUMBER to: ${IMAGE_NUMBER}\n";
	echo "${IMAGE_NUMBER}" > "${PROJECT_DIR}/IMAGE_NUMBER.txt";
}

function setup_environment()
{
	log_and_print "setup_environment: Setting up the secure build environment...";

	if [[ ! -d "${SB_DIR}" ]];
	then
		local	cmd="mkdir -p ${SB_DIR}";
		log_and_execute "${cmd}";
		local	cmd="cd ${SB_DIR}";
		log_and_execute "${cmd}";
	fi;
	if [[ ! -d "${SB_DIR}/github_keys" ]];
	then
		local	cmd="mkdir -p ${SB_DIR}/github_keys";
		log_and_execute "${cmd}";
	fi;
	export GITHUB_SSH_KEY="${SB_DIR}/github_keys/github_rsa_hpvs";

	local myemail="$USERNAME@$HOSTNAME";

	# Add hpvs registry with username and password (token provided) if it doesn't exist already
	if ! hpvs registry show --name "${REGISTRY_NAME}" &> /dev/null || [[ "$(hpvs registry list | wc -l)" -eq 4 ]];
	then
		log_and_print "${REGISTRY_NAME} will be added to the script";
		local	cmd="echo ${DOCKER_API_TOKEN} | docker login -u ${DOCKER_USERNAME} --password-stdin && docker logout";
		log_and_execute "${cmd}";
		local	cmd="
		echo \"${DOCKER_API_TOKEN}\" | hpvs registry add \
                --name \"${REGISTRY_NAME}\" --dct https://notary.docker.io \
                --url docker.io --user \"${DOCKER_USERNAME}\"";
		log_and_execute "${cmd}";
		local	cmd="hpvs registry list";
		log_and_execute "${cmd}";
	fi;
#	Generating SSH key:
	[[ ! -f "${GITHUB_SSH_KEY}" ]] && ssh-keygen -f "${GITHUB_SSH_KEY}" -t rsa -b 4096 -C "${myemail}" -N '';
	local sslpub="$(cat ${GITHUB_SSH_KEY}.pub | tail -1)";
#	git API path for posting a new ssh-key:
	local git_api_addkey="https://api.github.com/user/keys";
#	lets name the ssh-key id with hpvs_key and then the hostname with a timestamp:
	local git_ssl_keyname="hpvs_key_$(hostname)_$(date +%d-%m-%Y)";

#	Finally lets post this ssh key:
	local	cmd='ssh-keyscan -H github.com >> '"${HOME}/.ssh/known_hosts";
	log_and_execute "${cmd}";

	git_ssl_keyid="$(curl -s -H "Authorization: token ${GIT_API_TOKEN}" -H "Accept: application/vnd.github.v3+json" -X POST -d "{\"title\":\"${git_ssl_keyname}\",\"key\":\"${sslpub}\"}" "${git_api_addkey}" | jq -r '.id')"
	local	cmd="ssh -T git@github.com -i ${GITHUB_SSH_KEY}"' &> /dev/null';
	log_and_execute "${cmd}";

	# 1 is for regular no access via command line (i.e. success) ... 255 is for login error
	if [ "$?" -eq 1 ];
	then
		echo 'end setup_environment()';
	else
		printErr "Adding Git Hub key failed";
		exit 1;
	fi;
};

function create_certificate_and_key()
{
	log_and_print "Creating certificates and keys for secure image build...\n";
#	Follows hereupon the tag for the secure docker 
	local	base_image_tag=$(hpvs image list | awk '($0 ~ /secure-docker-build/) {print $4;}');
	if [[ -z "${base_image_tag}" ]];
	then
		echo -e "\nPlease note (as shown below) that the secure docker build image is not loaded";
		echo -e "\nhpvs load image --file=./securedockerbuild.tar.gz from the proper location";

		local	cmd="hpvs image list";
		log_and_execute "${cmd}";
	fi;
	local	cmd="openssl rand -out ${HOME}/.rnd -hex 256";
	log_and_execute "${cmd}";
	local	cmd="mkdir -p ${SB_DIR}/sbs_keys";
	log_and_execute "${cmd}";
	local	cmd="
	openssl req -newkey rsa:2048 \
        -new -nodes -x509 \
        -days 3650 \
        -out \"${SB_DIR}/sbs_keys/sbs.cert\" \
        -keyout \"${SB_DIR}/sbs_keys/sbs.key\" \
        -subj \"/C=US/O=IBM/CN=hpvs.example.com\"";
	log_and_execute "${cmd}";

	echo $(cat "${SB_DIR}/sbs_keys/sbs.cert" | base64) | tr -d ' ' > "${SB_DIR}/sbs_keys/sbs_base64.cert";
	export cert=$(cat "${SB_DIR}/sbs_keys/sbs_base64.cert");

	log_and_print "Creating quotagroup sb_user${HPVS_NUMBER} for Hyper Protect Secure Build Server...";
	local	cmd="hpvs quotagroup create --name sb_user${HPVS_NUMBER} --size=40GB";
	log_and_execute "${cmd}";

	if [[ $(hpvs image list | grep -ic 'SecureDockerBuild') -lt 1 ]];
	then
		log_and_print "Creating Hyper Protect Secure Build Server: sbserver_${HPVS_NUMBER}...";
		local cmd="
		hpvs vs create --name sbserver_${HPVS_NUMBER} --repo SecureDockerBuild \
		--tag ${base_image_tag} --cpu 2 --ram 2048 \
		--quotagroup \"{quotagroup = sb_user${HPVS_NUMBER}, mountid = new, mount = /newroot, filesystem = ext4, size = 10GB}\" \
		--quotagroup \"{quotagroup = sb_user${HPVS_NUMBER}, mountid = data, mount = /data, filesystem = ext4, size = 2GB}\" \
		--quotagroup \"{quotagroup = sb_user${HPVS_NUMBER}, mountid = docker, mount = /docker, filesystem = ext4, size = 16GB}\" \
		--env={EX_VOLUMES=\"/docker,/data\",ROOTFS_LOCK=y,CLIENT_CRT=$cert} \
		--ports \"{containerport = 443, protocol = tcp, hostport = ${SB_PORT}}\"";
		log_and_execute "${cmd}";
	else
		printErr "Image SecureDockerBuild doesn't exist please upload it";
		printErr "We can go no further without it...";
		exit 1;
	fi;
};

# contact docker hub support - permanently delete a repository and clean out the keys

function secure_build_application()
{
	log_and_print "Generating GPG keys to encrypt the image repository definition once the image is built...";
	export keyName="secure_bitcoin_key${RANDOM}";
	export passphrase="test_passphrase";
	[[ ! -d "${SB_DIR}/registration_keys" ]] && mkdir -p "${SB_DIR}/registration_keys";
	[[ ! -f "${SB_DIR}/registration_keys/${keyName}_definition_keys" ]] && cat > "${SB_DIR}/registration_keys/${keyName}_definition_keys" <<EOF
%echo Generating registration definition key
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: ${keyName}
Expire-Date: 0
Passphrase: ${passphrase}
# Do a commit here, so that we can later print "done" :-)
%commit
%echo done
EOF
	if [[ ! -f "${SB_DIR}/registration_keys/${keyName}_definition_keys" ]];
	then
		echo "No : ${SB_DIR}/registration_keys/${keyName}_definition_keys";
		return 1;
	else
		echo "Yes: ${SB_DIR}/registration_keys/${keyName}_definition_keys";
		local	cmd="gpg --armor --batch --generate-key ${SB_DIR}/registration_keys/${keyName}_definition_keys";
		log_and_execute "${cmd}";
		local	cmd="gpg --armor --pinentry-mode=loopback --passphrase ${passphrase} --export-secret-keys ${keyName} > ${SB_DIR}/registration_keys/${keyName}.private";
		log_and_execute "${cmd}";
		local	cmd="gpg --armor --export ${keyName} > ${SB_DIR}/registration_keys/${keyName}.pub";
		log_and_execute "${cmd}";
		local	cmd="ls ${SB_DIR}/registration_keys/";
		log_and_execute "${cmd}";
	fi;

	[[ ! -f "${SB_DIR}/sb_config.yaml" ]] && echo -e "\nGenerating secure build config file..." && cat > "${SB_DIR}/sb_config.yaml" <<EOF
secure_build_workers:
    sbs:
        url: 'https://${SB_IP}'
        port: '${SB_PORT}'
        cert_path: '${SB_DIR}/sbs_keys/sbs.cert'
        key_path: '${SB_DIR}/sbs_keys/sbs.key'
    regfile:
        id: '${REPO_ID}'
    github:
        url: '${GH_REPO}'
        branch: 'master'
        ssh_private_key_path: '${GITHUB_SSH_KEY}'
        recurse_submodules: 'False'
        dockerfile_path: '${DOCKERFILE_PATH}'
        docker_build_path: '${DOCKERFILE_BUILD_PATH}'
    docker:
        push_server: '${REGISTRY_NAME}'
        #base_server: '${REGISTRY_NAME}'
        pull_server: '${REGISTRY_NAME}'
        repo: '${DOCKER_USERNAME}/${IMAGE_NAME}'
        image_tag_prefix: 'latest'
        content_trust_base: 'False'
    #env:
    # You would enter environment variables that you want to use in your application container in the whitelist array.
    #    whitelist: []
    #build:
    # You would enter any desired docker build arguments in the args array.
    #    args: []
    signing_key:
        private_key_path: '${SB_DIR}/registration_keys/${keyName}.private'
        public_key_path: '${SB_DIR}/registration_keys/${keyName}.pub'
EOF
	until hpvs sb init --config "${SB_DIR}/sb_config.yaml" &> /dev/null;
	do
		echo -e "\nWaiting for Secure Build Server to become available for initialization...taking a 20 second nap.";
		sleep 20;
	done;
	log_and_print "Secure build server initialized";
	log_and_print "Securely Building Container Image: ${IMAGE_NAME}...";
	local	cmd="hpvs sb build --timeout 20 --config ${SB_DIR}/sb_config.yaml";
	log_and_execute "${cmd}";
	log_and_print "Encrypting registration file with GPG key...";
	local	cmd="echo ${passphrase} | hpvs sb regfile --config ${SB_DIR}/sb_config.yaml --out ${SB_DIR}/yaml.${REPO_ID}.enc";
	log_and_execute "${cmd}";
};

function delete_git_key()
{
	# delete git key for build if keyid created this run through
	local git_api_keyurl="https://api.github.com/user/keys/${git_ssl_keyid}";
	if [[ -n "${git_ssl_keyid}" ]];
	then
		log_and_print "For Git Hub account assocaited with the provided GIT_API_TOKEN:";
		log_and_print "\tRemoving git key ID: ${git_ssl_keyid}...";
		local	cmd="curl -H \"Authorization: token ${GIT_API_TOKEN}\" -H \"Accept: application/vnd.github.v3+json\" -X DELETE \"${git_api_keyurl}\"";
		log_and_execute "${cmd}";
	else
		log_and_print "A git key hasn't been uploaded at this point in the script run.";
	fi; 
}

function verify_application()
{
	local	cmd="mkdir -p ${SB_DIR}/manifest/manifest_files";
	log_and_execute "${cmd}";
	pushd "${SB_DIR}/manifest" > /dev/null;
	export BUILD_NAME="$(hpvs sb status --config "${SB_DIR}/sb_config.yaml" | grep build_name | egrep -ow 'docker.*[[:digit:]]')";
	log_and_print "Retrieving secure build manifest...";
	local manifest_tries=0;
	until hpvs sb manifest --config "${SB_DIR}/sb_config.yaml" --name "${BUILD_NAME}" &> /dev/null;
	do
		sleep 1;
		log_and_print "Could not retrieve manifest\nRetrying...";
		manifest_tries="$(( manifest_tries + 1 ))";
		if [[ manifest_tries -gt 3 ]];
		then
			printErr "Could not retrieve manifest after 3 attempts, skipping verify...";
			return 1;
		fi;
	done;
	local	cmd="hpvs sb manifest --config ${SB_DIR}/sb_config.yaml --name ${BUILD_NAME}";
	log_and_execute "${cmd}";
	log_and_print "Retrieving secure build public key...";
	local	cmd="hpvs sb pubkey --config ${SB_DIR}/sb_config.yaml --name ${BUILD_NAME}";
	log_and_execute "${cmd}";
	log_and_print "Files retrieved:";
	ls;
	export MANIFEST="${SB_DIR}/manifest/manifest.${BUILD_NAME}";
	export MAN_PUBKEY="${SB_DIR}/manifest/${BUILD_NAME}-public.pem";
	log_and_print "Verifying build integrity with manifest and public key...";
	local	cmd="tar -xjvf ${MANIFEST}.sig.tbz > /dev/null && rm ${MANIFEST}.sig.tbz";
	log_and_execute "${cmd}";
	local	cmd="cat ${MANIFEST}.sig | xxd -r -p > ${MANIFEST}.sig.bin";
	log_and_execute "${cmd}";
	local	cmd="openssl dgst -sha256 -binary -out ${MANIFEST}.tbz.sha256 ${MANIFEST}.tbz";
	log_and_execute "${cmd}";
	local	cmd="openssl dgst -sha256 -verify ${MAN_PUBKEY} -signature ${MANIFEST}.sig.bin ${MANIFEST}.tbz.sha256";
	log_and_execute "${cmd}";
	local	cmd="tar -xjf ${MANIFEST}.tbz -C ${SB_DIR}/manifest/manifest_files";
	log_and_execute "${cmd}";
	pushd "${SB_DIR}/manifest/manifest_files" > /dev/null;
	if [[ $? -eq 0 ]];
	then
		log_and_print "Manifest file directory structure";
		local cmd="ls";
		log_and_execute;
		popd > /dev/null;
	fi;
	popd > /dev/null;
};

function roll_in_the_maid()
{
	local	cmd="hpvs sb clean --config ${SB_DIR}/sb_config.yaml";
	log_and_execute "${cmd}";
};

function deploy_application()
{
	log_and_print "Registering ${REPO_ID} container repository with Hyper Protect Virtual Servers appliance...";
	local	cmd="hpvs repository register --pgp=${SB_DIR}/yaml.${REPO_ID}.enc --id=${REPO_ID}";
	log_and_execute "${cmd}";

	log_and_print "Creating quotagroup to deploy application using image repository: ${REPO_ID}...";
	local	cmd="hpvs quotagroup create --name=${REPO_ID} --size=5GB";
	log_and_execute "${cmd}";

	log_and_print "Creating Hyper Protect Virtual Servers application using image repository: ${REPO_ID}...";
	export APP_PORT=301${HPVS_NUMBER};
	local	cmd="
	hpvs vs create --name=${REPO_ID} --repo ${REPO_ID} \
	--tag latest --cpu 2 --ram 2048 \
	--quotagroup \"{quotagroup = ${REPO_ID}, mountid = new, mount = /newroot, filesystem = btrfs, size = 4GB}\" \
	--ports \"{containerport = ${INTERNAL_APP_PORT}, protocol = tcp, hostport = ${APP_PORT}}\"";
	log_and_execute "${cmd}";
	local	cmd="hpvs quotagroup show --name ${REPO_ID}";
	log_and_execute "${cmd}";
	local	cmd="hpvs vs show --name=${REPO_ID}";
	log_and_execute "${cmd}";
};

function clean_up()
{
	log_and_print "Starting the cleanup process\n";
	if hpvs vs show --name "sbserver_${HPVS_NUMBER}" &> /dev/null;
	then
		log_and_print "Cleaning up Hyper Protect Virtual Server sbserver_${HPVS_NUMBER}...";
		local	cmd="hpvs vs delete --name sbserver_${HPVS_NUMBER}";
		log_and_execute "${cmd}";
	fi;
	if hpvs quotagroup show --name "sb_user${HPVS_NUMBER}" &> /dev/null;
	then
		log_and_print "Cleaning up quotagroup sb_user${HPVS_NUMBER}...";
		local	cmd="hpvs quotagroup delete --name sb_user${HPVS_NUMBER}";
		log_and_execute "${cmd}";
	fi;
	if hpvs vs show --name "${REPO_ID}" &> /dev/null;
	then
		log_and_print "Cleaning up Hyper Protect Virtual Server ${REPO_ID}...";
		local	cmd="hpvs vs delete --name ${REPO_ID}";
		log_and_execute "${cmd}";
	fi;
	if hpvs quotagroup show --name "${REPO_ID}" &> /dev/null;
	then
		log_and_print "Cleaning up quotagroup ${REPO_ID}...";
		local	cmd="hpvs quotagroup delete --name ${REPO_ID}";
		log_and_execute "${cmd}";
	fi;
	if hpvs repository show --id "${REPO_ID}" &> /dev/null;
	then
		log_and_print "Cleaning up image repository ${REPO_ID}";
		local	cmd="hpvs repository delete --id ${REPO_ID} --force";
		log_and_execute "${cmd}";
	fi;

	if [[ -d "${SB_DIR}" ]];
	then
		log_and_print "Removing directory ${SB_DIR}";
		local	cmd="rm -rf ${SB_DIR}";
		log_and_execute "${cmd}";
	fi;

	if hpvs registry show --name "${REGISTRY_NAME}" &> /dev/null && [[ "$(hpvs registry list | wc -l)" -ne 4 ]];
	then
		log_and_print "Cleaning up Hyper Protect registry credentials for registry: ${REGISTRY_NAME}...";
		local	cmd="hpvs registry delete --name ${REGISTRY_NAME}";
		log_and_execute "${cmd}";
	fi;

	log_and_print "Current state of quotagroups on system";
	local	cmd="hpvs quotagroup list";
	log_and_execute "${cmd}";

	log_and_print "Current state of Hyper Protect Virtual Servers on system";
	local	cmd="hpvs vs list";
	log_and_execute "${cmd}";
};

function print_url_and_test()
{
	printf "\n%s\n" "${APP_STRING}";
	if [[ $(type -P curl) ]];
	then
		log_and_print "Let's test it with curl:\n";
		local	cmd="curl http://${SB_IP}:${APP_PORT}";
		log_and_execute "${cmd}";
	fi;
};

cleanup_prompt()
{
	local	time_to_wait=20;
	local	cleanup=${1:-""};

	if [[ -z ${cleanup} ]];
	then
		printf "\n";
		printf "If you do not respond, the script will perform a secure build.\n";
		printf "If you reply 'y' within the next 15 seconds, then the script will stop.\n";
		printf "\n";
		read -t ${time_to_wait} -p "Clean_up only?" cleanup;
	else
		[[ "${cleanup}" == "y" ]] && exit $?;
	fi;
};

log_and_print "\n";
log_and_print "Starting at $(date)";
prereq_check;
## clean up previous (if using non-incremented image #)
clean_up;
cleanup_prompt;
## update IMAGE_NUMBER for new run
update_image_number && source user_variables.env;
setup_environment;
create_certificate_and_key;
secure_build_application;
delete_git_key;
verify_application;
roll_in_the_maid;
deploy_application;
print_url_and_test;
#clean_up;
log_and_print "Complete at $(date)";

