#!/usr/bin/env bash

# This is the file where user variables are entered
source user_variables.env

export gitrepo_ssh="git@github.com:person/repo.git"
# Let's name the ssh-key in get after the hostname with a timestamp:
export git_ssl_keyid=""

function prereq_check()
{
	# Check if curl exists
	if ! command -v curl &> /dev/null;
	then
		echo -e "\nPlease install curl"
		exit 1
	fi

	# Check if jq exists
	if ! command -v jq &> /dev/null;
	then
		echo -e "\nPlease install jq"
		exit 1
	fi
}

function setup_environment()
{
	echo -e "setup_environment: Setting up the secure build environment...";
	[[ ! -d "${SB_DIR}" ]] && mkdir -p "${SB_DIR}" && cd "${SB_DIR}";
	[[ ! -d "${SB_DIR}/github_keys" ]] && mkdir -p "${SB_DIR}/github_keys";
	export GITHUB_SSH_KEY="${SB_DIR}/github_keys/github_rsa_hpvs";

#	set -xe
#	^ we had done this for debugging purposes

	local myemail="$USERNAME@$HOSTNAME";

	# Add hpvs registry with username and password (token provided) if it doesn't exist already
	if ! hpvs registry show --name "${REGISTRY_NAME}" &> /dev/null || [[ "$(hpvs registry list | wc -l)" -eq 4 ]];
	then
		echo -e "\n${REGISTRY_NAME} will be added to the script";
		echo "${DOCKER_API_TOKEN}" | docker login -u ${DOCKER_USERNAME} --password-stdin && docker logout
		echo "${DOCKER_API_TOKEN}" | hpvs registry add \
		--name "${REGISTRY_NAME}" --dct https://notary.docker.io \
		--url docker.io --user "${DOCKER_USERNAME}"
		hpvs registry list;
	fi
#	Generating SSH key:
	[[ ! -f "${GITHUB_SSH_KEY}" ]] && ssh-keygen -f "${GITHUB_SSH_KEY}" -t rsa -b 4096 -C "${myemail}" -N ''
	local sslpub="$(cat ${GITHUB_SSH_KEY}.pub | tail -1)"
#	git API path for posting a new ssh-key:
	local git_api_addkey="https://api.github.com/user/keys"
#	lets name the ssh-key id with hpvs_key and then the hostname with a timestamp:
	local git_ssl_keyname="hpvs_key_$(hostname)_$(date +%d-%m-%Y)"

#	Finally lets post this ssh key:
	ssh-keyscan -H github.com >> "${HOME}/.ssh/known_hosts"
	git_ssl_keyid="$(curl -s -H "Authorization: token ${GIT_API_TOKEN}" -H "Accept: application/vnd.github.v3+json" -X POST -d "{\"title\":\"${git_ssl_keyname}\",\"key\":\"${sslpub}\"}" "${git_api_addkey}" | jq -r '.id')"
	if ssh -T git@github.com -i "${GITHUB_SSH_KEY}" &> /dev/null;
	then
		echo 'end setup_environment()';
	fi
};

function create_certificate_and_key()
{
	echo -e "\nCreating certificates and keys for secure image build..."
#	Follows hereupon the tag for the secure docker 
	local	base_image_tag=$(hpvs image list | awk '($0 ~ /secure-docker-build/) {print $4;}');
	if [[ -z "${base_image_tag}" ]];
	then
		echo -e "\nPlease note (as shown below) that the secure docker build image is not loaded";
		echo -e "\nhpvs load image --file=./securedockerbuild.tar.gz from the proper location";
		hpvs image list;
	fi;

	openssl rand -out "${HOME}/.rnd" -hex 256;
	mkdir -p "${SB_DIR}/sbs_keys";
	openssl req -newkey rsa:2048 \
	-new -nodes -x509 \
	-days 3650 \
	-out "${SB_DIR}/sbs_keys/sbs.cert" \
	-keyout "${SB_DIR}/sbs_keys/sbs.key" \
	-subj "/C=US/O=IBM/CN=hpvs.example.com";

	echo $(cat "${SB_DIR}/sbs_keys/sbs.cert" | base64) | tr -d ' ' > "${SB_DIR}/sbs_keys/sbs_base64.cert";
	export cert=$(cat "${SB_DIR}/sbs_keys/sbs_base64.cert");

	echo -e "\nCreating quotagroup sb_user${HPVS_NUMBER} for Hyper Protect Secure Build Server..."
	hpvs quotagroup create --name "sb_user${HPVS_NUMBER}" --size=40GB;

	if [[ $(hpvs image list | grep -ic 'SecureDockerBuild') -lt 1 ]];
	then
		echo -e "\nCreating Hyper Protect Secure Build Server: sbserver_${HPVS_NUMBER}..."
		hpvs vs create --name sbserver_${HPVS_NUMBER} --repo SecureDockerBuild \
		--tag ${base_image_tag} --cpu 2 --ram 2048 \
		--quotagroup "{quotagroup = sb_user${HPVS_NUMBER}, mountid = new, mount = /newroot, filesystem = ext4, size = 10GB}" \
		--quotagroup "{quotagroup = sb_user${HPVS_NUMBER}, mountid = data, mount = /data, filesystem = ext4, size = 2GB}" \
		--quotagroup "{quotagroup = sb_user${HPVS_NUMBER}, mountid = docker, mount = /docker, filesystem = ext4, size = 16GB}" \
		--env={EX_VOLUMES="/docker,/data",ROOTFS_LOCK=y,CLIENT_CRT=$cert} \
		--ports "{containerport = 443, protocol = tcp, hostport = ${SB_PORT}}";
	else
		echo -e "\nImage SecureDockerBuild doesn't exist please upload it"
		echo -e "\nWe can go no further without it..."
		exit 1
	fi;
};

# contact docker hub support - permanently delete a repository and clean out the keys

function secure_build_application()
{
	echo -e "\nGenerating GPG keys to encrypt the image repository definition once the image is built..."
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
	gpg --armor --batch --generate-key "${SB_DIR}/registration_keys/${keyName}_definition_keys";
	gpg --armor --pinentry-mode=loopback --passphrase  "${passphrase}" --export-secret-keys "${keyName}" > "${SB_DIR}/registration_keys/${keyName}.private";
	gpg --armor --export ${keyName} > "${SB_DIR}/registration_keys/${keyName}.pub";
	ls ${SB_DIR}/registration_keys/;
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
	echo -e "\nSecure build server initialized"
	echo -e "\nSecurely Building Container Image: ${IMAGE_NAME}..."
	hpvs sb build --timeout 20 --config "${SB_DIR}/sb_config.yaml";
#	hpvs sb log --config "${SB_DIR}/sb_config.yaml";
#	hpvs sb status --config "${SB_DIR}/sb_config.yaml"
	echo -e "\nEncrypting registration file with GPG key..."
	echo "${passphrase}" | hpvs sb regfile --config "${SB_DIR}/sb_config.yaml" --out "${SB_DIR}/yaml.${REPO_ID}.enc";
};

function delete_git_key()
{
	# delete git key for build if keyid created this run through
	local git_api_keyurl="https://api.github.com/user/keys/${git_ssl_keyid}"
	if [[ -n "${git_ssl_keyid}" ]];
	then
		echo -e "\nFor Git Hub account assocaited with the provided GIT_API_TOKEN:"
		echo -e "\tRemoving git key ID: ${git_ssl_keyid}..."
		curl -H "Authorization: token ${GIT_API_TOKEN}" -H "Accept: application/vnd.github.v3+json" -X DELETE "${git_api_keyurl}"
	else
		echo -e "\nA git key hasn't been uploaded at this point in the script run."
	fi; 
}

function verify_application()
{
	mkdir -p "${SB_DIR}/manifest/manifest_files";
	pushd "${SB_DIR}/manifest" > /dev/null;
	export BUILD_NAME="$(hpvs sb status --config "${SB_DIR}/sb_config.yaml" | grep build_name | egrep -ow 'docker.*[[:digit:]]')";
	echo -e "\nRetrieving secure build manifest...";
	hpvs sb manifest --config "${SB_DIR}/sb_config.yaml" --name "${BUILD_NAME}";
	echo -e "\nRetrieving secure build public key..."
	hpvs sb pubkey --config "${SB_DIR}/sb_config.yaml" --name "${BUILD_NAME}";
	echo -e "\nFiles retrieved:";
	ls;
	export MANIFEST="${SB_DIR}/manifest/manifest.${BUILD_NAME}";
	export MAN_PUBKEY="${SB_DIR}/manifest/${BUILD_NAME}-public.pem";
	echo -e "\nVerifying build integrity with manifest and public key..."
	tar -xjvf "${MANIFEST}.sig.tbz" > /dev/null && rm "${MANIFEST}.sig.tbz";
	cat "${MANIFEST}.sig" | xxd -r -p > "${MANIFEST}.sig.bin";
	openssl dgst -sha256 -binary -out "${MANIFEST}.tbz.sha256" "${MANIFEST}.tbz";
	openssl dgst -sha256 -verify "${MAN_PUBKEY}" -signature "${MANIFEST}.sig.bin" "${MANIFEST}.tbz.sha256";
	tar -xjf "${MANIFEST}.tbz" -C "${SB_DIR}/manifest/manifest_files";
	pushd "${SB_DIR}/manifest/manifest_files" > /dev/null && echo -e "\nManifest file directory structure" && ls;
	popd > /dev/null;
	popd > /dev/null;
};

function deploy_application()
{
	echo -e "\nRegistering ${REPO_ID} container repository with Hyper Protect Virtual Servers appliance..."
	hpvs repository register --pgp="${SB_DIR}/yaml.${REPO_ID}.enc" --id="${REPO_ID}";
	echo -e "\nCreating quotagroup to deploy application using image repository: ${REPO_ID}..."
	hpvs quotagroup create --name="${REPO_ID}" --size=5GB;
	echo -e "\nCreating Hyper Protect Virtual Servers application using image repository: ${REPO_ID}..."
	export APP_PORT=301${HPVS_NUMBER};
	hpvs vs create --name=${REPO_ID} --repo ${REPO_ID} \
--tag latest --cpu 2 --ram 2048 \
--quotagroup "{quotagroup = ${REPO_ID}, mountid = new, mount = /newroot, filesystem = btrfs, size = 4GB}" \
--ports "{containerport = ${INTERNAL_APP_PORT}, protocol = tcp, hostport = ${APP_PORT}}"
	hpvs quotagroup show --name "${REPO_ID}";
	hpvs vs show --name=${REPO_ID};
};

function clean_up()
{
	if hpvs vs show --name "sbserver_${HPVS_NUMBER}" &> /dev/null;
	then
		echo -e "\nCleaning up Hyper Protect Virtual Server sbserver_${HPVS_NUMBER}..."
		hpvs vs delete --name "sbserver_${HPVS_NUMBER}";
	fi;
	if hpvs quotagroup show --name "sb_user${HPVS_NUMBER}" &> /dev/null;
	then
		echo -e "\nCleaning up quotagroup sb_user${HPVS_NUMBER}..."
		hpvs quotagroup delete --name "sb_user${HPVS_NUMBER}";
	fi;
	if hpvs vs show --name "${REPO_ID}" &> /dev/null;
	then
		echo -e "\nCleaning up Hyper Protect Virtual Server ${REPO_ID}..."
		hpvs vs delete --name "${REPO_ID}";
	fi;
	if hpvs quotagroup show --name "${REPO_ID}" &> /dev/null;
	then
		echo -e "\nCleaning up quotagroup ${REPO_ID}..."
		hpvs quotagroup delete --name "${REPO_ID}";
	fi;
	if hpvs repository show --id "${REPO_ID}" &> /dev/null;
	then
		echo -e "\nCleaning up image repository ${REPO_ID}"
		hpvs repository delete --id "${REPO_ID}" --force;
	fi;
	rm -rf "${SB_DIR}";

	if ! hpvs registry show --name "${REGISTRY_NAME}" &> /dev/null || [[ "$(hpvs registry list | wc -l)" -eq 4 ]];
	then
		echo -e "\nCleaning up Hyper Protect registry credentials for registry: ${REGISTRY_NAME}..."
		hpvs registry delete --name "${REGISTRY_NAME}"
	fi;

	echo -e "\nCurrent state of quotagroups on system"
	hpvs quotagroup list;
	echo -e "\nCurrent state of Hyper Protect Virtual Servers on system"
	hpvs vs list;
};

prereq_check;
clean_up;
setup_environment;
create_certificate_and_key;
secure_build_application;
delete_git_key;
verify_application;
deploy_application;
echo -e "\n${!APP_URL}"
#clean_up;