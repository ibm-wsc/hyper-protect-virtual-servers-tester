# Secure_Build_Tester

## Enter your VARIABLES in user_variables.env

The ones you must enter are labeled `MUST ENTER`

`IMAGE_NUMBER` lets you increment your image numbers so old repos that have trapped notary server keys can be left behind 
<details>
<summary>edit the following section {expand me for details}</summary>

```
########################################################
## Increment this number to get around problem of image name already used in notary server
## for keys in Docker Hub
export IMAGE_NUMBER="21";
########################################################
```
</details>

Others may be of use depending on the circumstance...

## Example Script Runthrough
<details>
<summary>Go Hello World Build (USE_GO=1) [tl;dr ~ 5 minute runtime] {expand me for details} </summary>

```
time ./lab1.sh 

Cleaning up quotagroup sb_user00...

Current state of quotagroups on system
+-----------------+
| QUOTAGROUP NAME |
+-----------------+
| sb_user21       |
| sb_user10       |
| prom0630_19     |
| sb_user1        |
| hpvs_bc_21      |
| sbgrafana       |
| hpvs_bc_16      |
| hpvs_bc_3_2     |
| sb_user2        |
| hpvs_grafana    |
| sb_user09       |
| sb_user16       |
| appliance_data  |
| hpvs_bc_10      |
+-----------------+

Current state of Hyper Protect Virtual Servers on system
+----------------------+---------+-------------+----------------------------------------------------------+
| NAMES                | STATE   | STATUS      | IMAGE                                                    |
+----------------------+---------+-------------+----------------------------------------------------------+
| prom0630_19          | running | Up 2 months | jinxiong/prom0630:latest                                 |
| grep11-0a-0016-19876 | running | Up 4 weeks  | ibmzcontainers/hpcs-grep11-prod:1.2.1                    |
| sbserver_16          | running | Up 5 weeks  | ibmzcontainers/secure-docker-build:1.2.1-release-9b63b43 |
| sbserver_10          | running | Up 5 weeks  | ibmzcontainers/secure-docker-build:1.2.1-release-9b63b43 |
| grep11-08-0016-9876  | running | Up 4 weeks  | ibmzcontainers/hpcs-grep11-prod:1.2.1                    |
| sbserver_2           | running | Up 7 days   | ibmzcontainers/secure-docker-build:1.2.1-release-9b63b43 |
| collectd             | running | Up 2 months | ibmzcontainers/collectd-host:1.2.1                       |
| sbserver_1           | running | Up 2 weeks  | ibmzcontainers/secure-docker-build:1.2.1-release-9b63b43 |
| hpvs_bc_3_2          | running | Up 3 days   | rkrishnm/hpvs_bc_3:latest                                |
| hpvs_grafana         | running | Up 2 months | jinxiong/hpvs_grafana:latest                             |
| hpvs_bc_10           | running | Up 5 weeks  | josedeivit/hpvs_bc:latest                                |
| sbserver_21          | running | Up 5 weeks  | ibmzcontainers/secure-docker-build:1.2.1-release-9b63b43 |
| hpvs_bc_21           | running | Up 5 weeks  | rodroxrom/hpvs_bc:latest                                 |
| monitoring           | running | Up 2 months | ibmzcontainers/monitoring:1.2.1                          |
| hpvs_bc_16           | running | Up 5 weeks  | maurocecc/hpvs_bc:latest                                 |
| sbserver_09          | running | Up 5 weeks  | ibmzcontainers/secure-docker-build:1.2.1-release-9b63b43 |
+----------------------+---------+-------------+----------------------------------------------------------+
setup_environment: Setting up the secure build environment...
Generating public/private rsa key pair.
Your identification has been saved in /home/hyper-protect-lab/securebuild-test/github_keys/github_rsa_hpvs.
Your public key has been saved in /home/hyper-protect-lab/securebuild-test/github_keys/github_rsa_hpvs.pub.
The key fingerprint is:
SHA256:8hqyaJ+9GzYyxpxjn/CtPxay+njwc/NpKDs7t8K0uR0 hyper-protect-lab@ubuntu
The key's randomart image is:
+---[RSA 4096]----+
|                 |
|                 |
|                 |
|                 |
|      . S        |
|   o..oo.        |
|    %===Eo       |
|  .+ #&OB...     |
| ...*+#^=*o      |
+----[SHA256]-----+
# github.com:22 SSH-2.0-babeld-00265aa9
# github.com:22 SSH-2.0-babeld-00265aa9
# github.com:22 SSH-2.0-babeld-00265aa9

Creating certificates and keys for secure image build...
Generating a RSA private key
..+++++
.................+++++
writing new private key to '/home/hyper-protect-lab/securebuild-test/sbs_keys/sbs.key'
-----

Creating quotagroup sb_user00 for Hyper Protect Secure Build Server...
+-------------+--------------+
| name        | sb_user00    |
| filesystem  | btrfs        |
| passthrough | false        |
| pool_id     | lv_data_pool |
| size        | 40GB         |
| available   | 40GB         |
| containers  | []           |
+-------------+--------------+

Creating Hyper Protect Secure Build Server: sbserver_00...
+-------------+------------------------------+
| PROPERTIES  | VALUES                       |
+-------------+------------------------------+
| Name        | sbserver_00                  |
| Status      | Up Less than a second        |
| CPU         | 2                            |
| Memory      | 2048                         |
| Networks    | Network:bridge               |
|             | IPAddress:172.31.0.7         |
|             | Gateway:172.31.0.1           |
|             | Subnet:16                    |
|             | MacAddress:02:42:ac:1f:00:07 |
|             |                              |
|             |                              |
| Ports       | LocalPort:443/tcp            |
|             | GuestPort:30000              |
|             |                              |
| Quotagroups | appliance_data               |
|             | sb_user00                    |
|             |                              |
| State       | running                      |
+-------------+------------------------------+

Generating GPG keys to encrypt the image repository definition once the image is built...
gpg: Generating registration definition key
gpg: key AD6328D1C026ECC6 marked as ultimately trusted
gpg: revocation certificate stored as '/home/hyper-protect-lab/.gnupg/openpgp-revocs.d/5E1AE39684D63D642B4D6DC4AD6328D1C026ECC6.rev'
gpg: done
secure_bitcoin_key29612_definition_keys  secure_bitcoin_key29612.pub
secure_bitcoin_key29612.private

Generating secure build config file...

Waiting for Secure Build Server to become available for initialization...taking a 20 second nap.

Waiting for Secure Build Server to become available for initialization...taking a 20 second nap.

Secure build server initialized

Securely Building Container Image: hpvs_hello_world_go1...
+--------+-------------------------+
| status | OK: async build started |
+--------+-------------------------+
###############################
+---------------------+-------------------------------------------------------------------------------------------------------+
| status              | success                                                                                               |
| build_name          | docker.io.gmoney23.hpvs_hello_world_go1.latest-a1d1fc3.2020-09-18_01-45-15.448395                     |
| image_tag           | latest-a1d1fc3                                                                                        |
| manifest_key_gen    | soft_crypto                                                                                           |
| manifest_public_key | manifest.docker.io.gmoney23.hpvs_hello_world_go1.latest-a1d1fc3.2020-09-18_01-45-15.448395-public.pem |
| root_ssh_enabled    | false                                                                                                 |
+---------------------+-------------------------------------------------------------------------------------------------------+

Encrypting registration file with GPG key...
Enter Sigining Private key passphrase: 

For Git Hub account assocaited with the provided GIT_API_TOKEN:
	Removing git key ID: 46284920...

Retrieving secure build manifest...

Retrieving secure build public key...

Files retrieved:
docker.io.gmoney23.hpvs_hello_world_go1.latest-a1d1fc3.2020-09-18_01-45-15.448395-public.pem
manifest.docker.io.gmoney23.hpvs_hello_world_go1.latest-a1d1fc3.2020-09-18_01-45-15.448395.sig.tbz
manifest_files

Verifying build integrity with manifest and public key...
Verified OK

Manifest file directory structure
data  git  root_ssh

Registering hpvs_hello_world_go1_00 container repository with Hyper Protect Virtual Servers appliance...
+-----------------+-----------------------------------------+
| repository name | docker.io/gmoney23/hpvs_hello_world_go1 |
| runtime         | runq                                    |
+-----------------+-----------------------------------------+

Creating quotagroup to deploy application using image repository: hpvs_hello_world_go1_00...
+-------------+-------------------------+
| name        | hpvs_hello_world_go1_00 |
| filesystem  | btrfs                   |
| passthrough | false                   |
| pool_id     | lv_data_pool            |
| size        | 5GB                     |
| available   | 5GB                     |
| containers  | []                      |
+-------------+-------------------------+

Creating Hyper Protect Virtual Servers application using image repository: hpvs_hello_world_go1_00...
+-------------+------------------------------+
| PROPERTIES  | VALUES                       |
+-------------+------------------------------+
| Name        | hpvs_hello_world_go1_00      |
| Status      | Up Less than a second        |
| CPU         | 2                            |
| Memory      | 2048                         |
| Networks    | Network:bridge               |
|             | IPAddress:172.31.0.13        |
|             | Gateway:172.31.0.1           |
|             | Subnet:16                    |
|             | MacAddress:02:42:ac:1f:00:0d |
|             |                              |
|             |                              |
| Ports       | LocalPort:5000/tcp           |
|             | GuestPort:30100              |
|             |                              |
| Quotagroups | hpvs_hello_world_go1_00      |
|             |                              |
| State       | running                      |
+-------------+------------------------------+
+-------------+-----------------------------------+
| PROPERTIES  | VALUES                            |
+-------------+-----------------------------------+
| name        | hpvs_hello_world_go1_00           |
| filesystem  | btrfs                             |
| passthrough | false                             |
| pool_id     | lv_data_pool                      |
| size        | 5 GB                              |
| available   | 752 MB                            |
| containers  | Mountids:"new"                    |
|             |                                   |
|             | Container:hpvs_hello_world_go1_00 |
|             |                                   |
+-------------+-----------------------------------+
+-------------+------------------------------+
| PROPERTIES  | VALUES                       |
+-------------+------------------------------+
| Name        | hpvs_hello_world_go1_00      |
| Status      | Up 2 seconds                 |
| CPU         | 2                            |
| Memory      | 2048                         |
| Networks    | Network:bridge               |
|             | IPAddress:172.31.0.13        |
|             | Gateway:172.31.0.1           |
|             | Subnet:16                    |
|             | MacAddress:02:42:ac:1f:00:0d |
|             |                              |
|             |                              |
| Ports       | LocalPort:5000/tcp           |
|             | GuestPort:30100              |
|             |                              |
| Quotagroups | hpvs_hello_world_go1_00      |
|             |                              |
| State       | running                      |
+-------------+------------------------------+

Hello World Go Application: http://192.168.22.80:30100

real	4m46.120s
user	0m9.161s
sys	0m2.205s
```

</details>

<details>
<summary>Secure Bitcoin Wallet Build (comment out #USE_GO=1) [tl;dr ~ 13 minutes of runtime] expand me for details {expand me for details}</summary>

```
time ./lab1.sh 

Cleaning up Hyper Protect Virtual Server sbserver_00...

Cleaning up quotagroup sb_user00...

Current state of quotagroups on system
+-----------------+
| QUOTAGROUP NAME |
+-----------------+
| sb_user21       |
| sb_user10       |
| prom0630_19     |
| sb_user1        |
| hpvs_bc_21      |
| sbgrafana       |
| hpvs_bc_16      |
| sb_user         |
| hpvs_bc_3_2     |
| sb_user2        |
| hpvs_grafana    |
| sb_user09       |
| sb_user16       |
| appliance_data  |
| hpvs_bc_10      |
+-----------------+

Current state of Hyper Protect Virtual Servers on system
+----------------------+---------+--------------+------------------------------------------------------------+
| NAMES                | STATE   | STATUS       | IMAGE                                                      |
+----------------------+---------+--------------+------------------------------------------------------------+
| monitoring           | running | Up 2 months  | ibmzcontainers/monitoring:1.2.1                            |
| sbserver_16          | running | Up 5 weeks   | ibmzcontainers/secure-docker-build:1.2.1-release-9b63b43   |
| prom0630_19          | running | Up 2 months  | jinxiong/prom0630:latest                                   |
| grep11-0a-0016-19876 | running | Up 4 weeks   | ibmzcontainers/hpcs-grep11-prod:1.2.1                      |
| hpvs_bc_21           | running | Up 5 weeks   | rodroxrom/hpvs_bc:latest                                   |
| sbserver_2           | running | Up 8 days    | ibmzcontainers/secure-docker-build:1.2.1-release-9b63b43   |
| sbserver_            | running | Up 6 minutes | ibmzcontainers/secure-docker-build:1.2.1.1-release-bf10b8e |
| hpvs_bc_10           | running | Up 5 weeks   | josedeivit/hpvs_bc:latest                                  |
| sbserver_21          | running | Up 5 weeks   | ibmzcontainers/secure-docker-build:1.2.1-release-9b63b43   |
| hpvs_bc_16           | running | Up 5 weeks   | maurocecc/hpvs_bc:latest                                   |
| sbserver_10          | running | Up 5 weeks   | ibmzcontainers/secure-docker-build:1.2.1-release-9b63b43   |
| grep11-08-0016-9876  | running | Up 4 weeks   | ibmzcontainers/hpcs-grep11-prod:1.2.1                      |
| hpvs_bc_3_2          | running | Up 4 days    | rkrishnm/hpvs_bc_3:latest                                  |
| collectd             | running | Up 2 months  | ibmzcontainers/collectd-host:1.2.1                         |
| hpvs_grafana         | running | Up 2 months  | jinxiong/hpvs_grafana:latest                               |
| sbserver_09          | running | Up 5 weeks   | ibmzcontainers/secure-docker-build:1.2.1-release-9b63b43   |
| sbserver_1           | running | Up 2 weeks   | ibmzcontainers/secure-docker-build:1.2.1-release-9b63b43   |
+----------------------+---------+--------------+------------------------------------------------------------+
setup_environment: Setting up the secure build environment...
Generating public/private rsa key pair.
Your identification has been saved in /home/hyper-protect-lab/securebuild-test/github_keys/github_rsa_hpvs.
Your public key has been saved in /home/hyper-protect-lab/securebuild-test/github_keys/github_rsa_hpvs.pub.
The key fingerprint is:
SHA256:1/rZrC8kZEW/OVBLj++K7ckB4Ejvg95Rtg5HyFXn5ig hyper-protect-lab@ubuntu
The key's randomart image is:
+---[RSA 4096]----+
|           .. + .|
|            .= * |
|        . ..o + +|
|       . =o= . B |
|        So* E = o|
|         +.=.+ o |
|        . *oo . .|
|       . . B.B + |
|        . . *=X  |
+----[SHA256]-----+
# github.com:22 SSH-2.0-babeld-00265aa9
# github.com:22 SSH-2.0-babeld-00265aa9
# github.com:22 SSH-2.0-babeld-00265aa9

Creating certificates and keys for secure image build...
Generating a RSA private key
.............................+++++
............................................+++++
writing new private key to '/home/hyper-protect-lab/securebuild-test/sbs_keys/sbs.key'
-----

Creating quotagroup sb_user00 for Hyper Protect Secure Build Server...
+-------------+--------------+
| name        | sb_user00    |
| filesystem  | btrfs        |
| passthrough | false        |
| pool_id     | lv_data_pool |
| size        | 40GB         |
| available   | 40GB         |
| containers  | []           |
+-------------+--------------+

Creating Hyper Protect Secure Build Server: sbserver_00...
+-------------+------------------------------+
| PROPERTIES  | VALUES                       |
+-------------+------------------------------+
| Name        | sbserver_00                  |
| Status      | Up Less than a second        |
| CPU         | 2                            |
| Memory      | 2048                         |
| Networks    | Network:bridge               |
|             | IPAddress:172.31.0.13        |
|             | Gateway:172.31.0.1           |
|             | Subnet:16                    |
|             | MacAddress:02:42:ac:1f:00:0d |
|             |                              |
|             |                              |
| Ports       | LocalPort:443/tcp            |
|             | GuestPort:30000              |
|             |                              |
| Quotagroups | appliance_data               |
|             | sb_user00                    |
|             |                              |
| State       | running                      |
+-------------+------------------------------+

Generating GPG keys to encrypt the image repository definition once the image is built...
gpg: Generating registration definition key
gpg: key 9E7CE6781BD2EB8B marked as ultimately trusted
gpg: revocation certificate stored as '/home/hyper-protect-lab/.gnupg/openpgp-revocs.d/FA2EE1A7306A0AE15F2FCB7C9E7CE6781BD2EB8B.rev'
gpg: done
secure_bitcoin_key28744_definition_keys  secure_bitcoin_key28744.pub
secure_bitcoin_key28744.private

Generating secure build config file...

Waiting for Secure Build Server to become available for initialization...taking a 20 second nap.

Waiting for Secure Build Server to become available for initialization...taking a 20 second nap.

Secure build server initialized

Securely Building Container Image: hpvs_bc99...
+--------+-------------------------+
| status | OK: async build started |
+--------+-------------------------+
##################################################################################################################################################################################################################################################################################################################################################################################################################
+---------------------+--------------------------------------------------------------------------------------------+
| build_name          | docker.io.gmoney23.hpvs_bc99.latest-ad52e76.2020-09-18_03-33-41.191504                     |
| image_tag           | latest-ad52e76                                                                             |
| manifest_key_gen    | soft_crypto                                                                                |
| manifest_public_key | manifest.docker.io.gmoney23.hpvs_bc99.latest-ad52e76.2020-09-18_03-33-41.191504-public.pem |
| root_ssh_enabled    | false                                                                                      |
| status              | success                                                                                    |
+---------------------+--------------------------------------------------------------------------------------------+

Encrypting registration file with GPG key...
Enter Sigining Private key passphrase: 

For Git Hub account assocaited with the provided GIT_API_TOKEN:
	Removing git key ID: 46287855...

Retrieving secure build manifest...

Retrieving secure build public key...

Files retrieved:
docker.io.gmoney23.hpvs_bc99.latest-ad52e76.2020-09-18_03-33-41.191504-public.pem
manifest.docker.io.gmoney23.hpvs_bc99.latest-ad52e76.2020-09-18_03-33-41.191504.sig.tbz
manifest_files

Verifying build integrity with manifest and public key...
Verified OK

Manifest file directory structure
data  git  root_ssh

Registering hpvs_bc99_00 container repository with Hyper Protect Virtual Servers appliance...
+-----------------+------------------------------+
| repository name | docker.io/gmoney23/hpvs_bc99 |
| runtime         | runq                         |
+-----------------+------------------------------+

Creating quotagroup to deploy application using image repository: hpvs_bc99_00...
+-------------+--------------+
| name        | hpvs_bc99_00 |
| filesystem  | btrfs        |
| passthrough | false        |
| pool_id     | lv_data_pool |
| size        | 5GB          |
| available   | 5GB          |
| containers  | []           |
+-------------+--------------+

Creating Hyper Protect Virtual Servers application using image repository: hpvs_bc99_00...
+-------------+------------------------------+
| PROPERTIES  | VALUES                       |
+-------------+------------------------------+
| Name        | hpvs_bc99_00                 |
| Status      | Up Less than a second        |
| CPU         | 2                            |
| Memory      | 2048                         |
| Networks    | Network:bridge               |
|             | IPAddress:172.31.0.19        |
|             | Gateway:172.31.0.1           |
|             | Subnet:16                    |
|             | MacAddress:02:42:ac:1f:00:13 |
|             |                              |
|             |                              |
| Ports       | LocalPort:443/tcp            |
|             | GuestPort:30100              |
|             |                              |
| Quotagroups | hpvs_bc99_00                 |
|             | appliance_data               |
|             |                              |
| State       | running                      |
+-------------+------------------------------+
+-------------+------------------------+
| PROPERTIES  | VALUES                 |
+-------------+------------------------+
| name        | hpvs_bc99_00           |
| filesystem  | btrfs                  |
| passthrough | false                  |
| pool_id     | lv_data_pool           |
| size        | 5 GB                   |
| available   | 752 MB                 |
| containers  | Container:hpvs_bc99_00 |
|             | Mountids:"new"         |
|             |                        |
|             |                        |
+-------------+------------------------+
+-------------+------------------------------+
| PROPERTIES  | VALUES                       |
+-------------+------------------------------+
| Name        | hpvs_bc99_00                 |
| Status      | Up 2 seconds                 |
| CPU         | 2                            |
| Memory      | 2048                         |
| Networks    | Network:bridge               |
|             | IPAddress:172.31.0.19        |
|             | Gateway:172.31.0.1           |
|             | Subnet:16                    |
|             | MacAddress:02:42:ac:1f:00:13 |
|             |                              |
|             |                              |
| Ports       | LocalPort:443/tcp            |
|             | GuestPort:30100              |
|             |                              |
| Quotagroups | appliance_data               |
|             | hpvs_bc99_00                 |
|             |                              |
| State       | running                      |
+-------------+------------------------------+

Secure Bicoin Wallet Application: https://192.168.22.80:30100/electrum

real	13m6.805s
user	0m4.595s
sys	0m1.048s
```

</details>

:octocat:
