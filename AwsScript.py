import json
import boto3
import pymysql
import threading
from datetime import datetime, timedelta

db_host = 'localhost'
# db_port=3306
db_user = 'root'
db_pass = 'root'
db_name = 'testdiscovery'

sts = boto3.client('sts')
master_role = 'arn:aws:iam::345117372609:role/MasterRole'
master = sts.assume_role(
		RoleArn=master_role,
		RoleSessionName='MasterSession'  
	)
credentials = master['Credentials']

master_session = boto3.Session(
	aws_access_key_id=credentials['AccessKeyId'],
	aws_secret_access_key=credentials['SecretAccessKey'],
	aws_session_token=credentials['SessionToken'],
	region_name='us-east-1' 
)

all_ec2_regions = master_session.get_available_regions('ec2')
all_regions = master_session.get_available_regions('elbv2')

orgClient = master_session.client('organizations')

multi_account = ['528519205020', '378903711927']
# multi_account = ['528519205020', '378903711927', '228269620532', '442228750442', '699531544441', '881288059377',
#                   '676634049556', '411993925814', '500291834548', '547484501635', '365382048271', '889148926241', 
#                   '156164862935', '613948007550']
service_accounts = []
account_IDs = []
next_token = None
while True:
	if next_token:
		response = orgClient.list_accounts(NextToken=next_token)
	else:
		response = orgClient.list_accounts()
		
	for accounts in response['Accounts']:
		account_IDs.append(accounts['Id'])
		account_name = accounts['Name']
		account_id = accounts['Id']
		discovery_credentials = ''
		datacenter_type = 'AWS'
		datacenter_url = ''
		is_parent = ''
		if account_id == '345117372609':
			is_master = 'True'
		else:
			is_master = 'False'
		account_details = {'Name': account_name, 'Account Id': account_id, 'Discovery Credential': discovery_credentials,
						 'Datacenter Type': datacenter_type, 'Datcenter URL': datacenter_url, 'Parent Account': is_parent,
						  'Is Master Account': is_master }
		service_accounts.append(account_details)
		
	if 'NextToken' in response:
		next_token = response['NextToken']
	else:
		break


def handler():
	try: 
		insert_service_account_details(service_accounts)
		vcpSubnetThread = threading.Thread(target=filtered_vpc_subnet_details)
		sgThread = threading.Thread(target=filtered_sg_details)
		hwThread = threading.Thread(target=filtered_hw_details)
		lbThread = threading.Thread(target=filtered_load_balancer_details)
		keyPairThread = threading.Thread(target=filtered_cld_key_pair_details)
		cld_db_Thread = threading.Thread(target=filtered_cloud_db_details)
		awsDCThread = threading.Thread(target=filtered_aws_dc_details)
		az_Thread = threading.Thread(target=filtered_az_details)
		strgVolThread = threading.Thread(target=filtered_strg_vol_details)
		strgMapThread = threading.Thread(target=filtered_strg_map_details)
		vmThread = threading.Thread(target=filtered_vm_instance_details)
		imageThread = threading.Thread(target=filtered_images_details)
		ipThread = threading.Thread(target=filtered_ip_details)
		logicalDCThread = threading.Thread(target=filter_logical_datacenter_details)
		lbIpThread = threading.Thread(target=filter_lb_publicIp)
		lbServiceThread = threading.Thread(target=filter_lb_service)
		

		sgThread.start()
		hwThread.start()
		lbThread.start()
		ipThread.start()
		keyPairThread.start()
		imageThread.start()		
		vcpSubnetThread.start()
		cld_db_Thread.start()
		awsDCThread.start()
		strgVolThread.start()
		strgMapThread.start()
		az_Thread.start()
		logicalDCThread.start()
		lbIpThread.start()
		lbServiceThread.start()
		vmThread.start()
		
		vcpSubnetThread.join()
		cld_db_Thread.join()
		awsDCThread.join()
		strgVolThread.join()
		sgThread.join()
		hwThread.join()
		lbThread.join()
		ipThread.join()
		keyPairThread.join()
		imageThread.join()
		strgMapThread.join()
		az_Thread.join()
		logicalDCThread.join()
		lbIpThread.join()
		lbServiceThread.join()
		vmThread.join()

	except Exception as e:
		return str(e)

def get_load_balancer_details(session, region):
	try:
		elb_client = session.client('elbv2', region_name=region)
		response = elb_client.describe_load_balancers()
		return response['LoadBalancers']

	except Exception as e:
		print(f"Error fetching ELB details in {region}: {str(e)}")
		return []

def get_subnet_details(session, region):
	try:
		ec2_client = session.client('ec2', region_name=region)
		response = ec2_client.describe_subnets()
		return response['Subnets']

	except Exception as e:
		print(f"Error fetching subnet details in {region}: {str(e)}")
		return []

def get_vpc_details(session, region):
	try:
		ec2_client = session.client('ec2', region_name=region)
		vpcs = ec2_client.describe_vpcs()
		return  vpcs['Vpcs']

	except Exception as e:
		print(f"Error fetching vpc details in {region}: {str(e)}")
		return []

def get_security_group_details(session,region):
	try:
		ec2_client = session.client('ec2', region_name=region)
		response = ec2_client.describe_security_groups()
		return response['SecurityGroups']
	
	except Exception as e:
		print(f"Error fetching Security Group details in {region}: {str(e)}")
		return []

def get_all_hardware_details(session, region):
	try:
		ec2_client = session.client('ec2', region_name=region)  
		response = ec2_client.describe_instance_types()
		instance_types = response['InstanceTypes']
		return instance_types
		
	except Exception as e:
		print(f"Error fetching Hardware details in {region}: {str(e)}")
		return []
		
def get_cld_key_pair_details(session, region):
	try:
		keypair_client = session.client('ec2', region_name=region)  
		response = keypair_client.describe_key_pairs()
		keypair_data = response['KeyPairs']
		return keypair_data
 
	except Exception as e:
		print(f"Error fetching Cloud key Pair details in {region}: {str(e)}")
		return []
 
def get_cld_ip_add_details(session, region):
	try:
		instances = session.client('ec2', region_name=region)  
		reservations = instances.describe_instances()["Reservations"]
		return reservations
 
	except Exception as e:
		print(f"Error fetching Cloud Ip Address details in {region}: {str(e)}")
		return []

def get_cloud_db_details(session, region):
	try:
		cldDB_client = session.client('rds', region_name=region)  
		response = cldDB_client.describe_db_instances()
		instance_types = response['DBInstances']
		return instance_types
		
	except Exception as e:
		print(f"Error fetching Cloud Database details in {region}: {str(e)}")
		return []

def get_aws_dc_details(session, region):
	try:
		awsdc_client = session.client('ec2', region_name=region)  
		response = awsdc_client.describe_regions()

		return response
		
	except Exception as e:
		print(f"Error fetching AWS datacenters details in {region}: {str(e)}")
		return []

def get_az_details(session, region):
	try:
		az_client = session.client('ec2', region_name=region)  
		response = az_client.describe_availability_zones()
		instance_types = response['AvailabilityZones']

		return instance_types
		
	except Exception as e:
		print(f"Error fetching AvailabilityZones details in {region}: {str(e)}")
		return []

def get_strg_vol_details(session, region):
	try:
		strgVol_client = session.client('ec2', region_name=region)  
		response = strgVol_client.describe_volumes()
		instance_types = response['Volumes']
		return instance_types
		
	except Exception as e:
		print(f"Error fetching Storage Volumes details in {region}: {str(e)}")
		return []

def get_strg_map_details(session, region):
	try:
		strgMap_client = session.client('ec2', region_name=region)  
		response = strgMap_client.describe_volumes()

		attached_volumes = []
		unattached_volumes = []

		for volume in response['Volumes']:
			if 'Attachments' in volume and volume['Attachments']:
				attached_volumes.append(volume)
			else:
				unattached_volumes.append(volume)

		return attached_volumes
		
	except Exception as e:
		print(f"Error fetching Storage Mapping details in {region}: {str(e)}")
		return []

def get_public_ip_addresses(session, region):
	try:
		ec2_client = session.client('ec2', region_name=region)

		response = ec2_client.describe_instances()

		ipDetails = []

		# Iterate through reservations and instances to get public IPs
		for reservation in response['Reservations']:
				for instance in reservation['Instances']:
						name = instance.get('KeyName', '')
						object_id = instance['InstanceId']
						public_ip = instance.get('PublicIpAddress', '')
						public_dns = instance.get('PublicDnsName', '')

						details = {
						'Name': name,
						'PublicIp': public_ip,
						'PublicDns' : public_dns,
						'ObjectId' : object_id
					}
						ipDetails.append(details)
		return ipDetails
		
	except Exception as e:
		print(f"Error fetching Public IP details in {region}: {str(e)}")
		return []

def get_images_details(session, region):
	try:
		ec2 = session.client('ec2', region_name=region)
		response = ec2.describe_images(Owners=['self'])
		return response['Images']
			
	except Exception as e:
		print(f"Error fetching Images details in {region}: {str(e)}")
		return []

def get_datacenter_details(session, region):
	try:
		ec2 = session.client('ec2', region_name=region)
		response = ec2.describe_regions()
		data = response['Regions']
		datacenter =[]
		for dc in data:
			name = dc['RegionName']
			region = dc['RegionName']
			discovery = ''
			Class = 'AWS Datacenter'

			details = {
				'Name' : name,
				'Region' : region,
				'DiscoveryStatus' : discovery,
				'Class' : Class
			}

			datacenter.append(details)

		return datacenter
			
	except Exception as e:
		print(f"Error Logical Datacenter details in {region}: {str(e)}")
		return []

def get_vm_instance_details(session, region):
	try:
		ec2_client = session.client('ec2', region_name=region)  
		response = ec2_client.describe_instances()
		return response['Reservations']
		
	except Exception as e:
		print(f"Error fetching VM Instance details in {region}: {str(e)}")
		return []


def filtered_vpc_subnet_details():
	try:
		required_subnet_details = []
		required_vpc_details = []
		all_subnet_details = []
		all_vpc_details = []

		# Loop for fetch and segregate Subnet data

		for val in multi_account:
			try:
				sts = master_session.client('sts')
				role = f'arn:aws:iam::{val}:role/MemberRole2'
				assumed_role = sts.assume_role(
					RoleArn=role,
					RoleSessionName='SessionName'  
				)
				credentials = assumed_role['Credentials']
				assumed_session = boto3.Session(
					aws_access_key_id=credentials['AccessKeyId'],
					aws_secret_access_key=credentials['SecretAccessKey'],
					aws_session_token=credentials['SessionToken'],
					region_name='us-east-1' 
				)

				for region in all_ec2_regions:
					subnets = get_subnet_details(assumed_session, region)
					all_subnet_details.extend(subnets)

			except Exception as e:
				print(f"Error Role to this account is not Attached {val} : {str(e)}")

		for sb in all_subnet_details:
			sb_name = ''
			sb_id = sb['SubnetId']
			sb_state = sb['State']
			sb_cidr = sb['CidrBlock']


			details = {
				'Name': sb_name,
				'State': sb_state,
				'Id': sb_id,
				'Cidr' : sb_cidr
			}

			required_subnet_details.append(details)

		# Loop for fetch and segregate VPC data
		for val in multi_account:
			try:
				sts = master_session.client('sts')
				role = f'arn:aws:iam::{val}:role/MemberRole2'
				assumed_role = sts.assume_role(
					RoleArn=role,
					RoleSessionName='SessionName'  
				)
				credentials = assumed_role['Credentials']
				assumed_session = boto3.Session(
					aws_access_key_id=credentials['AccessKeyId'],
					aws_secret_access_key=credentials['SecretAccessKey'],
					aws_session_token=credentials['SessionToken'],
					region_name='us-east-1' 
				)

				for region in all_ec2_regions:
					vpcs = get_vpc_details(assumed_session, region)
					all_vpc_details.extend(vpcs)

			except Exception as e:
				print(f"Error Role to this account is not Attached {val} : {str(e)}")

		for vp in all_vpc_details:
			vpc_name = ''
			vpc_id = vp['VpcId']
			vpc_state = vp['State']
			vpc_cidr = vp['CidrBlock']


			details = {
				'Name': vpc_name,
				'State': vpc_state,
				'Id': vpc_id,
				'Cidr' : vpc_cidr
			}

			required_vpc_details.append(details)

		insert_subnet_details(required_subnet_details)
		insert_vpc_details(required_vpc_details)

	except Exception as e:
		return 'Error: {str(e)}'

def filtered_load_balancer_details():
	try: 
		required_lb_details = []
		load_balancer_details = []

		# Loop to fetch and segregate Load Balancer data
		for val in multi_account:
			try:
				sts = master_session.client('sts')
				role = f'arn:aws:iam::{val}:role/MemberRole2'
				assumed_role = sts.assume_role(
					RoleArn=role,
					RoleSessionName='SessionName'  
				)
				credentials = assumed_role['Credentials']
				assumed_session = boto3.Session(
					aws_access_key_id=credentials['AccessKeyId'],
					aws_secret_access_key=credentials['SecretAccessKey'],
					aws_session_token=credentials['SessionToken'],
					region_name='us-east-1' 
				)

				for region in all_regions :
					load_balancer = get_load_balancer_details(assumed_session, region)
					load_balancer_details.extend(load_balancer)

			except Exception as e:
				print(f"Error Role to this account is not Attached {val} : {str(e)}")

		for lb in load_balancer_details:
			lb_name = lb['LoadBalancerName']
			lb_object_id = ''
			lb_State = lb['State']['Code']
			lb_hosted_zone_name = ''
			lb_Hosted_zone_ID = lb['CanonicalHostedZoneId']
			lb_dns_name = lb['DNSName']

			lb_details = {
				'Name': lb_name,
				'ObjectID':lb_object_id,
				'State' : lb_State,
				'HostedZoneName':lb_hosted_zone_name,
				'HostedZoneID': lb_Hosted_zone_ID,
				'DNSName': lb_dns_name
			}

			required_lb_details.append(lb_details)

		insert_lb_details(required_lb_details)

	except Exception as e:
		return str(e)

def filtered_sg_details():
	try:
		required_sg_details = []
		security_group_details = []

		# Function to fetch and segregate security group details
		
		for val in multi_account:
			try:
				sts = master_session.client('sts')
				role = f'arn:aws:iam::{val}:role/MemberRole2'
				assumed_role = sts.assume_role(
					RoleArn=role,
					RoleSessionName='SessionName'  
				)
				credentials = assumed_role['Credentials']
				assumed_session = boto3.Session(
					aws_access_key_id=credentials['AccessKeyId'],
					aws_secret_access_key=credentials['SecretAccessKey'],
					aws_session_token=credentials['SessionToken'],
					region_name='us-east-1' 
				)

				for region in all_regions:
					security_group = get_security_group_details(assumed_session, region)
					security_group_details.extend(security_group)

			except Exception as e:
				print(f"Error Role to this account is not Attached {val} : {str(e)}")
		
		for sg in security_group_details:
			sg_name = sg['GroupName']
			sg_id = sg['GroupId']
			sg_state = ''

			details = {
				'Name': sg_name,
				'Id': sg_id,
				'State' : sg_state
			}

			required_sg_details.append(details)

		insert_sg_details(required_sg_details)

	except Exception as e:
		return str(e)

def filtered_images_details():
	try:
		required_images_details = []
		images_details = []

		# Function to fetch and segregate security group details
		
		for val in multi_account:
			try:
				sts = master_session.client('sts')
				role = f'arn:aws:iam::{val}:role/MemberRole2'
				assumed_role = sts.assume_role(
					RoleArn=role,
					RoleSessionName='SessionName'  
				)
				credentials = assumed_role['Credentials']
				assumed_session = boto3.Session(
					aws_access_key_id=credentials['AccessKeyId'],
					aws_secret_access_key=credentials['SecretAccessKey'],
					aws_session_token=credentials['SessionToken'],
					region_name='us-east-1' 
				)

				for region in all_regions:
					images = get_images_details(assumed_session, region)
					images_details.extend(images)

			except Exception as e:
				print(f"Error Role to this account is not Attached {val} : {str(e)}")

		for image in images_details:
			Name = image['Name']
			objectId = image['ImageId']
			os = image['PlatformDetails']
			deviceType = image['RootDeviceType']
			type = image['ImageType']
			source = image['ImageLocation']
			key = ''
			hostName = ''

			details = {
				'Name' : Name,
				'ObjectID' : objectId,
				'OS' : os,
				'DeviceType': deviceType,
				'Type' : type,
				'location' : source,
				'Key': key,
				'HostName' : hostName
			}
			required_images_details.append(details)

		insert_image_deatils(required_images_details)

	except Exception as e:
		return str(e)

def filtered_hw_details():
	try:
		required_hardware_details = []
		all_hardware_details = []

		
		for val in multi_account:
			try:
				sts = master_session.client('sts')
				role = f'arn:aws:iam::{val}:role/MemberRole2'
				assumed_role = sts.assume_role(
					RoleArn=role,
					RoleSessionName='SessionName'  
				)
				credentials = assumed_role['Credentials']
				assumed_session = boto3.Session(
					aws_access_key_id=credentials['AccessKeyId'],
					aws_secret_access_key=credentials['SecretAccessKey'],
					aws_session_token=credentials['SessionToken'],
					region_name='us-east-1' 
				)

				for region in all_regions:
					hardware = get_all_hardware_details(assumed_session, region)
					all_hardware_details.extend(hardware)

			except Exception as e:
				print(f"Error Role to this account is not Attached {val} : {str(e)}")

	
		for hw in all_hardware_details:
			hw_name = hw['InstanceType']
			hw_vcpu = hw['VCpuInfo']['DefaultVCpus']
			hw_memory = hw['MemoryInfo']['SizeInMiB']
			if (hw['InstanceStorageSupported'] == True) :
				hw_storage = hw['InstanceStorageInfo']['TotalSizeInGB']
			else:
				hw_storage = ''

			details = {
				'Name' : hw_name,
				'Vcpu' : hw_vcpu,
				'Memory' : hw_memory,
				'Storage' : hw_storage
			}

			required_hardware_details.append(details)
		
		insert_hw_details(required_hardware_details)

	except Exception as e:
		return str(e)

def filtered_cld_key_pair_details():
	try:
		required_key = []
		key_pair_dtls = []

		for val in multi_account:
			try:
				sts = master_session.client('sts')
				role = f'arn:aws:iam::{val}:role/MemberRole2'
				assumed_role = sts.assume_role(
					RoleArn=role,
					RoleSessionName='SessionName'  
				)
				credentials = assumed_role['Credentials']
				assumed_session = boto3.Session(
					aws_access_key_id=credentials['AccessKeyId'],
					aws_secret_access_key=credentials['SecretAccessKey'],
					aws_session_token=credentials['SessionToken'],
					region_name='us-east-1' 
				)

				for region in all_ec2_regions:
					key_pair = get_cld_key_pair_details(assumed_session, region)
					key_pair_dtls.extend(key_pair)

			except Exception as e:
				print(f"Error Role to this account is not Attached {val} : {str(e)}")

		for kp in key_pair_dtls:
			Name = kp.get('KeyName')
			Object_ID = kp.get('KeyPairId')
			Finger_Print = kp.get('KeyFingerprint')
 
			details = {
				'Name': Name,
				'Object_ID':Object_ID,
				'Finger_Print' : Finger_Print
			}
 
			required_key.append(details)
		
		insert_cloud_keypair_details(required_key)
	except Exception as e:
		print(str(e))
 
def filtered_cloud_db_details():
	try:
		cloud_db_details = []
		cloud_database_details = []
		for val in multi_account:
			try:
				sts = master_session.client('sts')
				role = f'arn:aws:iam::{val}:role/MemberRole2'
				assumed_role = sts.assume_role(
					RoleArn=role,
					RoleSessionName='SessionName'  
				)
				credentials = assumed_role['Credentials']
				assumed_session = boto3.Session(
					aws_access_key_id=credentials['AccessKeyId'],
					aws_secret_access_key=credentials['SecretAccessKey'],
					aws_session_token=credentials['SessionToken'],
					region_name='us-east-1' 
				)
 
				for region in all_regions:
					cloud_db = get_cloud_db_details(assumed_session, region)
					cloud_database_details.extend(cloud_db)
 
			except Exception as e:
				print(f"Error Role to this account is not Attached {val} : {str(e)}")
 
		for res in cloud_database_details:
			try:
				cldDB_name = res['DBName']
			except:
				cldDB_name = ''
			try:
				cldDB_cat = ''
			except:
				cldDB_cat = ''
			try:
				cldDB_ver = res['EngineVersion']
			except:
				cldDB_ver = ''
			try:
				cldDB_class = res['DBInstanceClass']
			except:
				cldDB_class = ''
 
			cld_dtbs_dtls = {
				'Name': cldDB_name,
				'Category':cldDB_cat,
				'Version' : cldDB_ver,
				'Class':cldDB_class
			}
 
			cloud_db_details.append(cld_dtbs_dtls)
		insert_cld_db_details(cloud_db_details)
 
	except Exception as e:
		return str(e)

def filtered_aws_dc_details():
	try:
		# aws_dc_details = []
		# aws_rzn = []
		
		# for val in multi_account:
		# 	try:
		# 		sts = master_session.client('sts')
		# 		role = f'arn:aws:iam::{val}:role/MemberRole2'
		# 		assumed_role = sts.assume_role(
		# 			RoleArn=role,
		# 			RoleSessionName='SessionName'  
		# 		)
		# 		credentials = assumed_role['Credentials']
		# 		assumed_session = boto3.Session(
		# 			aws_access_key_id=credentials['AccessKeyId'],
		# 			aws_secret_access_key=credentials['SecretAccessKey'],
		# 			aws_session_token=credentials['SessionToken'],
		# 			region_name='us-east-1' 
		# 		)

		# 		for region in all_regions:
		# 			rzn_list = get_aws_dc_details(assumed_session, region)
		# 			aws_rzn.extend(rzn_list)

		# 	except Exception as e:
		# 		print(f"Error Role to this account is not Attached {val} : {str(e)}")

	
		# print()
		# print("aws_rzn--- ",aws_rzn)
		# for rzn in aws_rzn:
		# 	print("========================================")
		# 	print("rzn---------> ",rzn)
		# 	print()
		# 	rzn_name = rzn
		# 	disc_sts = ''
		# 	# rzn_class = ''

		# 	details = {
		# 		'Name': rzn_name,
		# 		'Region':region,
		# 		'Discovery Status' : disc_sts,
		# 		'Class':"AWS Datacenter"
		# 	}
		# 	print()
		# 	print("aws_dc_details---> ",aws_dc_details)
		# 	aws_dc_details.append(details)
		all_dc_regions = master_session.get_available_regions('ec2')
		print(all_dc_regions)
		insert_aws_dc_details(all_dc_regions)

	except Exception as e:
		return str(e)

def filtered_az_details():
	try:
		avail_zones_details = []
		avlbl_zones = []

		
		for val in multi_account:
			try:
				sts = master_session.client('sts')
				role = f'arn:aws:iam::{val}:role/MemberRole2'
				assumed_role = sts.assume_role(
					RoleArn=role,
					RoleSessionName='SessionName'  
				)
				credentials = assumed_role['Credentials']
				assumed_session = boto3.Session(
					aws_access_key_id=credentials['AccessKeyId'],
					aws_secret_access_key=credentials['SecretAccessKey'],
					aws_session_token=credentials['SessionToken'],
					region_name='us-east-1' 
				)

				for region in all_regions:
					avl_zone = get_az_details(assumed_session, region)
					avlbl_zones.extend(avl_zone)

			except Exception as e:
				print(f"Error Role to this account is not Attached {val} : {str(e)}")

	
		for az in avlbl_zones:
			name = az['ZoneName']

			details = {
				'Name': name
				}

			avail_zones_details.append(details)
		
		insert_az_details(avail_zones_details)

	except Exception as e:
		return str(e)

def filtered_strg_vol_details():
	try:
		strg_vol_details = []
		strg_vol_dtls = []

		
		for val in multi_account:
			try:
				sts = master_session.client('sts')
				role = f'arn:aws:iam::{val}:role/MemberRole2'
				assumed_role = sts.assume_role(
					RoleArn=role,
					RoleSessionName='SessionName'  
				)
				credentials = assumed_role['Credentials']
				assumed_session = boto3.Session(
					aws_access_key_id=credentials['AccessKeyId'],
					aws_secret_access_key=credentials['SecretAccessKey'],
					aws_session_token=credentials['SessionToken'],
					region_name='us-east-1' 
				)

				for region in all_regions:
					strg_vol = get_strg_vol_details(assumed_session, region)
					strg_vol_dtls.extend(strg_vol)

			except Exception as e:
				print(f"Error Role to this account is not Attached {val} : {str(e)}")

	
		for sv in strg_vol_dtls:
			name = ''
			obj_id = ''
			state = sv['State']
			size = sv['Size']
			strg_type = ''

			details = {
				'Name': name,
				'Object_ID':obj_id,
				'State' : state,
				'Size':size,
				'Storage_Type':strg_type
			}

			strg_vol_details.append(details)
		
		insert_strg_vol_details(strg_vol_details)

	except Exception as e:
		return str(e)

def filtered_strg_map_details():
	try:
		storage_mapping_data = []
		strg_map_dtls = []

		
		for val in multi_account:
			try:
				sts = master_session.client('sts')
				role = f'arn:aws:iam::{val}:role/MemberRole2'
				assumed_role = sts.assume_role(
					RoleArn=role,
					RoleSessionName='SessionName'  
				)
				credentials = assumed_role['Credentials']
				assumed_session = boto3.Session(
					aws_access_key_id=credentials['AccessKeyId'],
					aws_secret_access_key=credentials['SecretAccessKey'],
					aws_session_token=credentials['SessionToken'],
					region_name='us-east-1' 
				)

				for region in all_regions:
					strg_map = get_strg_map_details(assumed_session, region)
					strg_map_dtls.extend(strg_map)

			except Exception as e:
				print(f"Error Role to this account is not Attached {val} : {str(e)}")

	
		for mp in strg_map_dtls:
			name = mp['VolumeId']
			obj_id = mp['VolumeId']
			map_type = ''
			host = ''
			mount_point = mp['Attachments'][0]['Device']

			details = {
				'Name': name,
				'Object_ID':obj_id,
				'Mapping_Type' : map_type,
				'Host':host,
				'Mount_Point':mount_point
			}

			storage_mapping_data.append(details)
		
		insert_strg_map_details(storage_mapping_data)

	except Exception as e:
		return str(e)

def filtered_ip_details():
	try:
		ip_details = []

		# Function to fetch and segregate ip details
		
		for val in multi_account:
			try:
				sts = master_session.client('sts')
				role = f'arn:aws:iam::{val}:role/MemberRole2'
				assumed_role = sts.assume_role(
					RoleArn=role,
					RoleSessionName='SessionName'  
				)
				credentials = assumed_role['Credentials']
				assumed_session = boto3.Session(
					aws_access_key_id=credentials['AccessKeyId'],
					aws_secret_access_key=credentials['SecretAccessKey'],
					aws_session_token=credentials['SessionToken'],
					region_name='us-east-1' 
				)

				for region in all_ec2_regions:
					ip = get_public_ip_addresses(assumed_session, region)
					ip_details.extend(ip)

			except Exception as e:
				print(f"Error Role to this account is not Attached {val} : {str(e)}")

		insert_ip_deatils(ip_details)

	except Exception as e:
		return str(e)

def filter_logical_datacenter_details():
	try:
		dc_details = []
		# Function to fetch and segregate Logical Datacenter details
		
		for val in multi_account:
			try:
				sts = master_session.client('sts')
				role = f'arn:aws:iam::{val}:role/MemberRole2'
				assumed_role = sts.assume_role(
					RoleArn=role,
					RoleSessionName='SessionName'  
				)
				credentials = assumed_role['Credentials']
				assumed_session = boto3.Session(
					aws_access_key_id=credentials['AccessKeyId'],
					aws_secret_access_key=credentials['SecretAccessKey'],
					aws_session_token=credentials['SessionToken'],
					region_name='us-east-1' 
				)

				for region in all_ec2_regions:
					dc = get_datacenter_details(assumed_session, region)
					dc_details.extend(dc)

			except Exception as e:
				print(f"Error Role to this account is not Attached {val} : {str(e)}")

		insert_logical_datacenter_deatils(dc_details)

	except Exception as e:
		return str(e)

def filter_lb_publicIp():
	try:
		all_lb_details = []
		required_lb_details = []
		# Function to fetch and segregate Logical Datacenter details
		
		for val in multi_account:
			try:

				sts = master_session.client('sts')
				role = f'arn:aws:iam::{val}:role/MemberRole2'
				assumed_role = sts.assume_role(
					RoleArn=role,
					RoleSessionName='SessionName'  
				)
				credentials = assumed_role['Credentials']
				assumed_session = boto3.Session(
					aws_access_key_id=credentials['AccessKeyId'],
					aws_secret_access_key=credentials['SecretAccessKey'],
					aws_session_token=credentials['SessionToken'],
					region_name='us-east-1' 
				)

				for region in all_regions:
					lb = get_load_balancer_details(assumed_session, region)
					all_lb_details.extend(lb)

			except Exception as e:
				print(f"Error Role to this account is not Attached {val} : {str(e)}")

		for lb in all_lb_details:
			name = lb['LoadBalancerName']
			IpType = lb['IpAddressType']

			details = {
				'Name' : name,
				'IpAddressType' : IpType
			}

			required_lb_details.append(details)

		insert_lbIp_deatils(required_lb_details)
	except Exception as e:
			return str(e)

def filter_lb_service():
	try:
		all_lb_details = []
		required_lb_details = []
		# Function to fetch and segregate Logical Datacenter details
		
		for val in multi_account:
			try:
				sts = master_session.client('sts')
				role = f'arn:aws:iam::{val}:role/MemberRole2'
				assumed_role = sts.assume_role(
					RoleArn=role,
					RoleSessionName='SessionName'  
				)
				credentials = assumed_role['Credentials']
				assumed_session = boto3.Session(
					aws_access_key_id=credentials['AccessKeyId'],
					aws_secret_access_key=credentials['SecretAccessKey'],
					aws_session_token=credentials['SessionToken'],
					region_name='us-east-1' 
				)

				for region in all_regions:
					lb = get_load_balancer_details(assumed_session, region)
					all_lb_details.extend(lb)

			except Exception as e:
				print(f"Error Role to this account is not Attached {val} : {str(e)}")

		for lb in all_lb_details:
			name = lb['LoadBalancerName']
			IPAddress = ''
			port = ''
			inputUrl = ''
			Class = 'Load Balancer Service'
			lb = lb['LoadBalancerName']
			discovery = ''

			details = {
				'Name' : name,
				'IpAddress' : IPAddress,
				'Port' : port,
				'InputUrl' : inputUrl,
				'Class' : Class,
				'LoadBalancer' : lb,
				'Discovery' : discovery
			}

			required_lb_details.append(details)

		insert_lb_service_deatils(required_lb_details)
		
	except Exception as e:
			return str(e)

def filtered_vm_instance_details():
	try:
		vm_instance_details = []
		vm_instance = []

		
		for val in multi_account:
			try:
				sts = master_session.client('sts')
				role = f'arn:aws:iam::{val}:role/MemberRole2'
				assumed_role = sts.assume_role(
					RoleArn=role,
					RoleSessionName='SessionName'  
				)
				credentials = assumed_role['Credentials']
				assumed_session = boto3.Session(
					aws_access_key_id=credentials['AccessKeyId'],
					aws_secret_access_key=credentials['SecretAccessKey'],
					aws_session_token=credentials['SessionToken'],
					region_name='us-east-1' 
				)

				for region in all_regions:
					vm_ins = get_vm_instance_details(assumed_session, region)
					vm_instance.append(vm_ins)

			except Exception as e:
				print(f"Error Role to this account is not Attached {val} : {str(e)}")


		for reservation in vm_instance:
			for res in reservation:
				if res['Instances']:
					for instance in res['Instances']:
						try:
							name = instance['KeyName']
						except:
							name = ""

						try:
							region = instance['Placement']['AvailabilityZone']
						except:
							region = ""

						try:
							vm_id = instance['InstanceId']
						except:
							vm_id = ""
						network_interfaces = instance.get('NetworkInterfaces', [])
						for network_interface in network_interfaces:
							owner_id = network_interface.get('OwnerId', None)
						Object = instance['InstanceId']
						public_ip = ""

						details = {
							'Name': name,
							'Aws_Account_id': owner_id,
							'Provider': "AWS",
							'region': region,
							'Instanceid': vm_id,
							'ObjectID' : Object,
							'Ip_Address': public_ip
							}

						vm_instance_details.append(details)

		insert_vm_instance_details(vm_instance_details)

	except Exception as e:
		return str(e)


def insert_vpc_details(vpc_details):
	try:
		connection = pymysql.connect(host=db_host, user=db_user, password=db_pass, db=db_name, cursorclass=pymysql.cursors.DictCursor)
		table_name = 'cmdb_ci_network'
		cursor =  connection.cursor() 

		current_date = datetime.now()
		current_time = datetime.now().strftime("%H:%M:%S")
		previous_date = (current_date - timedelta(days=1)).strftime("%d-%m-%Y")
		# print(previous_date)

		show_table = f"SHOW TABLES LIKE '{table_name}'"
		cursor.execute(show_table)
		tb = cursor.fetchone() 
		if tb:
			rename_table_query = f"ALTER TABLE `{table_name}` RENAME TO `{table_name}_{previous_date}_{current_time}`"
			cursor.execute(rename_table_query)

		
		create_table = """
			CREATE TABLE IF NOT EXISTS cmdb_ci_network (
				Name varchar(50),
				State varchar(50),
				Object_ID varchar(50),
				CIDR varchar(50) 
			);"""
		 
		cursor.execute(create_table)

		for vpc in vpc_details:
			print(vpc)
			insert_query = """
				INSERT INTO cmdb_ci_network (Name, State, Object_ID, CIDR)
				VALUES (%s, %s, %s, %s);
			"""

			try:
				cursor.execute(insert_query, (vpc['Name'], vpc['State'], vpc['Id'], vpc['Cidr']))
			
			except pymysql.Error as e:
				print(f"Error: {e}")
		
		connection.commit()
		connection.close()

	except Exception as e:
		raise Exception(f"Error inserting data into RDS: {str(e)}")

def insert_subnet_details(subnet_details):
	try:
		connection = pymysql.connect(host=db_host, user=db_user, password=db_pass, db=db_name, cursorclass=pymysql.cursors.DictCursor)
		table_name = 'cmdb_ci_cloud_subnet'

		cursor = connection.cursor() 

		current_date = datetime.now()
		current_time = datetime.now().strftime("%H:%M:%S")
		previous_date = (current_date - timedelta(days=1)).strftime("%d-%m-%Y")
		# print(previous_date)

		show_table = f"SHOW TABLES LIKE '{table_name}'"
		cursor.execute(show_table)
		tb = cursor.fetchone() 
		if tb:
			rename_table_query = f"ALTER TABLE `{table_name}` RENAME TO `{table_name}_{previous_date}_{current_time}`"
			cursor.execute(rename_table_query)

		create_table = """
			CREATE TABLE IF NOT EXISTS cmdb_ci_cloud_subnet (
				Name varchar(50),
				State varchar(50),
				Object_ID varchar(50),
				CIDR varchar(50) 
			);"""
		
		cursor.execute(create_table)


		for sb in subnet_details:
			print(sb)
			insert_query = """
				INSERT INTO cmdb_ci_cloud_subnet (Name, State, Object_ID, CIDR)
				VALUES (%s, %s, %s, %s);
			"""

			try:
				cursor.execute(insert_query, (sb['Name'], sb['State'], sb['Id'], sb['Cidr']))
			
			except pymysql.Error as e:
				print(f"Error: {e}")
		
		connection.commit()
		connection.close()

	except Exception as e:
		raise Exception(f"Error inserting data into RDS: {str(e)}")

def insert_lb_details(elb_details):
	try:
		connection = pymysql.connect(host=db_host, user=db_user, password=db_pass, db=db_name, cursorclass=pymysql.cursors.DictCursor)
		table_name = 'cmdb_ci_cloud_load_balancer'

		cursor = connection.cursor() 

		current_date = datetime.now()
		current_time = datetime.now().strftime("%H:%M:%S")
		previous_date = (current_date - timedelta(days=1)).strftime("%d-%m-%Y")
		# print(previous_date)

		show_table = f"SHOW TABLES LIKE '{table_name}'"
		cursor.execute(show_table)
		tb = cursor.fetchone() 
		if tb:
			rename_table_query = f"ALTER TABLE `{table_name}` RENAME TO `{table_name}_{previous_date}_{current_time}`"
			cursor.execute(rename_table_query)

		create_table = """
			CREATE TABLE IF NOT EXISTS cmdb_ci_cloud_load_balancer (
				Name varchar(50),
				Object_ID varchar(50),
				State varchar(50),
				Canonical_Hosted_Zone_Name varchar(50),
				Canonical_Hosted_Zone_ID varchar(50),
				DNS_Name varchar(100)
			);"""
		
		cursor.execute(create_table)


		for elb in elb_details:
			print(elb)
			insert_query = """
				INSERT INTO cmdb_ci_cloud_load_balancer (Name, Object_ID, State, Canonical_Hosted_Zone_Name, Canonical_Hosted_Zone_ID, DNS_Name)
				VALUES (%s, %s, %s, %s, %s, %s);
			"""

			try:
				cursor.execute(insert_query, (elb['Name'], elb['ObjectID'], elb['State'], elb['HostedZoneName'], elb['HostedZoneID'], elb['DNSName']))
			
			except pymysql.Error as e:
				print(f"Error: {e}")
		
		connection.commit()
		connection.close()

	except Exception as e:
		raise Exception(f"Error inserting data into RDS: {str(e)}")

def insert_sg_details(sg_details):
	try:
		connection = pymysql.connect(host=db_host, user=db_user, password=db_pass, db=db_name, cursorclass=pymysql.cursors.DictCursor)
		table_name = 'cmdb_ci_compute_security_group'
		cursor =  connection.cursor() 

		current_date = datetime.now()
		current_time = datetime.now().strftime("%H:%M:%S")
		previous_date = (current_date - timedelta(days=1)).strftime("%d-%m-%Y")
		# print(previous_date)

		show_table = f"SHOW TABLES LIKE '{table_name}'"
		cursor.execute(show_table)
		tb = cursor.fetchone() 
		if tb:
			rename_table_query = f"ALTER TABLE `{table_name}` RENAME TO `{table_name}_{previous_date}_{current_time}`"
			cursor.execute(rename_table_query)

		
		create_table = """
			CREATE TABLE IF NOT EXISTS cmdb_ci_compute_security_group (
				Name varchar(50),
				Object_ID varchar(50),
				State varchar(50)
			);"""
		 
		cursor.execute(create_table)

		for sg in sg_details:
			print(sg)
			insert_query = """
				INSERT INTO cmdb_ci_compute_security_group (Name, Object_ID, State)
				VALUES (%s, %s, %s);
			"""

			try:
				cursor.execute(insert_query, (sg['Name'], sg['Id'], sg['State']))
			
			except pymysql.Error as e:
				print(f"Error: {e}")
		
		connection.commit()
		connection.close()

	except Exception as e:
		raise Exception(f"Error inserting data into RDS: {str(e)}")

def insert_hw_details(hw_details):
	try:
		connection = pymysql.connect(host=db_host, user=db_user, password=db_pass, db=db_name, cursorclass=pymysql.cursors.DictCursor)
		table_name = 'cmdb_ci_compute_template'
		cursor =  connection.cursor() 

		current_date = datetime.now()
		current_time = datetime.now().strftime("%H:%M:%S")
		previous_date = (current_date - timedelta(days=1)).strftime("%d-%m-%Y")
		# print(previous_date)

		show_table = f"SHOW TABLES LIKE '{table_name}'"
		cursor.execute(show_table)
		tb = cursor.fetchone() 
		if tb:
			rename_table_query = f"ALTER TABLE `{table_name}` RENAME TO `{table_name}_{previous_date}_{current_time}`"
			cursor.execute(rename_table_query)

		
		create_table = """
			CREATE TABLE IF NOT EXISTS cmdb_ci_compute_template (
				Name varchar(50),
				vCPUs varchar(50),
				Memory_MB varchar(50),
				Local_Storage_GB varchar(50) 
			);"""
		 
		cursor.execute(create_table)

		for hw in hw_details:
			print(hw)
			insert_query = """
				INSERT INTO cmdb_ci_compute_template (Name, vCPUs, Memory_MB, Local_Storage_GB)
				VALUES (%s, %s, %s, %s);
			"""

			try:
				cursor.execute(insert_query, (hw['Name'], hw['Vcpu'], hw['Memory'], hw['Storage']))
			
			except pymysql.Error as e:
				print(f"Error: {e}")
		
		connection.commit()
		connection.close()

	except Exception as e:
		raise Exception(f"Error inserting data into RDS: {str(e)}")

def insert_service_account_details(service_details):
	try:
		connection = pymysql.connect(host=db_host, user=db_user, password=db_pass, db=db_name, cursorclass=pymysql.cursors.DictCursor)
		table_name = 'cmdb_ci_cloud_service_account'

		cursor = connection.cursor() 

		current_date = datetime.now()
		current_time = datetime.now().strftime("%H:%M:%S")
		previous_date = (current_date - timedelta(days=1)).strftime("%d-%m-%Y")
		# print(previous_date)

		show_table = f"SHOW TABLES LIKE '{table_name}'"
		cursor.execute(show_table)
		tb = cursor.fetchone() 
		if tb:
			rename_table_query = f"ALTER TABLE `{table_name}` RENAME TO `{table_name}_{previous_date}_{current_time}`"
			cursor.execute(rename_table_query)

		create_table = """
			CREATE TABLE IF NOT EXISTS cmdb_ci_cloud_service_account (
				Name varchar(50),
				Account_Id varchar(50),
				Discovery_credentials varchar(50),
				Datacenter_Type varchar(50),
				Datacenter_URL varchar(50),
				Parent_Account varchar(50),
				Is_master_account varchar(50)
			);
			"""
		
		cursor.execute(create_table)


		for sv in service_details:
			print(sv)
			insert_query = """
				INSERT INTO cmdb_ci_cloud_service_account (Name, Account_Id, Discovery_credentials, Datacenter_Type, Datacenter_URL, Parent_Account, Is_master_account )
				VALUES (%s, %s, %s, %s, %s, %s, %s);
			"""

			try:
				cursor.execute(insert_query, (sv['Name'], sv['Account Id'], sv['Discovery Credential'], sv['Datacenter Type'], sv['Datcenter URL'], 
											  sv['Parent Account'], sv['Is Master Account']))
			
			except pymysql.Error as e:
				print(f"Error: {e}")
		
		connection.commit()
		connection.close()

	except Exception as e:
		raise Exception(f"Error inserting data into RDS: {str(e)}")
	
def insert_cloud_keypair_details(keypair):
	try:
		connection = pymysql.connect(host=db_host, user=db_user, password=db_pass, db=db_name, cursorclass=pymysql.cursors.DictCursor)
		table_name = 'cmdb_ci_cloud_key_pair'

		cursor = connection.cursor() 

		current_date = datetime.now()
		current_time = datetime.now().strftime("%H:%M:%S")
		previous_date = (current_date - timedelta(days=1)).strftime("%d-%m-%Y")
		# print(previous_date)

		show_table = f"SHOW TABLES LIKE '{table_name}'"
		cursor.execute(show_table)
		tb = cursor.fetchone() 
		if tb:
			rename_table_query = f"ALTER TABLE `{table_name}` RENAME TO `{table_name}_{previous_date}_{current_time}`"
			cursor.execute(rename_table_query)

		create_table ="""
			CREATE TABLE IF NOT EXISTS cmdb_ci_cloud_key_pair (
				Name varchar(50),
				Object_ID varchar(50),
				Finger_Print varchar(150)
			);"""
		
		cursor.execute(create_table)


		for kp in keypair:
			print()
			print("kp---> ",kp)
			try:
				insert_query = """
					INSERT INTO cmdb_ci_cloud_key_pair (Name, Object_ID, Finger_Print)
					VALUES (%s, %s, %s);
				"""
				
				cursor.execute(insert_query, (kp['Name'], kp['Object_ID'], kp['Finger_Print']))
			except pymysql.Error as e:
				print(f"Error: {e}")
		
		connection.commit()
		connection.close()

	except Exception as e:
		raise Exception(f"Error inserting data into RDS: {str(e)}")

def insert_cloud_ip_details(keypair):
	try:
		connection = pymysql.connect(host=db_host, user=db_user, password=db_pass, db=db_name, cursorclass=pymysql.cursors.DictCursor)
		table_name = 'cmdb_ci_cloud_public_ipaddress'

		cursor = connection.cursor() 

		current_date = datetime.now()
		current_time = datetime.now().strftime("%H:%M:%S")
		previous_date = (current_date - timedelta(days=1)).strftime("%d-%m-%Y")
		# print(previous_date)

		show_table = f"SHOW TABLES LIKE '{table_name}'"
		cursor.execute(show_table)
		tb = cursor.fetchone() 
		if tb:
			rename_table_query = f"ALTER TABLE `{table_name}` RENAME TO `{table_name}_{previous_date}_{current_time}`"
			cursor.execute(rename_table_query)

		create_table ="""
			CREATE TABLE IF NOT EXISTS cmdb_ci_cloud_key_pair (
				Name varchar(50),
				Object_ID varchar(50),
				Finger_Print varchar(50)
			);"""
		
		cursor.execute(create_table)


		for kp in keypair:
			print()
			print("kp---> ",kp)
			try:
				insert_query = """
					INSERT INTO cmdb_ci_cloud_key_pair (Name, Object_ID, Finger_Print)
					VALUES (%s, %s, %s);
				"""
				
				cursor.execute(insert_query, (kp['Name'], kp['Object_ID'], kp['Finger_Print']))
			except pymysql.Error as e:
				print(f"Error: {e}")
		
		connection.commit()
		connection.close()

	except Exception as e:
		raise Exception(f"Error inserting data into RDS: {str(e)}")

def insert_cld_db_details(cld_db_details):
	try:
		connection = pymysql.connect(host=db_host, user=db_user, password=db_pass, db=db_name, cursorclass=pymysql.cursors.DictCursor)
		table_name = 'cmdb_ci_cloud_database'
		cursor =  connection.cursor() 

		current_date = datetime.now()
		current_time = datetime.now().strftime("%H:%M:%S")
		previous_date = (current_date - timedelta(days=1)).strftime("%d-%m-%Y")
		# print(previous_date)

		show_table = f"SHOW TABLES LIKE '{table_name}'"
		cursor.execute(show_table)
		tb = cursor.fetchone() 
		if tb:
			rename_table_query = f"ALTER TABLE `{table_name}` RENAME TO `{table_name}_{previous_date}_{current_time}`"
			cursor.execute(rename_table_query)

		
		create_table = """
			CREATE TABLE IF NOT EXISTS cmdb_ci_cloud_database (
				Name varchar(50),
				Category varchar(50),
				Version varchar(50),
				Class varchar(50)
			);"""
		 
		cursor.execute(create_table)

		for cldb in cld_db_details:
			print(cldb)
			insert_query = """
				INSERT INTO cmdb_ci_cloud_database (Name, Category, Version, Class)
				VALUES (%s, %s, %s, %s);
			"""

			try:
				cursor.execute(insert_query, (cldb['Name'], cldb['Category'], cldb['Version'], cldb['Class']))
			
			except pymysql.Error as e:
				print(f"Error: {e}")
		
		connection.commit()
		connection.close()

	except Exception as e:
		raise Exception(f"Error inserting data into RDS: {str(e)}")

def insert_aws_dc_details(aws_dc_details):
	try:
		connection = pymysql.connect(host=db_host, user=db_user, password=db_pass, db=db_name, cursorclass=pymysql.cursors.DictCursor)
		table_name = 'cmdb_ci_aws_datacenter'
		cursor =  connection.cursor() 

		current_date = datetime.now()
		current_time = datetime.now().strftime("%H:%M:%S")
		previous_date = (current_date - timedelta(days=1)).strftime("%d-%m-%Y")
		# print(previous_date)

		show_table = f"SHOW TABLES LIKE '{table_name}'"
		cursor.execute(show_table)
		tb = cursor.fetchone() 
		if tb:
			rename_table_query = f"ALTER TABLE `{table_name}` RENAME TO `{table_name}_{previous_date}_{current_time}`"
			cursor.execute(rename_table_query)

		
		create_table = """
			CREATE TABLE IF NOT EXISTS cmdb_ci_aws_datacenter (
				Name varchar(50),
				Region varchar(50),
				Discovery_Status varchar(50),
				Class varchar(50)
			);"""
		 
		cursor.execute(create_table)

		for dc in aws_dc_details:
			print(dc)
			Discovery_Status = ''
			Class = "AWS Datacenter"

			insert_query = """
				INSERT INTO cmdb_ci_aws_datacenter (Name, Region, Discovery_Status, Class)
				VALUES (%s, %s, %s, %s);
			"""

			try:
				cursor.execute(insert_query, (dc, dc, Discovery_Status, Class))
			
			except pymysql.Error as e:
				print(f"Error: {e}")
		
		connection.commit()
		connection.close()

	except Exception as e:
		raise Exception(f"Error inserting data into RDS: {str(e)}")

def insert_az_details(az_details):
	try:
		connection = pymysql.connect(host=db_host, user=db_user, password=db_pass, db=db_name, cursorclass=pymysql.cursors.DictCursor)
		table_name = 'cmdb_ci_availability_zone'
		cursor =  connection.cursor() 

		current_date = datetime.now()
		current_time = datetime.now().strftime("%H:%M:%S")
		previous_date = (current_date - timedelta(days=1)).strftime("%d-%m-%Y")
		# print(previous_date)

		show_table = f"SHOW TABLES LIKE '{table_name}'"
		cursor.execute(show_table)
		tb = cursor.fetchone() 
		if tb:
			rename_table_query = f"ALTER TABLE `{table_name}` RENAME TO `{table_name}_{previous_date}_{current_time}`"
			cursor.execute(rename_table_query)

		
		create_table = """
			CREATE TABLE IF NOT EXISTS cmdb_ci_availability_zone (
				Name varchar(50) 
			);"""
		 
		cursor.execute(create_table)

		for az in az_details:
			print(az)
			insert_query = """
				INSERT INTO cmdb_ci_availability_zone (Name)
				VALUES (%s);
			"""

			try:
				cursor.execute(insert_query, (az['Name']))
			
			except pymysql.Error as e:
				print(f"Error: {e}")
		
		connection.commit()
		connection.close()

	except Exception as e:
		raise Exception(f"Error inserting data into RDS: {str(e)}")

def insert_strg_vol_details(strg_vol_details):
	try:
		connection = pymysql.connect(host=db_host, user=db_user, password=db_pass, db=db_name, cursorclass=pymysql.cursors.DictCursor)
		table_name = 'cmdb_ci_storage_volume'
		cursor =  connection.cursor() 

		current_date = datetime.now()
		current_time = datetime.now().strftime("%H:%M:%S")
		previous_date = (current_date - timedelta(days=1)).strftime("%d-%m-%Y")
		# print(previous_date)

		show_table = f"SHOW TABLES LIKE '{table_name}'"
		cursor.execute(show_table)
		tb = cursor.fetchone() 
		if tb:
			rename_table_query = f"ALTER TABLE `{table_name}` RENAME TO `{table_name}_{previous_date}_{current_time}`"
			cursor.execute(rename_table_query)

		
		create_table = """
			CREATE TABLE IF NOT EXISTS cmdb_ci_storage_volume (
				Name varchar(50),
				Object_ID varchar(50),
				State varchar(50),
				Size varchar(50),
				Storage_type varchar(50)
			);"""
		 
		cursor.execute(create_table)

		for vol in strg_vol_details:
			print(vol)
			insert_query = """
				INSERT INTO cmdb_ci_storage_volume (Name, Object_ID, State, Size, Storage_Type)
				VALUES (%s, %s, %s, %s, %s);
			"""

			try:
				cursor.execute(insert_query, (vol['Name'], vol['Object_ID'], vol['State'], vol['Size'], vol['Storage_Type']))
			
			except pymysql.Error as e:
				print(f"Error: {e}")
		
		connection.commit()
		connection.close()

	except Exception as e:
		raise Exception(f"Error inserting data into RDS: {str(e)}")

def insert_strg_map_details(strg_map_details):
	try:
		connection = pymysql.connect(host=db_host, user=db_user, password=db_pass, db=db_name, cursorclass=pymysql.cursors.DictCursor)
		table_name = 'cmdb_ci_storage_mapping'
		cursor =  connection.cursor() 

		current_date = datetime.now()
		current_time = datetime.now().strftime("%H:%M:%S")
		previous_date = (current_date - timedelta(days=1)).strftime("%d-%m-%Y")
		# print(previous_date)

		show_table = f"SHOW TABLES LIKE '{table_name}'"
		cursor.execute(show_table)
		tb = cursor.fetchone() 
		if tb:
			rename_table_query = f"ALTER TABLE `{table_name}` RENAME TO `{table_name}_{previous_date}_{current_time}`"
			cursor.execute(rename_table_query)

		
		create_table = """
			CREATE TABLE IF NOT EXISTS cmdb_ci_storage_mapping (
				Name varchar(50),
				Object_ID varchar(50),
				Mapping_Type varchar(50),
				Host varchar(50),
				Mount_Point varchar(50) 
			);"""
		 
		cursor.execute(create_table)

		for mp in strg_map_details:
			print(mp)
			insert_query = """
				INSERT INTO cmdb_ci_storage_mapping (Name, Object_ID, Mapping_Type, Host, Mount_Point)
				VALUES (%s, %s, %s, %s, %s);
			"""

			try:
				cursor.execute(insert_query, (mp['Name'], mp['Object_ID'], mp['Mapping_Type'], mp['Host'], mp['Mount_Point']))
			
			except pymysql.Error as e:
				print(f"Error: {e}")
		
		connection.commit()
		connection.close()

	except Exception as e:
		raise Exception(f"Error inserting data into RDS: {str(e)}")

def insert_image_deatils(os_details):
	try:
		connection = pymysql.connect(host=db_host, user=db_user, password=db_pass, db=db_name, cursorclass=pymysql.cursors.DictCursor)

		table_name = 'cmdb_ci_os_template'
		cursor =  connection.cursor() 

		current_date = datetime.now()
		current_time = datetime.now().strftime("%H:%M:%S")
		previous_date = (current_date - timedelta(days=1)).strftime("%d-%m-%Y")
		# print(previous_date)

		show_table = f"SHOW TABLES LIKE '{table_name}'"
		cursor.execute(show_table)
		tb = cursor.fetchone() 
		if tb:
			rename_table_query = f"ALTER TABLE `{table_name}` RENAME TO `{table_name}_{previous_date}_{current_time}`"
			cursor.execute(rename_table_query)

		
		create_table = """
            CREATE TABLE IF NOT EXISTS cmdb_ci_os_template (
                Name varchar(150),
                Object_ID varchar(100),
                Guest_OS varchar(50),
                Root_Device_Type varchar(50),
                Image_Type varchar(50),
                Image_Source varchar(150),
                Infuse_Key varchar(50),
                Update_Host_Name varchar(50)
            );"""

		cursor.execute(create_table)
		
		for os in os_details:
			print(os)
			insert_query = """
				INSERT INTO cmdb_ci_os_template (Name, Object_ID, Guest_OS, Root_Device_Type, Image_Type, Image_Source, Infuse_Key, Update_Host_Name )
				VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
			"""

			try:
				cursor.execute(insert_query, (os['Name'], os['ObjectID'], os['OS'], os['DeviceType'], os['Type'], os['location'], os['Key'], os['HostName']))
			
			except pymysql.Error as e:
				print(f"Error: {e}")
		
		connection.commit()
		connection.close()

	except Exception as e:
		raise Exception(f"Error inserting data into RDS: {str(e)}")

def insert_ip_deatils(ip_details):
	try:
		connection = pymysql.connect(host=db_host, user=db_user, password=db_pass, db=db_name, cursorclass=pymysql.cursors.DictCursor)

		table_name = 'cmdb_ci_cloud_public_ipaddress'
		cursor =  connection.cursor() 

		current_date = datetime.now()
		current_time = datetime.now().strftime("%H:%M:%S")
		previous_date = (current_date - timedelta(days=1)).strftime("%d-%m-%Y")
		# print(previous_date)

		show_table = f"SHOW TABLES LIKE '{table_name}'"
		cursor.execute(show_table)
		tb = cursor.fetchone() 
		if tb:
			rename_table_query = f"ALTER TABLE `{table_name}` RENAME TO `{table_name}_{previous_date}_{current_time}`"
			cursor.execute(rename_table_query)

		
		create_table = """
            CREATE TABLE IF NOT EXISTS cmdb_ci_cloud_public_ipaddress (
                Name varchar(100),
                Public_IP_Address varchar(50),
                Public_DNS varchar(100),
                Object_ID varchar(100)
            );"""

		cursor.execute(create_table)
		
		for ip in ip_details:
			print(ip)
			insert_query = """
				INSERT INTO cmdb_ci_cloud_public_ipaddress (Name, Public_IP_Address, Public_DNS, Object_ID)
				VALUES (%s, %s, %s, %s);
			"""

			try:
				cursor.execute(insert_query, (ip['Name'], ip['PublicIp'], ip['PublicDns'], ip['ObjectId']))
			
			except pymysql.Error as e:
				print(f"Error: {e}")
		
		connection.commit()
		connection.close()

	except Exception as e:
		raise Exception(f"Error inserting data into RDS: {str(e)}")

def insert_logical_datacenter_deatils(dc_details):
	try:
		connection = pymysql.connect(host=db_host, user=db_user, password=db_pass, db=db_name, cursorclass=pymysql.cursors.DictCursor)

		table_name = 'cmdb_ci_logical_datacenter'
		cursor =  connection.cursor() 

		current_date = datetime.now()
		current_time = datetime.now().strftime("%H:%M:%S")
		previous_date = (current_date - timedelta(days=1)).strftime("%d-%m-%Y")
		# print(previous_date)

		show_table = f"SHOW TABLES LIKE '{table_name}'"
		cursor.execute(show_table)
		tb = cursor.fetchone() 
		if tb:
			rename_table_query = f"ALTER TABLE `{table_name}` RENAME TO `{table_name}_{previous_date}_{current_time}`"
			cursor.execute(rename_table_query)

		
		create_table = """
            CREATE TABLE IF NOT EXISTS cmdb_ci_logical_datacenter (
                Name varchar(50),
                Region varchar(50),
                Discovery_Status varchar(50),
                Class varchar(50)
            );"""

		cursor.execute(create_table)
		
		for dc in dc_details:
			print(dc)
			insert_query = """
				INSERT INTO cmdb_ci_logical_datacenter (Name, Region, Discovery_Status, Class)
				VALUES (%s, %s, %s, %s);
			"""

			try:
				cursor.execute(insert_query, (dc['Name'], dc['Region'], dc['DiscoveryStatus'], dc['Class']))
			
			except pymysql.Error as e:
				print(f"Error: {e}")
		
		connection.commit()
		connection.close()

	except Exception as e:
		raise Exception(f"Error inserting data into RDS: {str(e)}")

def insert_lbIp_deatils(lb_details):
	try:
		connection = pymysql.connect(host=db_host, user=db_user, password=db_pass, db=db_name, cursorclass=pymysql.cursors.DictCursor)

		table_name = 'cmdb_ci_cloud_lb_ipaddress'
		cursor =  connection.cursor() 

		current_date = datetime.now()
		current_time = datetime.now().strftime("%H:%M:%S")
		previous_date = (current_date - timedelta(days=1)).strftime("%d-%m-%Y")
		# print(previous_date)

		show_table = f"SHOW TABLES LIKE '{table_name}'"
		cursor.execute(show_table)
		tb = cursor.fetchone() 
		if tb:
			rename_table_query = f"ALTER TABLE `{table_name}` RENAME TO `{table_name}_{previous_date}_{current_time}`"
			cursor.execute(rename_table_query)

		
		create_table = """
            CREATE TABLE IF NOT EXISTS cmdb_ci_cloud_lb_ipaddress (
                Name varchar(50),
                IPAddress_Type varchar(50)
            );"""

		cursor.execute(create_table)
		
		for lb in lb_details:
			print(lb)
			insert_query = """
				INSERT INTO cmdb_ci_cloud_lb_ipaddress (Name, IPAddress_Type)
				VALUES (%s, %s);
			"""

			try:
				cursor.execute(insert_query, (lb['Name'], lb['IpAddressType']))
			
			except pymysql.Error as e:
				print(f"Error: {e}")
		
		connection.commit()

	except Exception as e:
		raise Exception(f"Error inserting data into RDS: {str(e)}")
	
def insert_lb_service_deatils(lb_details):
	try:
		connection = pymysql.connect(host=db_host, user=db_user, password=db_pass, db=db_name, cursorclass=pymysql.cursors.DictCursor)

		table_name = 'cmdb_ci_lb_service'
		cursor =  connection.cursor() 

		current_date = datetime.now()
		current_time = datetime.now().strftime("%H:%M:%S")
		previous_date = (current_date - timedelta(days=1)).strftime("%d-%m-%Y")
		# print(previous_date)

		show_table = f"SHOW TABLES LIKE '{table_name}'"
		cursor.execute(show_table)
		tb = cursor.fetchone() 
		if tb:
			rename_table_query = f"ALTER TABLE `{table_name}` RENAME TO `{table_name}_{previous_date}_{current_time}`"
			cursor.execute(rename_table_query)

		
		create_table = """
            CREATE TABLE IF NOT EXISTS cmdb_ci_lb_service (
                Name varchar(50),
                IP_Address varchar(50),
                Port varchar(50),
                Input_URL varchar(50),
                Class varchar(50),
                Load_balancer varchar(50),
                Most_recent_discovery varchar(50)
            );"""

		cursor.execute(create_table)
		
		for lb in lb_details:
			print(lb)
			insert_query = """
				INSERT INTO cmdb_ci_lb_service (Name, IP_Address, Port, Input_URL, Class, Load_balancer, Most_recent_discovery )
				VALUES (%s, %s, %s, %s, %s, %s, %s);
			"""

			try:
				cursor.execute(insert_query, (lb['Name'], lb['IpAddress'], lb['Port'], lb['InputUrl'], lb['Class'], lb['LoadBalancer'], lb['Discovery']))
			
			except pymysql.Error as e:
				print(f"Error: {e}")
		
		connection.commit()

	except Exception as e:
		raise Exception(f"Error inserting data into RDS: {str(e)}")

def insert_vm_instance_details(vm_ins_details):
	try:
		connection = pymysql.connect(host=db_host, user=db_user, password=db_pass, db=db_name, cursorclass=pymysql.cursors.DictCursor)

		table_name = 'cmdb_ci_vm_instance'
		cursor =  connection.cursor() 

		current_date = datetime.now()
		current_time = datetime.now().strftime("%H:%M:%S")
		previous_date = (current_date - timedelta(days=1)).strftime("%d-%m-%Y")

		show_table = f"SHOW TABLES LIKE '{table_name}'"
		cursor.execute(show_table)
		tb = cursor.fetchone() 
		if tb:
			rename_table_query = f"ALTER TABLE `{table_name}` RENAME TO `{table_name}_{previous_date}_{current_time}`"
			cursor.execute(rename_table_query)

		
		create_table = """
			CREATE TABLE IF NOT EXISTS cmdb_ci_vm_instance (
				Name varchar(50),
				Aws_Account_id varchar(50),
				Provider varchar(50),
				region varchar(50),
				Instanceid varchar(50),
				Object_ID varchar(50),
				Ip_Address varchar(50)
			);"""
		 
		cursor.execute(create_table)

		for vm in vm_ins_details:
			print(vm)
			insert_query = """
				INSERT INTO cmdb_ci_vm_instance (Name, Aws_Account_id, Provider, region, Instanceid, Object_ID, Ip_Address)
				VALUES (%s, %s, %s, %s, %s, %s, %s);
			"""

			try:
				cursor.execute(insert_query, (vm['Name'], vm['Aws_Account_id'], vm['Provider'], vm['region'], vm['Instanceid'], vm['ObjectID'], vm['Ip_Address']))
			
			except pymysql.Error as e:
				print(f"Error: {e}")
		
		connection.commit()

	except Exception as e:
		raise Exception(f"Error inserting vm instances data into rds: {str(e)}")

handler()