import python_terraform
import uuid

#import argparse
from os import path
import sys
curr_path=path.abspath(path.dirname(sys.argv[0]))

#
#parser = argparse.ArgumentParser()
#parser.add_argument("-a", "--apply", action="store_true", help="Create a new gophish infrastructure")
#parser.add_argument('-d','--destroy', nargs='?', help="Destroy a gophish infra (the ec2 uuid has to be given)" )
#args = parser.parse_args()


def get_env():
	t = Terraform()
	return [i[2:] for i in t.cmd('workspace list')[1].split('\n') if i.startswith('ec2_',2)]

def create_uuid():
	return 'ec2_'+str(uuid.uuid4())

def print_env():
	print(*get_env(), sep = "\n")

def deploy_ec2(uuid, path):
	print('------------- Creating : ', uuid,' ----------------')
	t = python_terraform.Terraform(working_dir=path)
	if t.create_workspace(uuid)[0] != 0:
		t.set_workspace(uuid)
	t.apply(path, skip_plan=True ,capture_output=False)
	return t.cmd('output -json public_ip')[1].rstrip("\n").strip("\"") 

def destroy_ec2(uuid, path):
	print('------------- Destroying : ', uuid,' ----------------')
	t = Terraform(working_dir=path)
	if t.set_workspace('tree')[0] == 1:
		t.destroy(path ,capture_output=False)
	else:
		print('Unable to destroy instance, workspace does not exsist.')

def apply_deploy():
	print("++++++++[SBO] CREATING INSTANCE +++++++++++++")
	uuid=create_uuid()
	terraform_path = curr_path + "/terraform/aws"
	ip = deploy_ec2(uuid, terraform_path)
	with open('/tmp/'+uuid+".txt", 'r') as file:
		password = file.read().replace('\n', '')
	text_file = open(ip+"-gophish-pass.txt", "w")
	n = text_file.write(password)
	text_file.close()
	print("Instance created, please connect on port 3333 using admin : "+password+" as credentials")
	print("Once finished, destroy this instance unsing : python3 deploy.py -d "+uuid)


#if args.destroy:
#	destroy_ec2(args.destroy, curr_path + "/terraform/aws")
#if args.apply:
#	apply_deploy()
