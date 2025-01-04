import argparse
import bcrypt
import pickle
import sys
import logging
import uuid
from collections import defaultdict

# Configure logging
logging.basicConfig(filename='access.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

class CanAccess:
    def __init__(self, op, user, obj, setDomain_dict, setType_dict, access, user_groups, group_roles):
        self.op = op
        self.user = user
        self.obj = obj
        self.sDd = setDomain_dict
        self.sTd = setType_dict
        self.access_dict = access
        self.user_groups = user_groups  # User group mapping
        self.group_roles = group_roles   # Group role mapping

    def can_access(self):
        if not all([self.op, self.user, self.obj]):
            logging.warning(f'Access denied: missing parameters - op:{self.op}, user:{self.user}, obj:{self.obj}')
            print("Error: missing parameters for access check")
            return False

        user_domains = self._get_user_domains()

        obj_type = self.sTd.get(self.obj, [])

        for domain in user_domains:
            if self._check_access(domain, obj_type):
                return True

        logging.warning(f'Access denied for user {self.user} to {self.obj} with op {self.op}')
        print("Error: access denied")
        return False
    
    def _get_user_domains(self):
        user_domains = []
        if self.user in self.sDd:
          user_domain = self.sDd[self.user]
          if isinstance(user_domain, list):
              user_domains.extend(user_domain)
          else:
               user_domains.append(user_domain)
        
        if self.user in self.user_groups:
             for group in self.user_groups[self.user]:
                if group in self.group_roles:
                    user_domains.extend(self.group_roles[group])
        return user_domains
   
    def _check_access(self, domain, obj_type):
         for obj in obj_type:
             if (domain, obj) in self.access_dict:
                if self.op in self.access_dict[(domain, obj)]:
                    logging.info(f'Access granted: user {self.user} performed {self.op} on {self.obj}')
                    print("Success")
                    return True
         return False

class Authenticate:
    def __init__(self, username, password, users):
        self.username = username
        self.password = password
        self.users = users

    def auth_user(self):
        if not self.username or not self.password:
            logging.warning('Failed login attempt: missing username or password')
            print("Error: username and password required")
            return False
        if self.username not in self.users:
            logging.warning(f'Failed login attempt: no such user {self.username}')
            print("Error: no such username")
            return False

        hashed_pw = self.users[self.username]
        if bcrypt.checkpw(self.password.encode('utf-8'), hashed_pw):
            logging.info(f'User {self.username} authenticated successfully')
            print("Success")
            return True
        else:
            logging.warning(f'Failed login for {self.username}: bad password')
            print("Error: bad password")
            return False

class AddUser:
    def __init__(self, username, password, users):
        self.username = username
        self.password = password
        self.users = users

    def add_user(self):
        if not self.username or not self.password:
            logging.warning('Failed to add user: missing username or password')
            print("Error: username and password required")
            return False

        if self.username in self.users:
            logging.warning(f'Failed to add user: {self.username} already exists')
            print("Error: user exists")
            return False

        hashed_pw = bcrypt.hashpw(self.password.encode('utf-8'), bcrypt.gensalt())
        self.users[self.username] = hashed_pw
        logging.info(f'User {self.username} added successfully')
        print("Success")
        return True

class RoleManager:
    def __init__(self, roles):
        self.roles = roles

    def add_role(self, role, permissions):
        if not role or not permissions:
             logging.warning('Failed to add role: missing role or permissions')
             print('Error: role and permissions required')
             return False
        if role in self.roles:
            logging.warning(f'Role {role} already exists')
            print("Error: role exists")
            return False
        self.roles[role] = permissions
        logging.info(f'Role {role} added with permissions {permissions}')
        print("Success")
        return True

    def assign_role(self, user, role, user_roles):
        if not role or not user:
             logging.warning('Failed to assign role: missing user or role')
             print("Error: user and role required")
             return False
        if role not in self.roles:
            logging.warning(f'Attempt to assign non-existing role {role} to user {user}')
            print("Error: role does not exist")
            return False
        if user not in user_roles:
             user_roles[user] = []
        user_roles[user].append(role)
        logging.info(f'Role {role} assigned to user {user}')
        print("Success")
        return True

    def revoke_role(self, user, role, user_roles):
        if not role or not user:
             logging.warning('Failed to revoke role: missing user or role')
             print("Error: user and role required")
             return False
        if user in user_roles and role in user_roles[user]:
            user_roles[user].remove(role)
            logging.info(f'Role {role} revoked from user {user}')
            print("Success")
            return True
        else:
            logging.warning(f'Failed to revoke role {role} from user {user}')
            print("Error: role not assigned to user")
            return False

    def list_roles(self):
        if not self.roles:
             print('No roles to list.')
             return
        for role, permissions in self.roles.items():
            print(f'Role: {role}, Permissions: {permissions}')


class GroupManager:
   def __init__(self, groups, group_roles):
      self.groups = groups
      self.group_roles = group_roles

   def create_group(self, group_name):
       if not group_name:
           logging.warning('Failed to create group: missing group name')
           print('Error: group name required')
           return False
       if group_name in self.groups:
           logging.warning(f'Failed to create group: {group_name} already exists')
           print('Error: group exists')
           return False
       self.groups[group_name] = []
       logging.info(f'Group {group_name} created successfully')
       print('Success')
       return True

   def add_user_to_group(self, user, group_name, user_groups):
       if not all([user, group_name]):
            logging.warning('Failed to add user to group: missing user or group')
            print('Error: user and group required')
            return False
       if group_name not in self.groups:
           logging.warning(f'Failed to add user to group: group {group_name} does not exist')
           print('Error: no such group')
           return False
       if user not in user_groups:
         user_groups[user] = []
       if group_name in user_groups[user]:
            logging.warning(f'Failed to add user to group: user {user} already in group {group_name}')
            print('Error: user already in group')
            return False
       
       user_groups[user].append(group_name)
       logging.info(f'User {user} added to group {group_name}')
       print("Success")
       return True

   def assign_role_to_group(self, group_name, role, group_roles):
      if not all([group_name, role]):
            logging.warning('Failed to assign role to group: missing group or role')
            print("Error: group and role required")
            return False
      if group_name not in self.groups:
         logging.warning(f'Failed to assign role to group: group {group_name} does not exist')
         print("Error: no such group")
         return False
      if role not in roles:
         logging.warning(f'Failed to assign role to group: role {role} does not exist')
         print("Error: no such role")
         return False
      if group_name not in group_roles:
        group_roles[group_name] = []
      
      group_roles[group_name].append(role)
      logging.info(f'Role {role} assigned to group {group_name}')
      print("Success")
      return True
    
   def revoke_role_from_group(self, group_name, role, group_roles):
       if not all([group_name, role]):
            logging.warning('Failed to revoke role from group: missing group or role')
            print("Error: group and role required")
            return False
       if group_name not in group_roles:
           logging.warning(f'Failed to revoke role from group: group {group_name} does not have roles')
           print("Error: group does not have roles")
           return False
       if role in group_roles[group_name]:
            group_roles[group_name].remove(role)
            logging.info(f'Role {role} revoked from group {group_name}')
            print("Success")
            return True
       else:
         logging.warning(f'Failed to revoke role from group: role {role} not assigned to {group_name}')
         print("Error: role not assigned to group")
         return False


   def list_groups(self):
       if not self.groups:
            print('No groups to list.')
            return
       for group_name, users in self.groups.items():
          print(f'Group: {group_name}, Users: {users}')


class ObjectManager:
    def __init__(self, objects, object_types):
      self.objects = objects
      self.object_types = object_types

    def create_object(self, obj_type):
        if not obj_type:
            logging.warning('Failed to create object: missing object type')
            print("Error: object type required")
            return None
        
        obj_id = str(uuid.uuid4())
        self.objects[obj_id] = obj_type
        if obj_type not in self.object_types:
            self.object_types[obj_type] = []
        self.object_types[obj_type].append(obj_id)
        logging.info(f'Object {obj_id} created of type {obj_type}')
        print(f'Object {obj_id} created of type {obj_type}')
        return obj_id

    def list_objects(self):
        if not self.objects:
            print("No objects to list")
            return
        for obj, obj_type in self.objects.items():
            print(f'Object ID: {obj}, Type: {obj_type}')

class PermissionManager:
    def __init__(self, access_dict, roles):
        self.access_dict = access_dict
        self.roles = roles

    def add_permission(self, role, obj_type, operation):
        if not all([role, obj_type, operation]):
            logging.warning('Failed to add permission: missing role, object type, or operation')
            print("Error: role, object type and operation required")
            return False
        if role not in self.roles:
            logging.warning(f'Failed to add permission: no such role {role}')
            print("Error: role does not exist")
            return False

        if operation not in self.roles[role]:
            logging.warning(f'Failed to add permission: {role} does not have permission {operation}')
            print(f"Error: {role} does not have permission {operation}")
            return False

        for obj in object_types.get(obj_type,[]):
            if (role, obj) not in self.access_dict:
              self.access_dict[(role, obj)] = []
            if operation not in self.access_dict[(role, obj)]:
                self.access_dict[(role, obj)].append(operation)
        
        logging.info(f'Permission {operation} added for role {role} on type {obj_type}')
        print("Success")
        return True

    def list_permissions(self):
        if not self.access_dict:
             print('No permissions to list.')
             return
        for (domain, obj), operations in self.access_dict.items():
             print(f"Domain: {domain}, Object:{obj}, Operations: {operations}")

    def remove_permission(self, role, obj_type, operation):
        if not all([role, obj_type, operation]):
            logging.warning('Failed to remove permission: missing role, object type, or operation')
            print("Error: role, object type and operation required")
            return False
        if role not in self.roles:
            logging.warning(f'Failed to remove permission: no such role {role}')
            print("Error: role does not exist")
            return False
        
        removed = False
        for obj in object_types.get(obj_type,[]):
             if (role, obj) in self.access_dict and operation in self.access_dict[(role, obj)]:
                self.access_dict[(role, obj)].remove(operation)
                if not self.access_dict[(role, obj)]:
                  del self.access_dict[(role, obj)]
                logging.info(f'Permission {operation} revoked for role {role} on type {obj_type}')
                print("Success")
                removed = True
        if removed:
            return True
        logging.warning(f'Failed to remove permission: operation {operation} not found for role {role} on type {obj_type}')
        print("Error: permission not found")
        return False

# Helper functions for file persistence
def to_file(filename, data):
    with open(filename, 'wb') as file:
        pickle.dump(data, file)

def read_file(filename):
    try:
        with open(filename, 'rb') as file:
            return pickle.load(file)
    except (EOFError, FileNotFoundError):
        return {}

# Main program logic
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Access Control Management System")
    parser.add_argument('command', help='Command to execute')
    parser.add_argument('username', nargs='?', default='', help="Username for user management")
    parser.add_argument('password', nargs='?', default='', help="Password for user management")
    parser.add_argument('role', nargs='?', default='', help="Role for role management")
    parser.add_argument('group', nargs='?', default='', help="Group name for group management")
    parser.add_argument('object', nargs='?', default='', help='Object id for access checks')
    parser.add_argument('object_type', nargs='?', default='', help='Object type for object management')
    parser.add_argument('operation', nargs='?', default='', help='Operation for access checks')

    args = parser.parse_args()

    users = read_file('user.txt')
    roles = read_file('roles.txt')
    user_roles = read_file('user_roles.txt')
    objects = read_file('objects.txt')
    object_types = read_file('object_types.txt')
    access_dict = read_file('access_dict.txt')
    groups = read_file('groups.txt')
    user_groups = read_file('user_groups.txt')
    group_roles = read_file('group_roles.txt')

    if args.command == "AddUser":
        add_user = AddUser(args.username, args.password, users)
        if add_user.add_user():
            to_file('user.txt', users)

    elif args.command == "Authenticate":
        auth = Authenticate(args.username, args.password, users)
        auth.auth_user()

    elif args.command == "AddRole":
        if not args.role:
            print("Error: role name required")
        else:
            permissions = input("Enter permissions (comma separated): ").split(',')
            role_manager = RoleManager(roles)
            if role_manager.add_role(args.role, permissions):
                to_file('roles.txt', roles)

    elif args.command == "AssignRole":
        if not args.role or not args.username:
            print("Error: username and role required")
        else:
            role_manager = RoleManager(roles)
            if role_manager.assign_role(args.username, args.role, user_roles):
              to_file('user_roles.txt', user_roles)

    elif args.command == "RevokeRole":
        if not args.role or not args.username:
            print("Error: username and role required")
        else:
            role_manager = RoleManager(roles)
            if role_manager.revoke_role(args.username, args.role, user_roles):
                to_file('user_roles.txt', user_roles)

    elif args.command == "ListRoles":
        role_manager = RoleManager(roles)
        role_manager.list_roles()
    
    elif args.command == "CreateGroup":
      group_manager = GroupManager(groups, group_roles)
      if group_manager.create_group(args.group):
          to_file('groups.txt', groups)

    elif args.command == "AddUserToGroup":
      group_manager = GroupManager(groups, group_roles)
      if group_manager.add_user_to_group(args.username, args.group, user_groups):
            to_file('user_groups.txt', user_groups)

    elif args.command == "AssignRoleToGroup":
      group_manager = GroupManager(groups, group_roles)
      if group_manager.assign_role_to_group(args.group, args.role, group_roles):
         to_file('group_roles.txt', group_roles)

    elif args.command == "RevokeRoleFromGroup":
      group_manager = GroupManager(groups, group_roles)
      if group_manager.revoke_role_from_group(args.group, args.role, group_roles):
          to_file('group_roles.txt', group_roles)

    elif args.command == "ListGroups":
       group_manager = GroupManager(groups, group_roles)
       group_manager.list_groups()
       
    elif args.command == "CreateObject":
        object_manager = ObjectManager(objects, object_types)
        obj_id = object_manager.create_object(args.object_type)
        if obj_id:
            to_file('objects.txt', objects)
            to_file('object_types.txt', object_types)
    
    elif args.command == "ListObjects":
        object_manager = ObjectManager(objects, object_types)
        object_manager.list_objects()
        
    elif args.command == "AddPermission":
        if not all([args.role, args.object_type, args.operation]):
             print("Error: role, object type and operation required")
        else:
            permission_manager = PermissionManager(access_dict, roles)
            if permission_manager.add_permission(args.role, args.object_type, args.operation):
                 to_file('access_dict.txt', access_dict)

    elif args.command == "RemovePermission":
      if not all([args.role, args.object_type, args.operation]):
             print("Error: role, object type and operation required")
      else:
        permission_manager = PermissionManager(access_dict, roles)
        if permission_manager.remove_permission(args.role, args.object_type, args.operation):
            to_file('access_dict.txt', access_dict)

    elif args.command == "ListPermissions":
        permission_manager = PermissionManager(access_dict, roles)
        permission_manager.list_permissions()

    elif args.command == "CanAccess":
         can_access = CanAccess(args.operation, args.username, args.object, user_roles, object_types, access_dict, user_groups, group_roles)
         can_access.can_access()

    else:
        logging.error(f'Invalid command: {args.command}')
        print(f"Error: invalid command {args.command}")
      

