#!/usr/bin/env python3
"""
Automate ServiceNow API key setup for MCP Agent.

This script automates the creation of:
1. Service Account User with appropriate roles
2. REST API Key
3. Inbound Authentication Profile (manual step - see notes below)
4. API Access Policies (manual step - see notes below)

**IMPORTANT LIMITATIONS:**
- Some ServiceNow administrative operations cannot be automated via REST API
- You may need to complete steps manually in the ServiceNow UI for:
  - Inbound Authentication Profile creation
  - API Access Policy creation
  
See README.md for full manual setup instructions.

Environment Variables Required:
    SERVICENOW_INSTANCE_URL: ServiceNow instance URL (e.g., https://dev12345.service-now.com)
    
Authentication (use one of the following):
    Option 1 - Basic Auth (RECOMMENDED for this setup script):
        SERVICENOW_USERNAME: ServiceNow admin username
        SERVICENOW_PASSWORD: ServiceNow admin password
    
    Option 2 - API Key Auth:
        SERVICENOW_API_KEY: Your API key value
        SERVICENOW_API_KEY_HEADER: API key header name (optional, default: x-sn-apikey)
        
        NOTE: API key auth requires the key to have admin permissions to create users,
              assign roles, and create API keys. Most API keys don't have these permissions.
"""

import os
import sys
from typing import Any, Optional

import requests
from requests.auth import HTTPBasicAuth

# Known role sys_ids (fallback if lookup fails)
KNOWN_ROLE_SYS_IDS = {
    "cmdb_read": "ab250967b31213005e3de13516a8dc26",
}


class ServiceNowAPIKeySetup:
    """Automate ServiceNow API key setup for MCP Agent."""

    def __init__(self, instance_url: str, username: str = None, password: str = None, api_key: str = None, api_key_header: str = "x-sn-apikey") -> None:
        """Initialize the ServiceNow API key setup.

        Args:
            instance_url: ServiceNow instance URL
            username: ServiceNow admin username (required for basic auth)
            password: ServiceNow admin password (required for basic auth)
            api_key: API key for authentication (alternative to basic auth)
            api_key_header: Header name for API key (default: x-sn-apikey)
        """
        self.instance_url = instance_url.rstrip("/")
        
        # Support both basic auth and API key auth
        if api_key:
            self.auth = None  # API key auth doesn't use HTTPBasicAuth
            self.headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                api_key_header: api_key,
            }
        elif username and password:
            self.auth = HTTPBasicAuth(username, password)
            self.headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        else:
            raise ValueError("Either username/password or api_key must be provided")
        
        self.created_users: list[dict[str, Any]] = []
        self.created_api_keys: list[dict[str, Any]] = []
        self.errors: list[str] = []
        self.results: dict[str, Any] = {}  # Store created item sys_ids

    def get_user(self, user_name: str) -> Optional[str]:
        """Check if a user exists in ServiceNow.

        Args:
            user_name: Username to check

        Returns:
            User sys_id if exists, None otherwise
        """
        user_url = f"{self.instance_url}/api/now/table/sys_user"
        params = {
            "sysparm_query": f"user_name={user_name}",
            "sysparm_limit": "1",
            "sysparm_fields": "sys_id,user_name,first_name,last_name",
        }

        try:
            response = requests.get(
                user_url, auth=self.auth, headers=self.headers, params=params, timeout=30
            )

            if response.status_code == 200:
                result = response.json().get("result", [])
                if result:
                    sys_id = result[0].get("sys_id")
                    return str(sys_id) if sys_id is not None else None
            return None

        except Exception as e:
            self.errors.append(f"Failed to check user {user_name}: {str(e)}")
            return None

    def create_user(
        self, user_name: str, first_name: str, roles: list[str] = None
    ) -> Optional[str]:
        """Create a service account user in ServiceNow.

        Args:
            user_name: Username for the service account
            first_name: First name for the service account
            roles: List of role names to assign (e.g., ['cmdb_read'])

        Returns:
            User sys_id if successful, None otherwise
        """
        # Check if user already exists
        existing_user_id = self.get_user(user_name)
        if existing_user_id:
            print(f"  ℹ️  User {user_name} already exists (sys_id: {existing_user_id})")
            
            # Still try to assign roles even if user exists
            if roles:
                print(f"  Assigning roles to existing user...")
                self.assign_user_roles(existing_user_id, roles)
            
            # Return the existing user's sys_id
            self.created_users.append({"user_name": user_name, "sys_id": existing_user_id})
            return existing_user_id
        else:
            # Create new user
            user_url = f"{self.instance_url}/api/now/table/sys_user"

            user_payload = {
                "user_name": user_name,
                "first_name": first_name,
                "active": "true",
                "web_service_access_only": "true",  # Limit to API access only
            }

            try:
                response = requests.post(
                    user_url,
                    auth=self.auth,
                    headers=self.headers,
                    json=user_payload,
                    timeout=30,
                )

                if response.status_code == 201:
                    result = response.json().get("result", {})
                    user_sys_id = result.get("sys_id")
                    sys_id_str = str(user_sys_id) if user_sys_id is not None else None
                    print(f"  ✅ Created user: {user_name}")
                    print(f"     User sys_id: {sys_id_str}")
                    self.created_users.append(
                        {"user_name": user_name, "sys_id": sys_id_str}
                    )

                    # Assign roles if provided
                    if roles and sys_id_str:
                        self.assign_user_roles(sys_id_str, roles)

                    return sys_id_str
                else:
                    error_msg = (
                        f"Failed to create user {user_name}: "
                        f"{response.status_code} - {response.text}"
                    )
                    print(f"  ❌ {error_msg}")
                    self.errors.append(error_msg)
                    return None

            except Exception as e:
                error_msg = f"Exception creating user {user_name}: {str(e)}"
                print(f"  ❌ {error_msg}")
                self.errors.append(error_msg)
                return None

    def assign_user_roles(self, user_sys_id: str, role_names: list[str]) -> bool:
        """Assign roles to a user.

        Args:
            user_sys_id: User sys_id
            role_names: List of role names to assign

        Returns:
            True if successful, False otherwise
        """
        success_count = 0

        for role_name in role_names:
            # First, find the role sys_id
            role_sys_id = self.get_role(role_name)
            if not role_sys_id:
                print(f"  ⚠️  Role '{role_name}' not found, skipping...")
                continue

            # Create user_has_role record
            user_role_url = f"{self.instance_url}/api/now/table/sys_user_has_role"

            user_role_payload = {
                "user": user_sys_id,
                "role": role_sys_id,
            }

            try:
                response = requests.post(
                    user_role_url,
                    auth=self.auth,
                    headers=self.headers,
                    json=user_role_payload,
                    timeout=30,
                )

                if response.status_code == 201:
                    print(f"  ✅ Assigned role: {role_name}")
                    success_count += 1
                else:
                    print(f"  ⚠️  Failed to assign role {role_name}: {response.status_code}")
                    # Check if role already assigned
                    if response.status_code == 409:
                        print(f"     Role may already be assigned")
                        success_count += 1

            except Exception as e:
                print(f"  ⚠️  Exception assigning role {role_name}: {str(e)}")

        return success_count > 0

    def get_role(self, role_name: str) -> Optional[str]:
        """Get a role sys_id by name.

        Args:
            role_name: Name of the role

        Returns:
            Role sys_id if found, None otherwise
        """
        role_url = f"{self.instance_url}/api/now/table/sys_user_role"
        # Use direct field query instead of sysparm_query
        params = {
            "name": role_name,  # Direct field query
            "sysparm_limit": "1",
            "sysparm_fields": "sys_id,name",
        }

        try:
            response = requests.get(
                role_url, auth=self.auth, headers=self.headers, params=params, timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                result = data.get("result", [])
                if result:
                    sys_id = result[0].get("sys_id")
                    return str(sys_id) if sys_id is not None else None
        except Exception:
            pass  # Will fall through to use known sys_id
        
        # Fallback: use known sys_ids if API lookup fails (e.g., API key doesn't have permission)
        if role_name in KNOWN_ROLE_SYS_IDS:
            print(f"  ℹ️  Using known sys_id for role '{role_name}': {KNOWN_ROLE_SYS_IDS[role_name]}")
            return KNOWN_ROLE_SYS_IDS[role_name]
        
        return None

    def lookup_role_sys_id(self, role_name: str) -> Optional[str]:
        """Look up and print role sys_id for manual configuration.

        Args:
            role_name: Name of the role to look up

        Returns:
            Role sys_id if found, None otherwise
        """
        sys_id = self.get_role(role_name)
        if sys_id:
            print(f"  ℹ️  Found role '{role_name}': sys_id = {sys_id}")
        else:
            print(f"  ⚠️  Role '{role_name}' not found")
        return sys_id

    def get_api_key_token(self, api_key_sys_id: str) -> Optional[str]:
        """Retrieve API key token by sys_id.

        NOTE: This may not work on all ServiceNow versions as token
        retrieval is restricted for security reasons.

        Args:
            api_key_sys_id: API key sys_id

        Returns:
            API key token if available, None otherwise
        """
        api_key_url = f"{self.instance_url}/api/now/table/sys_api_key/{api_key_sys_id}"
        params = {
            "sysparm_fields": "key",
        }

        try:
            response = requests.get(
                api_key_url, auth=self.auth, headers=self.headers, params=params, timeout=30
            )

            if response.status_code == 200:
                result = response.json().get("result", {})
                return result.get("key")
            return None

        except Exception:
            return None

    def lookup_rest_api_sys_ids(self) -> dict[str, Optional[str]]:
        """Look up REST API sys_ids by name for reference.

        Returns:
            Dictionary mapping API names to sys_ids
        """
        rest_api_url = f"{self.instance_url}/api/now/table/sys_web_service"
        apis_to_find = [
            "Service Catalog API",
            "Table API",
        ]
        results = {}

        for api_name in apis_to_find:
            params = {
                "sysparm_query": f"name={api_name}",
                "sysparm_limit": "1",
                "sysparm_fields": "sys_id,name,api_name",
            }

            try:
                response = requests.get(
                    rest_api_url, auth=self.auth, headers=self.headers, params=params, timeout=30
                )

                if response.status_code == 200:
                    data = response.json().get("result", [])
                    if data:
                        sys_id = data[0].get("sys_id")
                        api_display_name = data[0].get("api_name", api_name)
                        if sys_id:
                            results[api_name] = str(sys_id)
                            print(f"  ℹ️  Found '{api_display_name}' API: sys_id = {sys_id}")
                        else:
                            results[api_name] = None
                            print(f"  ⚠️  API '{api_name}' found but has no sys_id")
                    else:
                        results[api_name] = None
                        print(f"  ⚠️  API '{api_name}' not found")
                else:
                    results[api_name] = None
                    print(f"  ⚠️  Error looking up '{api_name}': {response.status_code}")

            except Exception as e:
                results[api_name] = None
                print(f"  ⚠️  Exception looking up '{api_name}': {str(e)}")

        return results

    def create_api_key(
        self, name: str, user_sys_id: str, header_name: str = "x-sn-apikey"
    ) -> Optional[str]:
        """Create a REST API key for the user.

        NOTE: This operation may not be supported via REST API depending on your
        ServiceNow version. If this fails, you'll need to create the API key manually
        in the ServiceNow UI.

        Args:
            name: Name for the API key
            user_sys_id: User sys_id to associate with the API key
            header_name: Header name for authentication (default: x-sn-apikey)

        Returns:
            API key token if successful, None otherwise
        """
        api_key_url = f"{self.instance_url}/api/now/table/sys_api_key"

        api_key_payload = {
            "name": name,
            "header_name": header_name,
            "user": user_sys_id,
        }

        try:
            response = requests.post(
                api_key_url,
                auth=self.auth,
                headers=self.headers,
                json=api_key_payload,
                timeout=30,
            )

            if response.status_code == 201:
                result = response.json().get("result", {})
                api_key_token = result.get("key")
                api_key_sys_id = result.get("sys_id")
                print(f"  ✅ Created API key: {name}")
                print(f"     API Key sys_id: {api_key_sys_id}")
                if api_key_token:
                    print(f"  🔑 API Key Token: {api_key_token}")
                    print(f"     ⚠️  SAVE THIS TOKEN - It cannot be retrieved again!")
                else:
                    print(f"     ⚠️  Token not returned. Check the key in ServiceNow UI.")

                self.created_api_keys.append(
                    {
                        "name": name,
                        "sys_id": api_key_sys_id,
                        "token": api_key_token or "NOT_AVAILABLE",
                    }
                )
                return api_key_token

            else:
                error_msg = (
                    f"Failed to create API key {name}: "
                    f"{response.status_code} - {response.text}"
                )
                print(f"  ❌ {error_msg}")
                print(f"     This operation may require manual setup via ServiceNow UI.")
                self.errors.append(error_msg)
                return None

        except Exception as e:
            error_msg = f"Exception creating API key {name}: {str(e)}"
            print(f"  ❌ {error_msg}")
            print(f"     This operation may require manual setup via ServiceNow UI.")
            self.errors.append(error_msg)
            return None

    def setup_api_key(self) -> None:
        """Main function to set up API key configuration."""
        print("=" * 80)
        print("ServiceNow API Key Setup for MCP Agent")
        print("=" * 80)
        print(f"Instance: {self.instance_url}")
        print("=" * 80)
        print()

        # Step 1: Create service account user
        print("Step 1: Creating Service Account User")
        print("-" * 80)
        user_sys_id = self.create_user(
            user_name="test_svc_self_service_agent_mcp",
            first_name="Test Service Now MCP Agent Prod",
            roles=["cmdb_read"],
        )

        if not user_sys_id:
            print("❌ Failed to create service account user. Cannot continue.")
            return

        print()

        # Step 2: Create API Key
        print("Step 2: Creating REST API Key")
        print("-" * 80)
        api_key_token = self.create_api_key(
            name="Test MCP Agent API Key - Production",
            user_sys_id=user_sys_id,
            header_name="x-sn-apikey",
        )

        print()

        # Step 3: Look up sys_ids needed for manual configuration
        print("Step 3: Looking Up Required sys_ids for Manual Configuration")
        print("-" * 80)
        print("Looking up REST API sys_ids you'll need for manual policy configuration...")
        
        # Look up REST API sys_ids
        api_sys_ids = self.lookup_rest_api_sys_ids()
        
        # Look up role sys_id
        print("\nLooking up role sys_ids...")
        cmdb_read_sys_id = self.lookup_role_sys_id("cmdb_read")
        
        print()
        
        # Step 4: Print manual steps with sys_ids
        print("Step 4: Manual Configuration Required")
        print("-" * 80)
        print("⚠️  The following steps must be completed manually in the ServiceNow UI:")
        print()
        print("a) Create Inbound Authentication Profile:")
        print("   1. Navigate to: System Web Services > API Access Policies >")
        print("      Inbound Authentication Profile")
        print("   2. Click 'Create API Key authentication profiles'")
        print(f"   3. Name: 'Test MCP Agent - API Key Authentication'")
        print(f"   4. Auth Parameter: x-sn-apikey (from dropdown)")
        print()
        print("b) Create API Access Policies:")
        print("   1. Navigate to: System Web Services > API Access Policies >")
        print("      REST API Access Policies")
        print("   2. Create two policies:")
        print()
        print("   Policy 1 - Service Catalog:")
        print("     - Name: 'Test Service Now - API Key Catalog'")
        if api_sys_ids.get("Service Catalog API"):
            print(f"     - REST API: Service Catalog API (sys_id: {api_sys_ids.get('Service Catalog API')})")
        else:
            print("     - REST API: Service Catalog API")
        print("     - REST API Path: sn_sc/servicecatalog")
        print("     - Methods: All")
        print("     - Authentication: Your Inbound Authentication Profile")
        print()
        print("   Policy 2 - Table API:")
        print("     - Name: 'Test Service Now - API Key Tables'")
        if api_sys_ids.get("Table API"):
            print(f"     - REST API: Table API (sys_id: {api_sys_ids.get('Table API')})")
        else:
            print("     - REST API: Table API")
        print("     - REST API Path: now/table")
        print("     - Tables: cmdb_ci_computer,sys_user")
        print("     - Methods: All")
        print("     - Authentication: Your Inbound Authentication Profile")
        print()

        if api_key_token and api_key_token != "NOT_AVAILABLE":
            print("Step 5: Test Your API Key")
            print("-" * 80)
            print("Test the API key with:")
            print()
            print(
                f'curl -H "x-sn-apikey: {api_key_token}" \\'
            )
            print(
                f"  {self.instance_url}/api/now/table/sys_user?sysparm_limit=1"
            )
            print()

    def print_summary(self) -> None:
        """Print a summary of created resources and errors."""
        print("=" * 80)
        print("Summary")
        print("=" * 80)
        print(f"✅ Users created: {len(self.created_users)}")
        print(f"✅ API Keys created: {len(self.created_api_keys)}")
        print(f"❌ Errors: {len(self.errors)}")
        print()

        if self.created_users:
            print("Created Users:")
            for user in self.created_users:
                print(f"  - {user['user_name']} - sys_id: {user['sys_id']}")
                if 'sys_id' in user:
                    self.results['user_sys_id'] = user['sys_id']
            print()

        if self.created_api_keys:
            print("Created API Keys:")
            for api_key in self.created_api_keys:
                print(f"  - {api_key['name']}")
                print(f"    sys_id: {api_key['sys_id']}")
                if api_key['token'] != "NOT_AVAILABLE":
                    print(f"    🔑 token: {api_key['token']}")
                if 'sys_id' in api_key:
                    self.results['api_key_sys_id'] = api_key['sys_id']
                if api_key['token'] != "NOT_AVAILABLE":
                    self.results['api_key_value'] = api_key['token']
            print()

        if self.errors:
            print("Errors:")
            for error in self.errors:
                print(f"  ❌ {error}")
            print()

        # Print results summary
        if self.results:
            print("Created/Updated Resources:")
            print(f"  User sys_id: {self.results.get('user_sys_id', 'N/A')}")
            print(f"  API Key sys_id: {self.results.get('api_key_sys_id', 'N/A')}")
            if self.results.get('api_key_value'):
                print(f"  🔑 API Key Value: {self.results.get('api_key_value')}")

        print("=" * 80)


def main() -> None:
    """Main function to set up API key configuration."""
    # Get credentials from environment
    instance_url = os.getenv("SERVICENOW_INSTANCE_URL")
    username = os.getenv("SERVICENOW_USERNAME")
    password = os.getenv("SERVICENOW_PASSWORD")
    api_key = os.getenv("SERVICENOW_API_KEY")
    api_key_header = os.getenv("SERVICENOW_API_KEY_HEADER", "x-sn-apikey")

    # Validate environment variables
    if not instance_url:
        print("❌ ERROR: SERVICENOW_INSTANCE_URL environment variable is not set")
        sys.exit(1)

    # Support both basic auth and API key auth
    if api_key:
        print("🔑 Using API key authentication")
        setup = ServiceNowAPIKeySetup(
            instance_url, 
            api_key=api_key, 
            api_key_header=api_key_header
        )
    elif username and password:
        print("🔐 Using basic authentication")
        setup = ServiceNowAPIKeySetup(instance_url, username, password)
    else:
        print("❌ ERROR: Authentication credentials required")
        print()
        print("Provide either:")
        print("  - SERVICENOW_USERNAME and SERVICENOW_PASSWORD (basic auth)")
        print("  - SERVICENOW_API_KEY (API key auth)")
        print()
        print("Also required:")
        print("  - SERVICENOW_INSTANCE_URL")
        sys.exit(1)

    try:
        setup.setup_api_key()
        setup.print_summary()

        if setup.errors:
            print("⚠️  Some operations failed. See errors above.")
            print("   Manual setup may be required for API key creation.")
            print("   Refer to README.md for complete setup instructions.")
            sys.exit(1)
        else:
            print("🎉 API key setup completed successfully!")
            sys.exit(0)

    except KeyboardInterrupt:
        print("\n\n⚠️  Script interrupted by user")
        setup.print_summary()
        sys.exit(1)

    except Exception as e:
        print(f"\n\n❌ Unexpected error: {str(e)}")
        import traceback

        traceback.print_exc()
        setup.print_summary()
        sys.exit(1)


if __name__ == "__main__":
    main()

