#!/usr/bin/env python3

import argparse
import asyncio
import json
import logging
import os
import sys
import urllib.parse
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import McpError
from mcp.types import (
    CallToolResult,
    ErrorData,
    GetPromptResult,
    Prompt,
    PromptMessage,
    TextContent,
    Tool,
    INVALID_REQUEST ,
    METHOD_NOT_FOUND ,
    INTERNAL_ERROR,
)

from thoughtspot_rest_api_v1 import TSRestApiV2

# Enhanced logging configuration for debugging
import logging.handlers

# Determine log file path
log_path = "mcp_debug.log"
if not os.access(".", os.W_OK):
    log_path = "/tmp/mcp_debug.log"

# Create a more robust logging configuration
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# Clear any existing handlers
for handler in logger.handlers[:]:
    logger.removeHandler(handler)

# Create formatter
formatter = logging.Formatter('%(asctime)s %(levelname)s:%(message)s')

# File handler with rotation (only file logging, no console to avoid MCP protocol interference)
file_handler = logging.handlers.RotatingFileHandler(
    log_path, 
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5,
    mode='a'  # Append mode instead of overwrite
)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

logging.info("Enhanced logging is working.")
logging.info(f"Log file location: {os.path.abspath(log_path)}")
logging.info(f"Current working directory: {os.getcwd()}")


# Metadata types enum
class MetadataType(str, Enum):
    LIVEBOARD = "LIVEBOARD"
    ANSWER = "ANSWER"
    LOGICAL_TABLE = "LOGICAL_TABLE"
    CONNECTION = "CONNECTION"
    TAG = "TAG"
    USER_GROUP = "USER_GROUP"

class ThoughtSpotAdmin:
    """Class to manage ThoughtSpot client and related functionality.

    This class encapsulates the ThoughtSpot client and provides methods to initialize and access it.
    Using a class instead of a global variable makes the code more modular, testable, and thread-safe.
    """

    def __init__(self):
        """Initialize ThoughtSpotAdmin with no client."""
        self.ts_client: Optional[TSRestApiV2] = None

    def init_client(self, server_url: str, username: str, token: str) -> TSRestApiV2:
        """Initialize ThoughtSpot client with provided credentials."""
        logging.info(f"Initializing ThoughtSpot client with server_url: {server_url}, username: {username}")
        
        # Validate input parameters
        if not server_url:
            logging.error("Server URL is missing")
            raise McpError(
                ErrorData(code=INVALID_REQUEST, message="Server URL is required"),
            )
        if not username:
            logging.error("Username is missing")
            raise McpError(
                ErrorData(code=INVALID_REQUEST, message="Username is required"),
            )
        if not token:
            logging.error("API token is missing")
            raise McpError(
                ErrorData(code=INVALID_REQUEST, message="API token is required"),
            )

        try:
            logging.info("Creating TSRestApiV2 instance")
            self.ts_client = TSRestApiV2(server_url=server_url)
            logging.info("Setting bearer token")
            self.ts_client.bearer_token = token
            logging.info("Setting username")
            self.ts_client.username = username
            logging.info("ThoughtSpot client initialized successfully")
            return self.ts_client
        except Exception as e:
            logging.error(f"Failed to initialize ThoughtSpot client: {str(e)}")
            logging.error(f"Error type: {type(e)}")
            raise McpError(
                ErrorData(code=INTERNAL_ERROR, message=f"Failed to initialize ThoughtSpot client: {str(e)}"),
            )

    def get_client(self) -> TSRestApiV2:
        """Get the initialized ThoughtSpot client."""
        if self.ts_client is None:
            raise McpError(
                ErrorData(code=INTERNAL_ERROR, message="ThoughtSpot client not initialized. Please check your configuration."),
            )
        return self.ts_client

# Create a singleton instance to maintain compatibility with existing code
# while still benefiting from the class-based approach
ts_admin = ThoughtSpotAdmin()

def init_thoughtspot_client(server_url: str, username: str, token: str) -> TSRestApiV2:
    """Initialize ThoughtSpot client with provided credentials.

    This is a wrapper around ThoughtSpotAdmin.init_client for backward compatibility.
    """
    return ts_admin.init_client(server_url, username, token)

def get_ts_client() -> TSRestApiV2:
    """Get the initialized ThoughtSpot client.

    This is a wrapper around ThoughtSpotAdmin.get_client for backward compatibility.
    """
    return ts_admin.get_client()

async def search_metadata(
    types: List[str] = None,
    authors: List[str] = None,
    tags: List[str] = None,
    offset: int = 0,
    limit: int = 100  # Note that too many can cause Claude to complain about message sizes.
) -> List[Dict[str, Any]]:
    """Search metadata using ThoughtSpot API."""
    try:
        client = get_ts_client()

        # Build metadata types filter
        if types:
            # Validate types
            valid_types = [t for t in types if t in [mt.value for mt in MetadataType]]
            if len(valid_types) != len(types):
                invalid_types = [t for t in types if t not in [mt.value for mt in MetadataType]]
                raise McpError(
                    ErrorData(code=INVALID_REQUEST, message=f"Invalid metadata types: {invalid_types}. Valid types are: {[mt.value for mt in MetadataType]}"),
                )
            metadata_types = [{"type": t} for t in valid_types]
        else:
            # If no types specified, search all types
            metadata_types = [{"type": mt.value} for mt in MetadataType]

        # Build the search request
        search_request = {
            "dependent_object_version": "V1",
            "include_details": True,
            "include_headers": True,
            "record_offset": offset,
            "record_size": limit,
            "include_stats": True,
            "metadata": metadata_types
        }

        # Add optional filters
        if authors:
            search_request["created_by_user_identifiers"] = authors

        if tags:
            search_request["tag_identifiers"] = tags

        logging.debug(f"Search request: {search_request}")

        # Make the API call
        response = client.metadata_search(search_request)

        # Handle None response
        if response is None:
            logging.warning("Received None response from metadata_search")
            return []

        response = response if isinstance(response, list) else [response]
        return extract_metadata_fields(response)


    except Exception as e:
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Failed to search metadata: {str(e)}"),
        )

async def list_users(
    user_identifier: str = None,
    display_name: str = None,
    name_pattern: str = None,
    email: str = None,
    group_identifiers: List[str] = None,
    offset: int = 0,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """List users using ThoughtSpot API."""
    logging.info(f"Starting list_users with parameters: user_identifier={user_identifier}, display_name={display_name}, name_pattern={name_pattern}, email={email}, group_identifiers={group_identifiers}, offset={offset}, limit={limit}")
    
    try:
        logging.info("Getting ThoughtSpot client")
        client = get_ts_client()
        logging.info("Successfully got ThoughtSpot client")

        # Build the search request
        search_request = {
            "record_offset": offset,
            "record_size": limit,
            "include_favorite_metadata": False
        }

        # Add optional filters
        if user_identifier:
            search_request["user_identifier"] = user_identifier
            logging.debug(f"Added user_identifier filter: {user_identifier}")
        if display_name:
            search_request["display_name"] = display_name
            logging.debug(f"Added display_name filter: {display_name}")
        if name_pattern:
            search_request["name_pattern"] = name_pattern
            logging.debug(f"Added name_pattern filter: {name_pattern}")
        if email:
            search_request["email"] = email
            logging.debug(f"Added email filter: {email}")
        if group_identifiers:
            search_request["group_identifiers"] = group_identifiers
            logging.debug(f"Added group_identifiers filter: {group_identifiers}")

        # Validate that at least one filter is provided
        if not any([user_identifier, display_name, name_pattern, email, group_identifiers]):
            logging.error("No filters provided for user search")
            raise McpError(
                ErrorData(code=INVALID_REQUEST, message="At least one filter must be provided: user_identifier, display_name, name_pattern, email, or group_identifiers"),
            )

        logging.info(f"User search request: {search_request}")

        # Make the API call using the REST API endpoint
        logging.info("Making REST API call to /api/rest/2.0/users/search")
        try:
            response = client.users_search(
                request=search_request
            )
            logging.info(f"REST API call completed. Response type: {type(response)}")
            logging.debug(f"Raw response: {response}")
        except Exception as api_error:
            logging.error(f"REST API call failed: {str(api_error)}")
            logging.error(f"API error type: {type(api_error)}")
            raise

        # Handle None response
        if response is None:
            logging.warning("Received None response from users_search")
            return []

        # Ensure response is a list
        if not isinstance(response, list):
            logging.info(f"Converting single response to list. Original type: {type(response)}")
            response = [response]

        logging.info(f"Extracting user fields from {len(response)} user(s)")
        result = extract_user_fields(response)
        logging.info(f"Successfully extracted {len(result)} user(s)")
        return result

    except McpError:
        logging.error("McpError raised in list_users")
        raise
    except Exception as e:
        logging.error(f"Unexpected error in list_users: {str(e)}")
        logging.error(f"Error type: {type(e)}")
        logging.error(f"Error details: {e}")
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Failed to list users: {str(e)}"),
        )

async def list_groups(
    display_name: str = None,
    group_identifier: str = None,
    name_pattern: str = None,
    include_users: bool = False,
    include_sub_groups: bool = False,
    offset: int = 0,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """List groups using ThoughtSpot API."""
    logging.info(f"Starting list_groups with parameters: display_name={display_name}, group_identifier={group_identifier}, name_pattern={name_pattern}, include_users={include_users}, include_sub_groups={include_sub_groups}, offset={offset}, limit={limit}")
    
    try:
        logging.info("Getting ThoughtSpot client")
        client = get_ts_client()
        logging.info("Successfully got ThoughtSpot client")

        # Build the search request
        search_request = {
            "record_offset": offset,
            "record_size": limit,
            "include_users": include_users,
            "include_sub_groups": include_sub_groups
        }

        # Add optional filters
        if display_name:
            search_request["display_name"] = display_name
            logging.debug(f"Added display_name filter: {display_name}")
        if group_identifier:
            search_request["group_identifier"] = group_identifier
            logging.debug(f"Added group_identifier filter: {group_identifier}")
        if name_pattern:
            search_request["name_pattern"] = name_pattern
            logging.debug(f"Added name_pattern filter: {name_pattern}")

        logging.info(f"Group search request: {search_request}")

        # Make the API call using the REST API endpoint
        logging.info("Making REST API call to /api/rest/2.0/groups/search")
        try:
            response = client.groups_search(
                request=search_request
            )
            logging.info(f"REST API call completed. Response type: {type(response)}")
            logging.debug(f"Raw response: {response}")
        except Exception as api_error:
            logging.error(f"REST API call failed: {str(api_error)}")
            logging.error(f"API error type: {type(api_error)}")
            raise

        # Handle None response
        if response is None:
            logging.warning("Received None response from groups_search")
            return []

        # Ensure response is a list
        if not isinstance(response, list):
            logging.info(f"Converting single response to list. Original type: {type(response)}")
            response = [response]

        logging.info(f"Extracting group fields from {len(response)} group(s)")
        result = extract_group_fields(response)
        logging.info(f"Successfully extracted {len(result)} group(s)")
        return result

    except McpError:
        logging.error("McpError raised in list_groups")
        raise
    except Exception as e:
        logging.error(f"Unexpected error in list_groups: {str(e)}")
        logging.error(f"Error type: {type(e)}")
        logging.error(f"Error details: {e}")
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Failed to list groups: {str(e)}"),
        )

async def manage_user_groups(
    username: str,
    operation: str,
    group_identifiers: List[str]
) -> Dict[str, Any]:
    """Add or remove users from groups using ThoughtSpot API."""
    logging.info(f"Starting manage_user_groups with parameters: username={username}, operation={operation}, group_identifiers={group_identifiers}")
    
    try:
        logging.info("Getting ThoughtSpot client")
        client = get_ts_client()
        logging.info("Successfully got ThoughtSpot client")

        # Validate operation
        logging.info(f"Validating operation: {operation}")
        if operation not in ["ADD", "REMOVE"]:
            logging.error(f"Invalid operation: {operation}")
            raise McpError(
                ErrorData(code=INVALID_REQUEST, message="Operation must be either 'ADD' or 'REMOVE'"),
            )
        logging.info(f"Operation validation passed: {operation}")

        # Validate inputs
        logging.info(f"Validating username: {username}")
        if not username:
            logging.error("Username is empty or None")
            raise McpError(
                ErrorData(code=INVALID_REQUEST, message="Username is required"),
            )
        logging.info(f"Username validation passed: {username}")

        logging.info(f"Validating group_identifiers: {group_identifiers}")
        if not group_identifiers or len(group_identifiers) == 0:
            logging.error("No group identifiers provided")
            raise McpError(
                ErrorData(code=INVALID_REQUEST, message="At least one group identifier is required"),
            )
        logging.info(f"Group identifiers validation passed: {len(group_identifiers)} groups")

        # Build the update request
        update_request = {
            "operation": operation,
            "group_identifiers": group_identifiers
        }

        logging.info(f"User group management request: {update_request}")

        # URL encode the username for the endpoint
        logging.info(f"URL encoding username: {username}")
        encoded_username = urllib.parse.quote(username, safe='')
        logging.info(f"Encoded username: {encoded_username}")
        
        # Make the API call using the REST API endpoint
        endpoint = f"/api/rest/2.0/users/{encoded_username}/update"
        logging.info(f"Making REST API call to {endpoint}")
        try:
            response = client.users_update(
                user_identifier=encoded_username,
                request=update_request
            )
            logging.info(f"REST API call completed. Response type: {type(response)}")
            logging.debug(f"Raw response: {response}")
        except Exception as api_error:
            logging.error(f"REST API call failed: {str(api_error)}")
            logging.error(f"API error type: {type(api_error)}")
            raise

        # The API returns 204 for success, but the client might handle this differently
        # Return a success message
        result = {
            "success": True,
            "message": f"Successfully {operation.lower()}ed user '{username}' to/from {len(group_identifiers)} group(s)",
            "operation": operation,
            "username": username,
            "group_identifiers": group_identifiers
        }
        logging.info(f"Operation completed successfully: {result}")
        return result

    except McpError:
        logging.error("McpError raised in manage_user_groups")
        raise
    except Exception as e:
        logging.error(f"Unexpected error in manage_user_groups: {str(e)}")
        logging.error(f"Error type: {type(e)}")
        logging.error(f"Error details: {e}")
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Failed to manage user groups: {str(e)}"),
        )

def extract_user_fields(user_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Extract specific fields from user search response and return them as a flat JSON object.
    
    Fields extracted:
    * id - the unique user ID
    * name - the username/email
    * display_name - the display name
    * email - the email address
    * account_status - the account status (ACTIVE, INACTIVE, etc.)
    * account_type - the account type (OIDC_USER, LOCAL_USER, etc.)
    * user_groups - list of groups the user belongs to
    * user_inherited_groups - list of groups the user inherits from
    * privileges - list of user privileges
    * creation_time - when the user was created
    * modification_time - when the user was last modified
    """
    logging.info(f"Starting extract_user_fields with {len(user_list)} user(s)")
    result = []

    for i, user in enumerate(user_list):
        logging.debug(f"Processing user {i+1}/{len(user_list)}")
        
        if user is None:
            logging.warning(f"Skipping None user item at index {i}")
            continue

        logging.debug(f"Extracting user: {user}")
        try:
            flat_user = {
                "id": user.get("id", ""),
                "name": user.get("name", ""),
                "display_name": user.get("display_name", ""),
                "email": user.get("email", ""),
                "account_status": user.get("account_status", ""),
                "account_type": user.get("account_type", ""),
                "super_user": user.get("super_user", False),
                "system_user": user.get("system_user", False),
                "external": user.get("external", False),
                "deleted": user.get("deleted", False)
            }

            # Extract groups
            if "user_groups" in user and isinstance(user["user_groups"], list):
                flat_user["user_groups"] = [
                    {"id": group.get("id", ""), "name": group.get("name", "")} 
                    for group in user["user_groups"] if group is not None
                ]
                logging.debug(f"Extracted {len(flat_user['user_groups'])} user groups")

            if "user_inherited_groups" in user and isinstance(user["user_inherited_groups"], list):
                flat_user["user_inherited_groups"] = [
                    {"id": group.get("id", ""), "name": group.get("name", "")} 
                    for group in user["user_inherited_groups"] if group is not None
                ]
                logging.debug(f"Extracted {len(flat_user['user_inherited_groups'])} inherited groups")

            # Extract privileges
            if "privileges" in user and isinstance(user["privileges"], list):
                flat_user["privileges"] = user["privileges"]
                logging.debug(f"Extracted {len(flat_user['privileges'])} privileges")

            # Convert epoch dates to datetime objects
            if "creation_time_in_millis" in user:
                creation_epoch = user["creation_time_in_millis"]
                flat_user["creation_time"] = datetime.fromtimestamp(creation_epoch / 1000) if creation_epoch else None
                logging.debug(f"Converted creation time: {flat_user['creation_time']}")

            if "modification_time_in_millis" in user:
                modification_epoch = user["modification_time_in_millis"]
                flat_user["modification_time"] = datetime.fromtimestamp(modification_epoch / 1000) if modification_epoch else None
                logging.debug(f"Converted modification time: {flat_user['modification_time']}")

            logging.debug(f"Successfully extracted user: {flat_user}")
            result.append(flat_user)
            
        except Exception as e:
            logging.error(f"Error extracting user at index {i}: {str(e)}")
            logging.error(f"User data: {user}")
            # Continue processing other users
            continue

    logging.info(f"Successfully extracted {len(result)} user(s) out of {len(user_list)}")
    return result

def extract_group_fields(group_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Extract specific fields from group search response and return them as a flat JSON object.
    
    Fields extracted:
    * id - the unique group ID
    * name - the group name
    * display_name - the group display name
    * description - the group description
    * type - the group type (LOCAL_GROUP, etc.)
    * system_group - whether it's a system group
    * external - whether it's an external group
    * users - list of users in the group (if include_users=True)
    * privileges - list of group privileges
    * creation_time - when the group was created
    * modification_time - when the group was last modified
    """
    logging.info(f"Starting extract_group_fields with {len(group_list)} group(s)")
    result = []

    for i, group in enumerate(group_list):
        logging.debug(f"Processing group {i+1}/{len(group_list)}")
        
        if group is None:
            logging.warning(f"Skipping None group item at index {i}")
            continue

        logging.debug(f"Extracting group: {group}")
        try:
            flat_group = {
                "id": group.get("id", ""),
                "name": group.get("name", ""),
                "display_name": group.get("display_name", ""),
                "description": group.get("description", ""),
                "type": group.get("type", ""),
                "system_group": group.get("system_group", False),
                "external": group.get("external", False),
                "deleted": group.get("deleted", False),
                "hidden": group.get("hidden", False)
            }

            # Extract users if included
            if "users" in group and isinstance(group["users"], list):
                flat_group["users"] = [
                    {"id": user.get("id", ""), "name": user.get("name", "")} 
                    for user in group["users"] if user is not None
                ]
                logging.debug(f"Extracted {len(flat_group['users'])} users")

            # Extract privileges
            if "privileges" in group and isinstance(group["privileges"], list):
                flat_group["privileges"] = group["privileges"]
                logging.debug(f"Extracted {len(flat_group['privileges'])} privileges")

            # Convert epoch dates to datetime objects
            if "creation_time_in_millis" in group:
                creation_epoch = group["creation_time_in_millis"]
                flat_group["creation_time"] = datetime.fromtimestamp(creation_epoch / 1000) if creation_epoch else None
                logging.debug(f"Converted creation time: {flat_group['creation_time']}")

            if "modification_time_in_millis" in group:
                modification_epoch = group["modification_time_in_millis"]
                flat_group["modification_time"] = datetime.fromtimestamp(modification_epoch / 1000) if modification_epoch else None
                logging.debug(f"Converted modification time: {flat_group['modification_time']}")

            logging.debug(f"Successfully extracted group: {flat_group}")
            result.append(flat_group)
            
        except Exception as e:
            logging.error(f"Error extracting group at index {i}: {str(e)}")
            logging.error(f"Group data: {group}")
            # Continue processing other groups
            continue

    logging.info(f"Successfully extracted {len(result)} group(s) out of {len(group_list)}")
    return result

def extract_metadata_fields(metadata_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Extract specific fields from metadata search response and return them as a flat JSON object.

    Fields extracted:
    * metadata_id - the ID of the metadata (unique and always provided)
    * metadata_obj_id - the metadata object id, may or may not be provided
    * metadata_name - the name of the metadata
    * metadata_type - the type of the metadata
    * metadata_header.description - description of the metadata
    * metadata_header.author_name - name of the author of the metadata
    * metadata_header.created - epoch date when the object was created
    * metadata_header.modified - epoch date when the object was last modified
    * metadata_header.tags[].name - Tags are a list of tags for the object and the name is the name of the tag.
    * stats.views - number of views of this item
    * stats.last_accessed - epoch date for the last time this object was accessed

    For epoch dates, convert to a datetime object using the local timezone.
    """
    result = []

    for metadata in metadata_list:
        if metadata is None:
            logging.warning("Skipping None metadata item")
            continue

        logging.debug(f"Extracting metadata: {metadata}")
        flat_metadata = {
            "metadata_id": metadata.get("metadata_id", ""),
            "metadata_type": metadata.get("metadata_type", ""),
            "metadata_name": metadata.get("metadata_name", ""),
            "metadata_obj_id": metadata.get("metadata_obj_id", "")
        }

        # Extract header fields
        logging.debug(f"trying to extract from header")
        if "metadata_header" in metadata:
            header = metadata["metadata_header"]
            flat_metadata["metadata_description"] = header.get("description", "")
            flat_metadata["author_name"] = header.get("authorName", "")

            # Convert epoch dates to datetime objects
            if "created" in header:
                created_epoch = header["created"]
                flat_metadata["created"] = datetime.fromtimestamp(created_epoch / 1000)

            if "modified" in header:
                modified_epoch = header["modified"]
                flat_metadata["modified"] = datetime.fromtimestamp(modified_epoch / 1000)

            # Extract tags
            if "tags" in header and isinstance(header["tags"], list):
                flat_metadata["tags"] = [tag.get("name", "") if tag is not None else "" for tag in header["tags"]]

        # Extract stats fields
        logging.debug(f"Trying to extract stats")
        if "stats" in metadata:
            stats = metadata["stats"]
            if stats:  # stats can be None
                flat_metadata["views"] = stats.get("views", 0)

                if "last_accessed" in stats:
                    last_access_epoch = stats["last_accessed"]
                    flat_metadata["last_accessed"] = datetime.fromtimestamp(last_access_epoch / 1000) if last_access_epoch else None

        logging.debug(f"Successfully extracted metadata: {flat_metadata}")

        result.append(flat_metadata)

    return result

# Create the server
logging.info("Creating MCP server instance")
app = Server("thoughtspot-admin")
logging.info("MCP server instance created")

@app.list_tools()
async def list_tools() -> List[Tool]:
    """List available tools."""
    logging.info("list_tools() called - returning available tools")
    return [
        Tool(
            name="search-metadata",
            description="Search ThoughtSpot metadata objects by type, author, tags, and other criteria",
            inputSchema={
                "type": "object",
                "properties": {
                    "types": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": [mt.value for mt in MetadataType]
                        },
                        "description": "Metadata types to search for (LIVEBOARD, ANSWER, LOGICAL_TABLE, CONNECTION). Leave empty to search all types."
                    },
                    "authors": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Filter by author names (optional)"
                    },
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Filter by tag names (optional)"
                    },
                    "offset": {
                        "type": "number",
                        "description": "Record offset for pagination (default: 0)",
                        "default": 0
                    },
                    "limit": {
                        "type": "number",
                        "description": "Maximum number of records to return (default: 100, max: 1000)",
                        "default": 100,
                        "maximum": 1000
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="list-users",
            description="List ThoughtSpot users with optional filtering by identifier, name, email, or groups",
            inputSchema={
                "type": "object",
                "properties": {
                    "user_identifier": {
                        "type": "string",
                        "description": "Filter by user identifier (username/email)"
                    },
                    "display_name": {
                        "type": "string",
                        "description": "Filter by display name"
                    },
                    "name_pattern": {
                        "type": "string",
                        "description": "Filter by name pattern (supports wildcards like 'Bill%')"
                    },
                    "email": {
                        "type": "string",
                        "description": "Filter by email address"
                    },
                    "group_identifiers": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Filter by group identifiers (users who belong to these groups)"
                    },
                    "offset": {
                        "type": "number",
                        "description": "Record offset for pagination (default: 0)",
                        "default": 0
                    },
                    "limit": {
                        "type": "number",
                        "description": "Maximum number of records to return (default: 100, max: 1000)",
                        "default": 100,
                        "maximum": 1000
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="list-groups",
            description="List ThoughtSpot groups with optional filtering and user inclusion",
            inputSchema={
                "type": "object",
                "properties": {
                    "display_name": {
                        "type": "string",
                        "description": "Filter by group display name"
                    },
                    "group_identifier": {
                        "type": "string",
                        "description": "Filter by group identifier"
                    },
                    "name_pattern": {
                        "type": "string",
                        "description": "Filter by name pattern (supports wildcards like 'Admin%')"
                    },
                    "include_users": {
                        "type": "boolean",
                        "description": "Include users in each group (default: false)",
                        "default": False
                    },
                    "include_sub_groups": {
                        "type": "boolean",
                        "description": "Include sub-groups (default: false)",
                        "default": False
                    },
                    "offset": {
                        "type": "number",
                        "description": "Record offset for pagination (default: 0)",
                        "default": 0
                    },
                    "limit": {
                        "type": "number",
                        "description": "Maximum number of records to return (default: 100, max: 1000)",
                        "default": 100,
                        "maximum": 1000
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="manage-user-groups",
            description="Add or remove users from groups in ThoughtSpot",
            inputSchema={
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "Username/email of the user to manage"
                    },
                    "operation": {
                        "type": "string",
                        "enum": ["ADD", "REMOVE"],
                        "description": "Operation to perform: ADD to add user to groups, REMOVE to remove user from groups"
                    },
                    "group_identifiers": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of group identifiers to add/remove the user from"
                    }
                },
                "required": ["username", "operation", "group_identifiers"]
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> list[TextContent]:
    """Handle tool calls."""
    logging.info(f"Tool call received: {name}")
    logging.info(f"Tool arguments: {arguments}")
    
    if name == "search-metadata":
        try:
            types = arguments.get("types", [])
            authors = arguments.get("authors", [])
            tags = arguments.get("tags", [])
            offset = arguments.get("offset", 0)
            limit = min(arguments.get("limit", 100), 1000)

            results = await search_metadata(
                types=types,
                authors=authors,
                tags=tags,
                offset=offset,
                limit=limit
            )

            # Extract only the specified fields from the metadata search response
            s_results = json.dumps(results, indent=2, default=str)
            logging.debug(f"Debug: extracted_results content: {s_results}")

            return [TextContent(type="text", text=s_results)]

        except McpError:
            raise
        except Exception as e:
            raise McpError(
                ErrorData(code=INTERNAL_ERROR, message=f"Tool execution failed: {str(e)}"),
            )
    
    elif name == "list-users":
        logging.info(f"Tool call: list-users with arguments: {arguments}")
        try:
            user_identifier = arguments.get("user_identifier")
            display_name = arguments.get("display_name")
            name_pattern = arguments.get("name_pattern")
            email = arguments.get("email")
            group_identifiers = arguments.get("group_identifiers", [])
            offset = arguments.get("offset", 0)
            limit = min(arguments.get("limit", 100), 1000)

            logging.info(f"Parsed arguments: user_identifier={user_identifier}, display_name={display_name}, name_pattern={name_pattern}, email={email}, group_identifiers={group_identifiers}, offset={offset}, limit={limit}")

            results = await list_users(
                user_identifier=user_identifier,
                display_name=display_name,
                name_pattern=name_pattern,
                email=email,
                group_identifiers=group_identifiers,
                offset=offset,
                limit=limit
            )

            s_results = json.dumps(results, indent=2, default=str)
            logging.info(f"Tool call list-users completed successfully. Results length: {len(results)}")
            logging.debug(f"Debug: user search results: {s_results}")

            return [TextContent(type="text", text=s_results)]

        except McpError as mcp_error:
            logging.error(f"McpError in list-users tool call: {mcp_error}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error in list-users tool call: {str(e)}")
            logging.error(f"Error type: {type(e)}")
            raise McpError(
                ErrorData(code=INTERNAL_ERROR, message=f"Tool execution failed: {str(e)}"),
            )
    
    elif name == "list-groups":
        logging.info(f"Tool call: list-groups with arguments: {arguments}")
        try:
            display_name = arguments.get("display_name")
            group_identifier = arguments.get("group_identifier")
            name_pattern = arguments.get("name_pattern")
            include_users = arguments.get("include_users", False)
            include_sub_groups = arguments.get("include_sub_groups", False)
            offset = arguments.get("offset", 0)
            limit = min(arguments.get("limit", 100), 1000)

            logging.info(f"Parsed arguments: display_name={display_name}, group_identifier={group_identifier}, name_pattern={name_pattern}, include_users={include_users}, include_sub_groups={include_sub_groups}, offset={offset}, limit={limit}")

            results = await list_groups(
                display_name=display_name,
                group_identifier=group_identifier,
                name_pattern=name_pattern,
                include_users=include_users,
                include_sub_groups=include_sub_groups,
                offset=offset,
                limit=limit
            )

            s_results = json.dumps(results, indent=2, default=str)
            logging.info(f"Tool call list-groups completed successfully. Results length: {len(results)}")
            logging.debug(f"Debug: group search results: {s_results}")

            return [TextContent(type="text", text=s_results)]

        except McpError as mcp_error:
            logging.error(f"McpError in list-groups tool call: {mcp_error}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error in list-groups tool call: {str(e)}")
            logging.error(f"Error type: {type(e)}")
            raise McpError(
                ErrorData(code=INTERNAL_ERROR, message=f"Tool execution failed: {str(e)}"),
            )
    
    elif name == "manage-user-groups":
        logging.info(f"Tool call: manage-user-groups with arguments: {arguments}")
        try:
            username = arguments.get("username")
            operation = arguments.get("operation")
            group_identifiers = arguments.get("group_identifiers", [])

            logging.info(f"Parsed arguments: username={username}, operation={operation}, group_identifiers={group_identifiers}")

            results = await manage_user_groups(
                username=username,
                operation=operation,
                group_identifiers=group_identifiers
            )

            s_results = json.dumps(results, indent=2, default=str)
            logging.info(f"Tool call manage-user-groups completed successfully")
            logging.debug(f"Debug: user group management results: {s_results}")

            return [TextContent(type="text", text=s_results)]

        except McpError as mcp_error:
            logging.error(f"McpError in manage-user-groups tool call: {mcp_error}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error in manage-user-groups tool call: {str(e)}")
            logging.error(f"Error type: {type(e)}")
            raise McpError(
                ErrorData(code=INTERNAL_ERROR, message=f"Tool execution failed: {str(e)}"),
            )
    
    else:
        logging.error(f"Unknown tool requested: {name}")
        raise McpError(
            ErrorData(code=METHOD_NOT_FOUND, message=f"Unknown tool: {name}"),
        )

@app.list_prompts()
async def list_prompts() -> List[Prompt]:
    """List available prompts."""
    logging.info("list_prompts() called - returning available prompts")
    return [
        Prompt(
            name="search-examples",
            description="Examples of how to search ThoughtSpot metadata"
        ),
        Prompt(
            name="metadata-analysis",
            description="Analyze metadata usage patterns and generate insights"
        ),
        Prompt(
            name="user-management-examples",
            description="Examples of how to manage ThoughtSpot users and groups"
        ),
        Prompt(
            name="user-group-analysis",
            description="Analyze user and group relationships and permissions"
        )
    ]

@app.get_prompt()
async def get_prompt(name: str, _arguments: Dict[str, str]) -> GetPromptResult:
    """Handle prompt requests."""
    if name == "search-examples":
        return GetPromptResult(
            description="Examples of metadata search queries",
            messages=[
                PromptMessage(
                    role="user",
                    content=TextContent(
                        type="text",
                        text="""Here are some example queries you can use with the search-metadata tool:

1. **Find all liveboards:**
   - Use types: ["LIVEBOARD"]

2. **Find objects created by specific users:**
   - Use authors: ["john.doe", "jane.smith"]

3. **Find objects with specific tags:**
   - Use tags: ["Finance", "Marketing"]

4. **Find all data objects (tables, worksheets, views):**
   - Use types: ["LOGICAL_TABLE"]

5. **Find recently created liveboards by a specific author:**
   - Use types: ["LIVEBOARD"] and authors: ["john.doe"]

6. **Get paginated results:**
   - Use offset: 0, limit: 50 for first 50 results
   - Use offset: 50, limit: 50 for next 50 results

7. **Find all objects (no filters):**
   - Leave all parameters empty to get all metadata objects

8. **Find tagged objects by multiple criteria:**
   - Use types: ["LIVEBOARD", "ANSWER"], tags: ["Production"], authors: ["admin"]

The search results will include:
- Metadata ID and name
- Author information
- Creation and modification dates
- Tags associated with the object
- Usage statistics (views, last access)
- Object descriptions"""
                    )
                )
            ]
        )

    elif name == "metadata-analysis":
        return GetPromptResult(
            description="Analyze metadata for insights and patterns",
            messages=[
                PromptMessage(
                    role="user",
                    content=TextContent(
                        type="text",
                        text="""Use the search-metadata tool to analyze your ThoughtSpot environment:

**Usage Analytics:**
- Search for all liveboards to analyze which ones are most/least used
- Look at stats.views and stats.last_accesses to identify unused content
- Find objects not accessed in the last 30/60/90 days

**Content Governance:**
- Search by author to see content distribution across users
- Identify authors who haven't created content recently
- Find objects without descriptions (empty metadata_header.details)

**Tag Analysis:**
- Search for untagged objects (objects without tags)
- Find objects with specific tags to validate tagging strategy
- Analyze tag consistency across different content types

**Content Audit:**
- Search for old content using creation dates
- Find duplicate or similar named objects
- Identify objects that might need updates or archiving

**Performance Insights:**
- Sort by view counts to find most popular content
- Identify content that's created but never viewed
- Find content accessed recently but created long ago

**Example Analysis Queries:**
1. Find all liveboards with low usage: types: ["LIVEBOARD"]
2. Find untagged worksheets: types: ["LOGICAL_TABLE"]
3. Find content by inactive users: authors: ["former.employee"]
4. Find recent content: Use creation timestamps in results
5. Find production content: tags: ["Production"]

Analyze the results to generate insights about:
- Content utilization patterns
- User engagement levels
- Governance compliance
- Content lifecycle management opportunities"""
                    )
                )
            ]
        )

    elif name == "user-management-examples":
        return GetPromptResult(
            description="Examples of how to manage ThoughtSpot users and groups",
            messages=[
                PromptMessage(
                    role="user",
                    content=TextContent(
                        type="text",
                        text="""Here are some example queries you can use with the user and group management tools:

**User Management Examples:**

1. **Find all users:**
   - Use list-users with name_pattern: "*" to get all users

2. **Find specific user by email:**
   - Use list-users with email: "john.doe@company.com"

3. **Find users by name pattern:**
   - Use list-users with name_pattern: "Bill*" to find users whose names start with "Bill"

4. **Find users in specific groups:**
   - Use list-users with group_identifiers: ["Administrator", "Developers"]

5. **Find users by display name:**
   - Use list-users with display_name: "John Doe"

**Group Management Examples:**

1. **List all groups:**
   - Use list-groups with no filters to get all groups

2. **Find specific group:**
   - Use list-groups with group_identifier: "Administrator"

3. **Find groups by name pattern:**
   - Use list-groups with name_pattern: "Admin*" to find groups starting with "Admin"

4. **List groups with their users:**
   - Use list-groups with include_users: true

5. **Find groups by display name:**
   - Use list-groups with display_name: "Administration Group"

**User-Group Management Examples:**

1. **Add user to a group:**
   - Use manage-user-groups with operation: "ADD", username: "john.doe@company.com", group_identifiers: ["Developers"]

2. **Add user to multiple groups:**
   - Use manage-user-groups with operation: "ADD", username: "john.doe@company.com", group_identifiers: ["Developers", "Analysts"]

3. **Remove user from a group:**
   - Use manage-user-groups with operation: "REMOVE", username: "john.doe@company.com", group_identifiers: ["Developers"]

4. **Remove user from multiple groups:**
   - Use manage-user-groups with operation: "REMOVE", username: "john.doe@company.com", group_identifiers: ["Developers", "Analysts"]

**Common Workflows:**

1. **Onboard a new user:**
   - First, find the user: list-users with email: "new.user@company.com"
   - Then add them to appropriate groups: manage-user-groups with operation: "ADD"

2. **Audit user permissions:**
   - List all users: list-users with name_pattern: "*"
   - For each user, check their groups and privileges in the response

3. **Find users without specific groups:**
   - List users in a group: list-users with group_identifiers: ["Developers"]
   - Compare with all users to find those not in the group

4. **Clean up inactive users:**
   - List all users and check their account_status
   - Remove inactive users from groups as needed

**Important Notes:**
- At least one filter must be provided for list-users (user_identifier, display_name, name_pattern, email, or group_identifiers)
- Group identifiers are typically the group names (e.g., "Administrator", "Developers")
- The manage-user-groups tool requires all three parameters: username, operation, and group_identifiers
- Username should be the email address or user identifier
- Operations are case-sensitive: "ADD" or "REMOVE"

The tools return detailed information including:
- User/group IDs, names, and display names
- Account status and types
- Group memberships and inherited groups
- Privileges and permissions
- Creation and modification timestamps"""
                    )
                )
            ]
        )

    elif name == "user-group-analysis":
        return GetPromptResult(
            description="Analyze user and group relationships and permissions",
            messages=[
                PromptMessage(
                    role="user",
                    content=TextContent(
                        type="text",
                        text="""Use the user and group management tools to analyze your ThoughtSpot environment:

**User Analysis:**
- Search for all users to understand your user base
- Identify users by account status (ACTIVE, INACTIVE, etc.)
- Find external vs. internal users
- Analyze user creation patterns and account types

**Group Analysis:**
- List all groups to understand your group structure
- Identify system groups vs. custom groups
- Find groups with no users (empty groups)
- Analyze group privileges and permissions

**Permission Analysis:**
- Check user privileges to understand access levels
- Identify super users and system users
- Find users with specific privileges
- Analyze inherited group permissions

**User-Group Relationship Analysis:**
- Find users in multiple groups
- Identify users not in any groups
- Find groups with many users vs. few users
- Analyze group inheritance patterns

**Security and Compliance:**
- Identify external users and their group memberships
- Find users with administrative privileges
- Check for orphaned users (no group memberships)
- Audit group permissions and access levels

**Example Analysis Queries:**

1. **Find all active users:**
   - Use list-users with name_pattern: "*" and check account_status in results

2. **Find users with admin privileges:**
   - Use list-users with name_pattern: "*" and look for "ADMINISTRATION" in privileges

3. **Find groups with no users:**
   - Use list-groups with include_users: true and look for empty users arrays

4. **Find external users:**
   - Use list-users with name_pattern: "*" and check external: true in results

5. **Find users in specific groups:**
   - Use list-users with group_identifiers: ["Administrator", "Developers"]

6. **Analyze group permissions:**
   - Use list-groups with no filters and examine privileges arrays

**Common Analysis Patterns:**

1. **User Onboarding Analysis:**
   - Find recently created users
   - Check their group memberships
   - Verify appropriate permissions

2. **Access Review:**
   - List all users and their groups
   - Identify users with excessive permissions
   - Find users who might need additional access

3. **Group Optimization:**
   - Find underutilized groups
   - Identify groups that could be consolidated
   - Check for redundant group memberships

4. **Security Audit:**
   - Find users with sensitive privileges
   - Check for external users with admin access
   - Identify inactive users who still have access

**Data Interpretation:**
- account_status: ACTIVE, INACTIVE, PENDING, etc.
- account_type: OIDC_USER, LOCAL_USER, etc.
- privileges: List of permissions like ADMINISTRATION, AUTHORING, etc.
- user_groups: Direct group memberships
- user_inherited_groups: Groups inherited through other groups
- system_group: Whether it's a built-in system group
- external: Whether the user/group is from external identity provider

Use these insights to:
- Optimize group structure and permissions
- Ensure proper access controls
- Plan user onboarding and offboarding processes
- Maintain security and compliance standards"""
                    )
                )
            ]
        )

    else:
        raise McpError(
            ErrorData(code=METHOD_NOT_FOUND, message=f"Unknown prompt: {name}"),
        )

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="ThoughtSpot Admin MCP Server")
    parser.add_argument(
        "--username",
        required=True,
        help="ThoughtSpot username"
    )
    parser.add_argument(
        "--token",
        required=True,
        help="ThoughtSpot API token"
    )
    parser.add_argument(
        "--tsurl",
        required=True,
        help="ThoughtSpot server URL"
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Test the connection by fetching all liveboards and answers"
    )

    return parser.parse_args()

async def get_all_liveboards_and_answers():
    """Get all liveboards and answers and write them as JSON to standard output.

    This function fetches all liveboards and answers from ThoughtSpot and outputs them
    in a JSON format that can be easily parsed by LLMs and other automated tools.
    """
    try:
        # Define metadata types to fetch
        metadata_types = [
            (MetadataType.LIVEBOARD, "Liveboard"),
            (MetadataType.ANSWER, "Answer")
        ]

        # Create a dictionary to hold all results
        results = {}

        # Loop through each metadata type
        for metadata_type, type_label in metadata_types:
            # Fetch items for this type
            items = await search_metadata(types=[metadata_type.value])

            # Add to results dictionary
            results[type_label.lower() + "s"] = {
                "count": len(items),
                "items": items
            }

        # Output the results as JSON
        # print(json.dumps(results, indent=2, default=str))
        print(results)

    except Exception as e:
        error_response = {
            "error": True,
            "message": str(e)
        }
        print(json.dumps(error_response), file=sys.stderr)

async def main():
    """Main function to start the server."""
    logging.info("Starting ThoughtSpot Admin MCP Server")
    args = parse_arguments()

    try:
        logging.info(f"Parsed arguments: tsurl={args.tsurl}, username={args.username}, test={args.test}")
        
        # Validate arguments
        if not args.tsurl.startswith(('http://', 'https://')):
            logging.error(f"Invalid ThoughtSpot URL format: {args.tsurl}")
            print(f"Error: Invalid ThoughtSpot URL format: {args.tsurl}", file=sys.stderr)
            print("URL should start with http:// or https://", file=sys.stderr)
            sys.exit(1)

        # Initialize ThoughtSpot client
        try:
            logging.info("Initializing ThoughtSpot client")
            init_thoughtspot_client(args.tsurl, args.username, args.token)
            logging.info("ThoughtSpot client initialized successfully")
        except Exception as e:
            logging.error(f"Error initializing ThoughtSpot client: {e}")
            print(f"Error initializing ThoughtSpot client: {e}", file=sys.stderr)
            print("Please check your credentials and server URL.", file=sys.stderr)
            sys.exit(1)

        # Test connection if requested
        if args.test:
            logging.info("Running test mode")
            await get_all_liveboards_and_answers()
            return

        # Start the server
        logging.info("Starting MCP server with stdio transport")
        async with stdio_server() as (read_stream, write_stream):
            logging.info("MCP server started, waiting for tool calls")
            await app.run(read_stream, write_stream, app.create_initialization_options())

    except Exception as e:
        logging.error(f"Server error: {e}")
        print(f"Server error: {e}", file=sys.stderr)
        sys.exit(1)

def run_main():
    """Entry point for the application."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutting down gracefully...")
        sys.exit(0)
    except argparse.ArgumentError as e:
        print(f"Argument error: {e}", file=sys.stderr)
        sys.exit(1)
    except SystemExit as e:
        # This catches the sys.exit() called by argparse when --help is used
        # or when invalid arguments are provided
        if e.code != 0:
            print("Error: Missing or invalid arguments. Use --help for usage information.", file=sys.stderr)
        sys.exit(e.code)

if __name__ == "__main__":
    run_main()
