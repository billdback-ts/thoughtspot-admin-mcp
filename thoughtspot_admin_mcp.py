#!/usr/bin/env python3

import argparse
import asyncio
import json
import logging
import os
import sys
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

# Test logging.  Turn off when working.
log_path = "mcp_debug.log"
if not os.access(".", os.W_OK):
    log_path = "/tmp/mcp_debug.log"

logging.basicConfig(
    filename=log_path,
    filemode="w",
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s:%(message)s"
)

logging.info("Logging is working.")


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
        # Validate input parameters
        if not server_url:
            raise McpError(
                ErrorData(code=INVALID_REQUEST, message="Server URL is required"),
            )
        if not username:
            raise McpError(
                ErrorData(code=INVALID_REQUEST, message="Username is required"),
            )
        if not token:
            raise McpError(
                ErrorData(code=INVALID_REQUEST, message="API token is required"),
            )

        try:
            self.ts_client = TSRestApiV2(server_url=server_url)
            self.ts_client.bearer_token = token
            self.ts_client.username = username
            return self.ts_client
        except Exception as e:
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
app = Server("thoughtspot-admin")

@app.list_tools()
async def list_tools() -> List[Tool]:
    """List available tools."""
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
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> list[TextContent]:
    """Handle tool calls."""
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
    else:
        raise McpError(
            ErrorData(code=METHOD_NOT_FOUND, message=f"Unknown tool: {name}"),
        )

@app.list_prompts()
async def list_prompts() -> List[Prompt]:
    """List available prompts."""
    return [
        Prompt(
            name="search-examples",
            description="Examples of how to search ThoughtSpot metadata"
        ),
        Prompt(
            name="metadata-analysis",
            description="Analyze metadata usage patterns and generate insights"
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
    args = parse_arguments()

    try:
        # Validate arguments
        if not args.tsurl.startswith(('http://', 'https://')):
            print(f"Error: Invalid ThoughtSpot URL format: {args.tsurl}", file=sys.stderr)
            print("URL should start with http:// or https://", file=sys.stderr)
            sys.exit(1)

        # Initialize ThoughtSpot client
        try:
            init_thoughtspot_client(args.tsurl, args.username, args.token)
        except Exception as e:
            print(f"Error initializing ThoughtSpot client: {e}", file=sys.stderr)
            print("Please check your credentials and server URL.", file=sys.stderr)
            sys.exit(1)

        # Test connection if requested
        if args.test:
            await get_all_liveboards_and_answers()
            return

        # Start the server
        async with stdio_server() as (read_stream, write_stream):
            await app.run(read_stream, write_stream, app.create_initialization_options())

    except Exception as e:
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
